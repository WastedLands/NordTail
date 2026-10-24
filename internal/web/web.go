// Package web serves the dashboard and its JSON API on the tailnet only
// (decision 0001, tsnet mode). Every request is authorized by the caller's
// Tailscale identity; there is no other way in.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/WastedLands/NordTail/internal/config"
	"github.com/WastedLands/NordTail/internal/controller"
	"github.com/WastedLands/NordTail/internal/secret"
)

type Server struct {
	logFile *os.File
	cfg     *config.Config
	ctl     *controller.Controller
	log     *slog.Logger
	ts      *tsnet.Server
	lc      *local.Client
	http    *http.Server
}

func New(cfg *config.Config, ctl *controller.Controller, log *slog.Logger) *Server {
	return &Server{cfg: cfg, ctl: ctl, log: log}
}

// Start joins the tailnet as the "nordtail" node and serves HTTP on its
// tailnet address only.
func (s *Server) Start(ctx context.Context) error {
	dir := filepath.Join(s.cfg.DataDir, "tsnet")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	logf, err := openLog(filepath.Join(dir, "tsnet.log"))
	if err != nil {
		return err
	}
	s.logFile = logf
	s.ts = &tsnet.Server{
		Hostname:   "nordtail",
		Dir:        dir,
		AuthKey:    s.cfg.TSAuthKey.Reveal(),
		ControlURL: s.cfg.LoginServer,
		Logf:       log.New(logf, "", log.LstdFlags).Printf, // chatty: to a file, not stderr
	}
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := s.ts.Up(upCtx); err != nil {
		return err
	}
	lc, err := s.ts.LocalClient()
	if err != nil {
		return err
	}
	s.lc = lc
	ln, err := s.ts.Listen("tcp", ":80")
	if err != nil {
		return err
	}
	s.http = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("dashboard server", "err", err)
		}
	}()
	s.log.Info("dashboard listening on the tailnet", "url", "http://nordtail/")
	return nil
}

func (s *Server) Close() {
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.http.Shutdown(ctx)
		cancel()
	}
	if s.ts != nil {
		_ = s.ts.Close()
	}
	if s.logFile != nil {
		_ = s.logFile.Close()
	}
}

// openLog appends to path, starting over once it passes 8 MiB.
func openLog(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > 8<<20 {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	return os.OpenFile(path, flags, 0o600)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/whoami", s.whoami)
	mux.HandleFunc("GET /api/v1/regions", s.listRegions)
	mux.HandleFunc("POST /api/v1/regions", s.createRegion)
	mux.HandleFunc("GET /api/v1/regions/{id}", s.getRegion)
	mux.HandleFunc("DELETE /api/v1/regions/{id}", s.deleteRegion)
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("POST /regions", s.formCreate)
	mux.HandleFunc("POST /regions/{id}/delete", s.formDelete)
	return s.authorize(mux)
}

type ctxKey struct{}

// authorize admits only untagged tailnet identities on the admin allowlist.
// Cross-site writes are rejected (CSRF).
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil || who.Node == nil || who.UserProfile == nil || who.Node.IsTagged() ||
			!slices.Contains(s.cfg.Admins, who.UserProfile.LoginName) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, who.UserProfile.LoginName)))
	})
}

func login(r *http.Request) string { s, _ := r.Context().Value(ctxKey{}).(string); return s }

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"login": login(r), "admin": true})
}

func (s *Server) listRegions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ctl.List(r.Context()))
}

func (s *Server) getRegion(w http.ResponseWriter, r *http.Request) {
	st, err := s.ctl.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type createReq struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	WGConf   string `json:"wgconf"`
}

func (s *Server) createRegion(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "want application/json", http.StatusUnsupportedMediaType)
		return
	}
	var req createReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	cfgText := secret.New(req.WGConf)
	req.WGConf = ""
	if _, err := s.ctl.Create(r.Context(), req.ID, req.Provider, cfgText); err != nil {
		apiError(w, err)
		return
	}
	s.log.Info("region created", "region", req.ID, "by", login(r))
	st, err := s.ctl.Get(r.Context(), req.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, st)
}

func (s *Server) deleteRegion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.ctl.Delete(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	s.log.Info("region deleted", "region", id, "by", login(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) formCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	if _, err := s.ctl.Create(r.Context(), id, "wgconf", secret.New(r.PostFormValue("wgconf"))); err != nil {
		apiError(w, err)
		return
	}
	s.log.Info("region created", "region", id, "by", login(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) formDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.ctl.Delete(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	s.log.Info("region deleted", "region", id, "by", login(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
	_ = pageTmpl.Execute(w, map[string]any{"Login": login(r), "Regions": s.ctl.List(r.Context())})
}

func apiError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controller.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, controller.ErrExists):
		http.Error(w, "region already exists", http.StatusConflict)
	case errors.Is(err, controller.ErrNotFound):
		http.Error(w, "region not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NordTail</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:56rem;margin:2rem auto;padding:0 1rem;color:#1d1d1f}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd}
.ok{color:#18794e}.bad{color:#c62828}textarea{width:100%;font-family:monospace}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}th,td{border-color:#333}}
</style></head><body>
<h1>NordTail</h1>
<p>Signed in as {{.Login}}.</p>
<h2>Regions</h2>
{{if .Regions}}<table><tr><th>Exit node</th><th>Tunnel</th><th>Node</th><th>Approved</th><th></th></tr>
{{range .Regions}}<tr>
<td>{{.Hostname}}</td>
<td>{{if .Tunnel.Up}}<span class="ok">up</span>{{else}}<span class="bad">down</span>{{end}}</td>
<td>{{.Phase}}{{if .Error}}: {{.Error}}{{end}}</td>
<td>{{if .Node.ExitApproved}}yes{{else}}no{{end}}</td>
<td><form method="post" action="/regions/{{.ID}}/delete"><button>Delete</button></form></td>
</tr>{{end}}</table>{{else}}<p>No regions yet.</p>{{end}}
<h2>Add a region</h2>
<form method="post" action="/regions">
<p><label>Region ID (lowercase letters and digits, e.g. us)<br><input name="id" required pattern="[a-z0-9]{1,12}"></label></p>
<p><label>WireGuard configuration from your VPN provider<br><textarea name="wgconf" rows="12" required></textarea></label></p>
<p><button>Add region</button></p>
</form>
</body></html>`))
