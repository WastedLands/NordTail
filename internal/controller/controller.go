// Package controller turns stored regions into running exit nodes and keeps
// them honest: it builds each region (netns, WireGuard, routing, firewall,
// tailscaled), probes the tunnel, and takes a region's node offline while its
// tunnel is down (decision 0004).
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	vnetns "github.com/vishvananda/netns"

	"github.com/WastedLands/NordTail/internal/config"
	"github.com/WastedLands/NordTail/internal/netns"
	"github.com/WastedLands/NordTail/internal/provider/wgconf"
	"github.com/WastedLands/NordTail/internal/secret"
	"github.com/WastedLands/NordTail/internal/store"
	"github.com/WastedLands/NordTail/internal/tsnode"
	"github.com/WastedLands/NordTail/internal/wg"
)

const (
	probeEvery     = 5 * time.Second
	probeTimeout   = 3 * time.Second
	probeFailLimit = 3                // consecutive misses before the tunnel counts as down
	recoverAfter   = 10 * time.Second // healthy this long before a withdrawn node returns
)

var idRE = regexp.MustCompile(`^[a-z0-9]{1,12}$`)

var (
	ErrInvalid  = errors.New("invalid region")
	ErrExists   = store.ErrExists
	ErrNotFound = store.ErrNotFound
)

type Controller struct {
	cfg   *config.Config
	store *store.Store
	outer *netns.Outer
	log   *slog.Logger

	buildMu sync.Mutex // region builds share the outer netns (veth naming, NAT table)
	mu      sync.Mutex
	regions map[string]*region
}

type region struct {
	rec    *store.Region
	layout netns.Layout
	tunnel *wgconf.Tunnel
	node   *tsnode.Node
	log    *slog.Logger
	cancel context.CancelFunc

	mu             sync.Mutex
	ns             vnetns.NsHandle
	phase          string // starting, running, withdrawn, error
	lastErr        string
	tunnelUp       bool
	misses         int
	unhealthySince time.Time
	healthySince   time.Time
	withdrawn      bool
}

func New(cfg *config.Config, st *store.Store, outer *netns.Outer, log *slog.Logger) *Controller {
	return &Controller{cfg: cfg, store: st, outer: outer, log: log, regions: map[string]*region{}}
}

// Start brings up every stored region.
func (c *Controller) Start(ctx context.Context) error {
	recs, err := c.store.List(ctx)
	if err != nil {
		return err
	}
	if err := c.applyOuterNAT(recs); err != nil {
		return err
	}
	for _, rec := range recs {
		if err := c.launch(rec); err != nil {
			c.log.Error("region start", "region", rec.ID, "err", err)
		}
	}
	return nil
}

// Create validates and stores a region, then brings it up in the background.
func (c *Controller) Create(ctx context.Context, id, provider string, cfgText secret.String) (*store.Region, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("%w: id must match %s", ErrInvalid, idRE)
	}
	if provider != "wgconf" {
		return nil, fmt.Errorf("%w: unsupported provider %q", ErrInvalid, provider)
	}
	t, err := wgconf.Parse(cfgText.Reveal())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(t.DNS) == 0 {
		return nil, fmt.Errorf("%w: the WireGuard config needs a DNS resolver ([Interface] DNS)", ErrInvalid)
	}
	rec, err := c.store.Create(ctx, id, provider, cfgText, c.cfg.PortMin, c.cfg.PortMax)
	if err != nil {
		return nil, err
	}
	recs, err := c.store.List(ctx)
	if err == nil {
		err = c.applyOuterNAT(recs)
	}
	if err == nil {
		err = c.launch(rec)
	}
	return rec, err
}

// Delete removes the region's node from the tailnet, tears the region down,
// and forgets it.
func (c *Controller) Delete(ctx context.Context, id string) error {
	c.mu.Lock()
	r := c.regions[id]
	delete(c.regions, id)
	c.mu.Unlock()
	if r != nil {
		r.cancel()
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := r.node.Logout(lctx); err != nil {
			r.log.Warn("logout", "err", err)
		}
		cancel()
		r.node.Stop()
		_ = netns.Delete(r.layout)
		_ = os.RemoveAll(r.node.Dir)
	}
	if err := c.store.Delete(ctx, id); err != nil {
		return err
	}
	recs, err := c.store.List(ctx)
	if err != nil {
		return err
	}
	return c.applyOuterNAT(recs)
}

// Shutdown stops every region's daemon and removes its netns. State stays on
// disk, so the next start restores the same nodes.
func (c *Controller) Shutdown() {
	c.mu.Lock()
	rs := make([]*region, 0, len(c.regions))
	for _, r := range c.regions {
		rs = append(rs, r)
	}
	c.mu.Unlock()
	for _, r := range rs {
		r.cancel()
		r.node.Stop()
		_ = netns.Delete(r.layout)
	}
}

func (c *Controller) layout(rec *store.Region, t *wgconf.Tunnel) netns.Layout {
	return netns.Layout{ID: rec.ID, Index: rec.Port - c.cfg.PortMin, Port: rec.Port, Resolvers: t.DNS}
}

func (c *Controller) applyOuterNAT(recs []*store.Region) error {
	var ls []netns.Layout
	for _, rec := range recs {
		ls = append(ls, netns.Layout{ID: rec.ID, Index: rec.Port - c.cfg.PortMin, Port: rec.Port})
	}
	return netns.OuterNAT(c.outer, ls)
}

func (c *Controller) launch(rec *store.Region) error {
	t, err := wgconf.Parse(rec.Config.Reveal())
	if err != nil {
		return err
	}
	dir := filepath.Join(c.cfg.DataDir, "regions", rec.ID)
	l := c.layout(rec, t)
	ctx, cancel := context.WithCancel(context.Background())
	r := &region{
		rec: rec, layout: l, tunnel: t, cancel: cancel, phase: "starting",
		log: c.log.With("region", rec.ID),
		node: &tsnode.Node{
			Dir: dir, NSPath: l.NSPath(), ResolvConf: filepath.Join(dir, "resolv.conf"),
			Port: rec.Port, Hostname: "exit-" + rec.ID,
			LoginServer: c.cfg.LoginServer, AuthKey: c.cfg.TSAuthKey,
			Log: c.log.With("region", rec.ID, "component", "tailscaled"),
		},
	}
	c.mu.Lock()
	c.regions[rec.ID] = r
	c.mu.Unlock()
	go c.run(ctx, r)
	return nil
}

func (c *Controller) run(ctx context.Context, r *region) {
	if err := c.build(ctx, r); err != nil {
		r.setErr(err)
		r.log.Error("build failed", "err", err)
		return
	}
	r.mu.Lock()
	r.phase = "running"
	r.lastErr = ""
	r.mu.Unlock()
	r.log.Info("region up")
	c.monitor(ctx, r)
}

func (c *Controller) build(ctx context.Context, r *region) error {
	c.buildMu.Lock()
	ns, err := netns.Create(r.layout)
	if err == nil {
		err = wg.Create(ctx, c.outer, ns, r.layout.WGName(), r.tunnel)
	}
	if err == nil {
		err = netns.Route(ns, r.layout)
	}
	if err == nil {
		err = netns.Firewall(ns, r.layout)
	}
	c.buildMu.Unlock()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.ns = ns
	r.mu.Unlock()

	if err := os.MkdirAll(r.node.Dir, 0o700); err != nil {
		return err
	}
	var rc strings.Builder
	for _, a := range r.tunnel.DNS {
		fmt.Fprintf(&rc, "nameserver %s\n", a)
	}
	if err := os.WriteFile(r.node.ResolvConf, []byte(rc.String()), 0o644); err != nil {
		return err
	}
	if err := r.node.Start(); err != nil {
		return err
	}
	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return r.node.Up(upCtx)
}

// monitor probes the tunnel and withdraws/restores the node (decision 0004).
func (c *Controller) monitor(ctx context.Context, r *region) {
	tick := time.NewTicker(probeEvery)
	defer tick.Stop()
	for {
		healthy := c.probe(r)
		now := time.Now()
		r.mu.Lock()
		r.tunnelUp = healthy
		if healthy {
			r.unhealthySince = time.Time{}
			if r.healthySince.IsZero() {
				r.healthySince = now
			}
		} else {
			r.healthySince = time.Time{}
			if r.unhealthySince.IsZero() {
				r.unhealthySince = now
			}
		}
		withdraw := !healthy && !r.withdrawn && now.Sub(r.unhealthySince) >= c.cfg.DownGrace
		restore := healthy && r.withdrawn && now.Sub(r.healthySince) >= recoverAfter
		r.mu.Unlock()

		if withdraw || restore {
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := r.node.SetOnline(sctx, restore)
			cancel()
			if err != nil {
				r.log.Error("change node availability", "online", restore, "err", err)
			} else {
				r.mu.Lock()
				r.withdrawn = withdraw
				if withdraw {
					r.phase = "withdrawn"
				} else {
					r.phase = "running"
				}
				r.mu.Unlock()
				r.log.Info("node availability changed", "online", restore)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// probe reports tunnel health: link up and the resolver answers through the
// tunnel, tolerating up to probeFailLimit-1 consecutive misses.
func (c *Controller) probe(r *region) bool {
	r.mu.Lock()
	ns := r.ns
	r.mu.Unlock()
	h, err := wg.Inspect(ns, r.layout.WGName())
	ok := err == nil && h.Up
	if ok {
		ok = wg.Probe(ns, r.tunnel.DNS[0], probeTimeout) == nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !h.Up || err != nil {
		r.misses = probeFailLimit // a missing or down link is unhealthy at once
		return false
	}
	if ok {
		r.misses = 0
		return true
	}
	r.misses++
	return r.misses < probeFailLimit && r.tunnelUp
}

func (r *region) setErr(err error) {
	r.mu.Lock()
	r.phase = "error"
	r.lastErr = err.Error()
	r.mu.Unlock()
}

// RegionStatus is the API's Region object (DESIGN.md "Dashboard HTTP API").
type RegionStatus struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Provider      string     `json:"provider"`
	PrivateKeySet bool       `json:"private_key_set"`
	Phase         string     `json:"phase"`
	Error         string     `json:"error,omitempty"`
	Tunnel        TunnelInfo `json:"tunnel"`
	Node          NodeInfo   `json:"node"`
}

type TunnelInfo struct {
	Up            bool       `json:"up"`
	Endpoint      string     `json:"endpoint,omitempty"`
	LastHandshake *time.Time `json:"last_handshake"`
}

type NodeInfo struct {
	State        string   `json:"state"`
	Online       bool     `json:"online"`
	ExitApproved bool     `json:"exit_approved"`
	TailscaleIPs []string `json:"tailscale_ips"`
}

func (c *Controller) Get(ctx context.Context, id string) (*RegionStatus, error) {
	c.mu.Lock()
	r := c.regions[id]
	c.mu.Unlock()
	if r == nil {
		return nil, ErrNotFound
	}
	return r.status(ctx), nil
}

func (c *Controller) List(ctx context.Context) []*RegionStatus {
	c.mu.Lock()
	rs := make([]*region, 0, len(c.regions))
	for _, r := range c.regions {
		rs = append(rs, r)
	}
	c.mu.Unlock()
	sort.Slice(rs, func(i, j int) bool { return rs[i].rec.Port < rs[j].rec.Port })
	out := make([]*RegionStatus, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.status(ctx))
	}
	return out
}

func (r *region) status(ctx context.Context) *RegionStatus {
	r.mu.Lock()
	s := &RegionStatus{
		ID: r.rec.ID, Hostname: "exit-" + r.rec.ID, Provider: r.rec.Provider,
		PrivateKeySet: !r.tunnel.PrivateKey.IsZero(),
		Phase:         r.phase, Error: r.lastErr,
		Tunnel: TunnelInfo{Up: r.tunnelUp},
	}
	ns := r.ns
	r.mu.Unlock()
	if ns.IsOpen() {
		if h, err := wg.Inspect(ns, r.layout.WGName()); err == nil {
			s.Tunnel.Endpoint = h.Endpoint
			if !h.LastHandshake.IsZero() {
				t := h.LastHandshake.UTC()
				s.Tunnel.LastHandshake = &t
			}
		}
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if ns, err := r.node.Status(sctx); err == nil {
		s.Node = NodeInfo{State: ns.State, Online: ns.Online, ExitApproved: ns.ExitApproved, TailscaleIPs: ns.TailscaleIPs}
	}
	if s.Node.TailscaleIPs == nil {
		s.Node.TailscaleIPs = []string{}
	}
	return s
}
