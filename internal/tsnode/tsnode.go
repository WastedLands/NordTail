// Package tsnode supervises one region's tailscaled: a kernel-mode daemon
// running inside the region netns with persistent state, driven through its
// LocalAPI socket.
package tsnode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"github.com/WastedLands/NordTail/internal/secret"
)

// TailscaledPath is the bundled daemon (see Dockerfile).
var TailscaledPath = "/usr/local/bin/tailscaled"

type Node struct {
	Dir         string // persistent state directory for this region
	NSPath      string // /var/run/netns/rg-<id>
	ResolvConf  string // resolv.conf bind-mounted for the daemon
	Port        int
	Hostname    string
	LoginServer string
	AuthKey     secret.String
	Log         *slog.Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{}
	stopped bool
	lc      *local.Client
}

func (n *Node) socket() string { return filepath.Join(n.Dir, "tailscaled.sock") }

// Start launches tailscaled (and relaunches it if it dies) until Stop.
func (n *Node) Start() error {
	if err := os.MkdirAll(n.Dir, 0o700); err != nil {
		return err
	}
	n.lc = &local.Client{Socket: n.socket(), UseSocketOnly: true}
	n.mu.Lock()
	n.stopped = false
	n.mu.Unlock()
	if err := n.spawn(); err != nil {
		return err
	}
	go n.supervise()
	return nil
}

func (n *Node) spawn() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logPath := filepath.Join(n.Dir, "tailscaled.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 8<<20 {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC // keep the log bounded
	}
	logf, err := os.OpenFile(logPath, flags, 0o600)
	if err != nil {
		return err
	}
	// Re-exec ourselves as a tiny namespace launcher (cmd/nordtail netns-exec):
	// it enters the region netns, gives the daemon the region's resolv.conf in
	// a private mount namespace, then execs tailscaled.
	cmd := exec.Command(self, "netns-exec", "--netns", n.NSPath, "--resolv", n.ResolvConf, "--",
		TailscaledPath,
		"--state="+filepath.Join(n.Dir, "tailscaled.state"),
		"--statedir="+n.Dir,
		"--socket="+n.socket(),
		"--port="+strconv.Itoa(n.Port),
		"--tun=tailscale0",
	)
	cmd.Env = append(os.Environ(), "TS_DEBUG_FIREWALL_MODE=nftables")
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return fmt.Errorf("start tailscaled: %w", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		logf.Close()
		close(done)
	}()
	n.mu.Lock()
	n.cmd, n.done = cmd, done
	n.mu.Unlock()
	return nil
}

func (n *Node) supervise() {
	backoff := time.Second
	for {
		n.mu.Lock()
		done := n.done
		n.mu.Unlock()
		<-done
		n.mu.Lock()
		stopped := n.stopped
		n.mu.Unlock()
		if stopped {
			return
		}
		n.Log.Warn("tailscaled exited; restarting", "in", backoff)
		time.Sleep(backoff)
		backoff = min(backoff*2, 30*time.Second)
		if err := n.spawn(); err != nil {
			n.Log.Error("restart tailscaled", "err", err)
		}
	}
}

// Stop terminates tailscaled; its state stays on disk.
func (n *Node) Stop() {
	n.mu.Lock()
	n.stopped = true
	cmd, done := n.cmd, n.done
	n.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

// Up waits for the daemon and makes sure it is logged in, advertising the
// exit routes under its hostname. A node with persisted state just starts;
// only a new node uses the auth key.
func (n *Node) Up(ctx context.Context) error {
	var st *ipnstate.Status
	if err := poll(ctx, 30*time.Second, func() error {
		var err error
		st, err = n.lc.Status(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("tailscaled not answering: %w", err)
	}
	prefs := ipn.NewPrefs()
	prefs.ControlURL = n.LoginServer
	if prefs.ControlURL == "" {
		prefs.ControlURL = ipn.DefaultControlURL
	}
	prefs.Hostname = n.Hostname
	prefs.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	prefs.WantRunning = true
	prefs.CorpDNS = false // the region resolves via its own resolver, not tailnet DNS
	prefs.RouteAll = false

	if !st.HaveNodeKey {
		// New node: register with the auth key.
		if err := n.lc.Start(ctx, ipn.Options{AuthKey: n.AuthKey.Reveal(), UpdatePrefs: prefs}); err != nil {
			return fmt.Errorf("start: %w", err)
		}
		if err := n.lc.StartLoginInteractive(ctx); err != nil {
			return fmt.Errorf("login: %w", err)
		}
	} else if err := n.syncPrefs(ctx, prefs); err != nil {
		// Saved state: tailscaled logs itself back in. Calling Start here
		// would restart its control client mid-login (seen in E2E: the
		// second login then got stuck on a forced port-443 dial).
		return err
	}
	return poll(ctx, 60*time.Second, func() error {
		s, err := n.lc.Status(ctx)
		if err != nil {
			return err
		}
		if s.BackendState != ipn.Running.String() {
			return fmt.Errorf("backend state %s", s.BackendState)
		}
		return nil
	})
}

// syncPrefs changes only the prefs that differ from want. WantRunning is
// always restored: a node withdrawn before a restart comes back online here.
func (n *Node) syncPrefs(ctx context.Context, want *ipn.Prefs) error {
	cur, err := n.lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}
	mp := &ipn.MaskedPrefs{Prefs: *want}
	mp.WantRunningSet = !cur.WantRunning
	mp.HostnameSet = cur.Hostname != want.Hostname
	mp.AdvertiseRoutesSet = !slices.Equal(cur.AdvertiseRoutes, want.AdvertiseRoutes)
	mp.CorpDNSSet = cur.CorpDNS != want.CorpDNS
	mp.RouteAllSet = cur.RouteAll != want.RouteAll
	if !mp.WantRunningSet && !mp.HostnameSet && !mp.AdvertiseRoutesSet && !mp.CorpDNSSet && !mp.RouteAllSet {
		return nil
	}
	if _, err := n.lc.EditPrefs(ctx, mp); err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}
	return nil
}

// SetOnline takes the node offline (keeping state, identity, and route
// approval) or brings it back (decision 0004).
func (n *Node) SetOnline(ctx context.Context, on bool) error {
	_, err := n.lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: on}, WantRunningSet: true})
	return err
}

// Logout removes the node from the tailnet (used when a region is deleted).
func (n *Node) Logout(ctx context.Context) error { return n.lc.Logout(ctx) }

// Status summarizes what the dashboard shows.
type Status struct {
	State        string
	Online       bool
	ExitApproved bool
	TailscaleIPs []string
}

func (n *Node) Status(ctx context.Context) (Status, error) {
	if n.lc == nil {
		return Status{}, errors.New("not started")
	}
	st, err := n.lc.Status(ctx)
	if err != nil {
		return Status{}, err
	}
	s := Status{State: st.BackendState}
	if st.Self != nil {
		s.Online = st.Self.Online
		// Approval shows up as the exit routes in the node's own AllowedIPs
		// (spike finding 8); PrimaryRoutes stays empty for exit nodes.
		if st.Self.AllowedIPs != nil {
			for _, p := range st.Self.AllowedIPs.All() {
				if p.Bits() == 0 {
					s.ExitApproved = true
				}
			}
		}
		for _, ip := range st.Self.TailscaleIPs {
			s.TailscaleIPs = append(s.TailscaleIPs, ip.String())
		}
	}
	return s, nil
}

func poll(ctx context.Context, d time.Duration, f func() error) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var err error
	for {
		if err = f(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last: %v)", ctx.Err(), err)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
