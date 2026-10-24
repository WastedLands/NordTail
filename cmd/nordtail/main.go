// Command nordtail runs the NordTail controller and dashboard.
//
//	nordtail                  serve (configuration from the environment)
//	nordtail netns-exec ...   internal: launch a program inside a region netns
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/WastedLands/NordTail/internal/config"
	"github.com/WastedLands/NordTail/internal/controller"
	"github.com/WastedLands/NordTail/internal/netns"
	"github.com/WastedLands/NordTail/internal/store"
	"github.com/WastedLands/NordTail/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "netns-exec" {
		if err := netnsExec(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "netns-exec:", err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := serve(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	// Configuration (master key first) is validated before any state is
	// touched: no master key, no start.
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "nordtail.db"), cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	outer, err := netns.DetectOuter()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctl := controller.New(cfg, st, outer, log)
	if err := ctl.Start(ctx); err != nil {
		return fmt.Errorf("start regions: %w", err)
	}
	defer ctl.Shutdown()

	srv := web.New(cfg, ctl, log)
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	defer srv.Close()

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}

// netnsExec enters a named netns, bind-mounts a resolv.conf over
// /etc/resolv.conf in a private mount namespace, and execs the program.
// It runs as a fresh child process, so namespace changes never touch the
// controller's own threads.
func netnsExec(args []string) error {
	fs := flag.NewFlagSet("netns-exec", flag.ContinueOnError)
	nsPath := fs.String("netns", "", "path of the network namespace")
	resolv := fs.String("resolv", "", "resolv.conf to use inside")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if *nsPath == "" || len(argv) == 0 {
		return errors.New("usage: netns-exec --netns PATH [--resolv FILE] -- PROGRAM [ARGS...]")
	}
	runtime.LockOSThread()
	f, err := os.Open(*nsPath)
	if err != nil {
		return err
	}
	if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("setns: %w", err)
	}
	f.Close()
	if *resolv != "" {
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return fmt.Errorf("unshare mount ns: %w", err)
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return fmt.Errorf("make mounts private: %w", err)
		}
		if err := unix.Mount(*resolv, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind resolv.conf: %w", err)
		}
	}
	return unix.Exec(argv[0], argv, os.Environ())
}
