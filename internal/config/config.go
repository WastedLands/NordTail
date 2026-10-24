// Package config reads NordTail's environment configuration (DESIGN.md
// "Configuration (environment)").
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/WastedLands/NordTail/internal/secret"
)

type Config struct {
	MasterKey   *secret.MasterKey
	TSAuthKey   secret.String
	LoginServer string
	Admins      []string
	DataDir     string
	PortMin     int
	PortMax     int
	DownGrace   time.Duration
}

// Load reads and validates the environment. The master key is checked first so
// a missing key fails before anything else is read or touched.
func Load(getenv func(string) string) (*Config, error) {
	mk, err := masterKey(getenv)
	if err != nil {
		return nil, err
	}
	c := &Config{
		MasterKey:   mk,
		TSAuthKey:   secret.New(strings.TrimSpace(getenv("NORDTAIL_TS_AUTHKEY"))),
		LoginServer: strings.TrimSpace(getenv("NORDTAIL_LOGIN_SERVER")),
		DataDir:     orDefault(getenv("NORDTAIL_DATA_DIR"), "/data"),
		DownGrace:   60 * time.Second,
		PortMin:     41700,
		PortMax:     41709,
	}
	if c.TSAuthKey.Placeholder() {
		return nil, errors.New("NORDTAIL_TS_AUTHKEY is missing or a placeholder")
	}
	for _, a := range strings.Split(getenv("NORDTAIL_ADMINS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			c.Admins = append(c.Admins, a)
		}
	}
	if len(c.Admins) == 0 {
		return nil, errors.New("NORDTAIL_ADMINS must name at least one Tailscale login")
	}
	if v := strings.TrimSpace(getenv("NORDTAIL_DOWN_GRACE")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("NORDTAIL_DOWN_GRACE: invalid duration %q", v)
		}
		c.DownGrace = d
	}
	if v := strings.TrimSpace(getenv("NORDTAIL_REGION_PORTS")); v != "" {
		lo, hi, ok := strings.Cut(v, "-")
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if !ok || err1 != nil || err2 != nil || a < 1024 || b > 65535 || a > b || b-a > 250 {
			return nil, fmt.Errorf("NORDTAIL_REGION_PORTS: want a range like 41700-41709, got %q", v)
		}
		c.PortMin, c.PortMax = a, b
	}
	return c, nil
}

func masterKey(getenv func(string) string) (*secret.MasterKey, error) {
	raw := getenv("NORDTAIL_MASTER_KEY")
	if f := strings.TrimSpace(getenv("NORDTAIL_MASTER_KEY_FILE")); f != "" {
		if raw != "" {
			return nil, errors.New("set NORDTAIL_MASTER_KEY or NORDTAIL_MASTER_KEY_FILE, not both")
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading NORDTAIL_MASTER_KEY_FILE: %w", err)
		}
		raw = string(b)
	}
	k, err := secret.ParseMasterKey(secret.New(raw))
	if err != nil {
		return nil, fmt.Errorf("NORDTAIL_MASTER_KEY: %w", err)
	}
	return k, nil
}

func orDefault(v, d string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return d
}
