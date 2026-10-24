package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Acceptance criterion 10: a missing or placeholder master key stops the
// process with a non-zero exit before any state is created.
//
// Failure modes covered: key unset, placeholder, wrong length, not base64,
// all zeros, and both env and file set. In each case the data directory must
// stay empty (no database, no tsnet state, no region directories).
func TestMasterKeyFailsClosed(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "nordtail")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"unset":        {},
		"placeholder":  {"NORDTAIL_MASTER_KEY=REPLACE_ME"},
		"short":        {"NORDTAIL_MASTER_KEY=c2hvcnQ="},
		"not base64":   {"NORDTAIL_MASTER_KEY=this is not base64!"},
		"all zeros":    {"NORDTAIL_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"env and file": {"NORDTAIL_MASTER_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "NORDTAIL_MASTER_KEY_FILE=" + keyFile},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			data := t.TempDir()
			cmd := exec.Command(bin)
			cmd.Env = append([]string{
				"PATH=" + os.Getenv("PATH"),
				"NORDTAIL_DATA_DIR=" + data,
				"NORDTAIL_TS_AUTHKEY=tskey-auth-canary-not-real",
				"NORDTAIL_ADMINS=admin",
			}, env...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected non-zero exit, got success:\n%s", out)
			}
			if !strings.Contains(string(out), "NORDTAIL_MASTER_KEY") {
				t.Errorf("error should name the master key setting:\n%s", out)
			}
			if strings.Contains(string(out), "canary") {
				t.Errorf("output leaked the auth key:\n%s", out)
			}
			entries, _ := os.ReadDir(data)
			if len(entries) != 0 {
				t.Errorf("state was created before failing: %v", entries)
			}
		})
	}
}
