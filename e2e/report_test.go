//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

// Report is the machine-readable E2E result (schema in DESIGN.md "E2E report").
type Report struct {
	Schema     int       `json:"schema"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Control    string    `json:"control"`
	SetupError string    `json:"setup_error,omitempty"`
	Checks     []Check   `json:"checks"`

	mu sync.Mutex
}

type Check struct {
	ID       string `json:"id"`
	Criteria []int  `json:"criteria"`
	Status   string `json:"status"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Detail   string `json:"detail,omitempty"`
}

var report = &Report{Schema: 1}

// check records one acceptance check and fails the test when it didn't pass.
func check(t *testing.T, id string, criteria []int, expected, observed string, ok bool, detail string) {
	t.Helper()
	c := Check{ID: id, Criteria: criteria, Status: "pass", Expected: expected, Observed: observed, Detail: detail}
	if !ok {
		c.Status = "fail"
	}
	report.mu.Lock()
	report.Checks = append(report.Checks, c)
	report.mu.Unlock()
	if !ok {
		t.Errorf("%s: expected %s, observed %s %s", id, expected, observed, detail)
	}
}

func (r *Report) write(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Checks == nil {
		r.Checks = []Check{}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
