package rig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// A report is the record of one test run, written beside the rig as Markdown
// ("portable-smb-server local\results\<kind>-<time>.md"): one row per pair and condition, with the
// outcome, the time it took and anything the condition measured. `go test -v` has the same, but a
// table that survives the terminal is what gets compared between versions.
type report struct {
	kind  string
	start time.Time
	mu    sync.Mutex
	rows  []reportRow
	notes []string
}

type reportRow struct {
	group, name, outcome string
	took                 time.Duration
	note                 string
}

func newReport(kind string) *report {
	return &report{kind: kind, start: time.Now()}
}

// add records a subtest's outcome. Call it deferred inside the subtest, once it has run.
func (r *report) add(t *testing.T, group, name string, start time.Time, note string) {
	outcome := "pass"
	switch {
	case t.Failed():
		outcome = "FAIL"
	case t.Skipped():
		outcome = "skip"
	}
	r.mu.Lock()
	r.rows = append(r.rows, reportRow{group, name, outcome, time.Since(start).Truncate(100 * time.Millisecond), note})
	r.mu.Unlock()
}

func (r *report) note(format string, args ...any) {
	r.mu.Lock()
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

// ResultsDir is where reports go: results\ beside the provisioning folder.
func ResultsDir() string { return filepath.Join(filepath.Dir(RigDir()), "results") }

// write saves the report and logs its path.
func (r *report) write(t testing.TB) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rows) == 0 && len(r.notes) == 0 {
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s run, %s\n\n", r.kind, r.start.Format("2006-01-02 15:04"))
	fmt.Fprintf(&sb, "Took %s. ", time.Since(r.start).Truncate(time.Second))
	counts := map[string]int{}
	for _, row := range r.rows {
		counts[row.outcome]++
	}
	fmt.Fprintf(&sb, "%d pass, %d fail, %d skip.\n\n", counts["pass"], counts["FAIL"], counts["skip"])
	for _, n := range r.notes {
		fmt.Fprintf(&sb, "- %s\n", n)
	}
	if len(r.notes) > 0 {
		sb.WriteString("\n")
	}
	groups := []string{}
	byGroup := map[string][]reportRow{}
	for _, row := range r.rows {
		if _, ok := byGroup[row.group]; !ok {
			groups = append(groups, row.group)
		}
		byGroup[row.group] = append(byGroup[row.group], row)
	}
	// Conditions as rows, pairs as columns: the shape that shows which client or server an
	// outcome follows.
	names := []string{}
	seen := map[string]bool{}
	for _, row := range r.rows {
		if !seen[row.name] {
			seen[row.name] = true
			names = append(names, row.name)
		}
	}
	if len(groups) > 1 {
		fmt.Fprintf(&sb, "| condition | %s |\n|---|%s\n", strings.Join(groups, " | "), strings.Repeat("---|", len(groups)))
		for _, n := range names {
			fmt.Fprintf(&sb, "| %s |", n)
			for _, g := range groups {
				cell := ""
				for _, row := range byGroup[g] {
					if row.name == n {
						cell = row.outcome + " " + row.took.String()
						if row.note != "" {
							cell += " · " + row.note
						}
					}
				}
				fmt.Fprintf(&sb, " %s |", cell)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	for _, g := range groups {
		fmt.Fprintf(&sb, "## %s\n\n| condition | outcome | took | notes |\n|---|---|---|---|\n", g)
		for _, row := range byGroup[g] {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", row.name, row.outcome, row.took, row.note)
		}
		sb.WriteString("\n")
	}
	sort.Strings(names)
	if err := os.MkdirAll(ResultsDir(), 0o755); err != nil {
		t.Logf("report: %v", err)
		return
	}
	p := filepath.Join(ResultsDir(), fmt.Sprintf("%s-%s.md", r.kind, r.start.Format("20060102-150405")))
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Logf("report: %v", err)
		return
	}
	t.Logf("report: %s", p)
}
