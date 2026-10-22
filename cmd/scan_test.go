package cmd

import (
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// A scan that finds a CRITICAL compromised action must be able to fail
// a CI pipeline. Without --fail-on the tool always exits 0.
func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		failOn   string
		summary  *scanner.Summary
		wantFail bool
		wantCode int
	}{
		{"none never fails", "none", &scanner.Summary{Critical: 3}, false, 0},
		{"empty never fails", "", &scanner.Summary{Critical: 3}, false, 0},
		{"critical on critical", "critical", &scanner.Summary{Critical: 1}, true, 1},
		{"critical ignores high", "critical", &scanner.Summary{High: 5}, false, 0},
		{"high catches high", "high", &scanner.Summary{High: 1}, true, 1},
		{"high catches critical", "high", &scanner.Summary{Critical: 1}, true, 1},
		{"high ignores medium", "high", &scanner.Summary{Medium: 9}, false, 0},
		{"medium catches medium", "medium", &scanner.Summary{Medium: 1}, true, 1},
		{"medium ignores low", "medium", &scanner.Summary{Low: 9}, false, 0},
		{"low catches low", "low", &scanner.Summary{Low: 1}, true, 1},
		{"low catches everything", "low", &scanner.Summary{Critical: 1}, true, 1},
		{"clean scan never fails", "low", &scanner.Summary{}, false, 0},
		{"case insensitive", "CRITICAL", &scanner.Summary{Critical: 1}, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, fail := exitCode(tt.summary, tt.failOn)
			if fail != tt.wantFail {
				t.Fatalf("exitCode(failOn=%q) fail = %v, want %v", tt.failOn, fail, tt.wantFail)
			}
			if fail && code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
		})
	}
}

// A typo in a CI config must not silently disable the gate.
func TestExitCodeRejectsUnknownThreshold(t *testing.T) {
	code, fail := exitCode(&scanner.Summary{Critical: 1}, "bogus")
	if !fail {
		t.Fatal("an unknown --fail-on value must fail loudly, not disable the gate")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (configuration error, not findings)", code)
	}
}

// A degraded scan (a threat feed was unreachable) saw almost no
// advisories. Letting it pass a gate would report "clean" for findings
// the scan never got the chance to see.
func TestExitCodeFailsOnDegradedScan(t *testing.T) {
	s := &scanner.Summary{Degraded: true, DegradedReason: "ghsa: unreachable"}
	code, fail := exitCode(s, "critical")
	if !fail {
		t.Fatal("a degraded scan must not pass the gate")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (could not check, not findings)", code)
	}
}

// The gate reads the severity counters the scanner fills in.
func TestExitCodeUsesSeverityCounters(t *testing.T) {
	s := &scanner.Summary{Low: 1}
	if _, fail := exitCode(s, "low"); !fail {
		t.Error("a LOW finding must fail the low gate")
	}
}

func TestScanTarget(t *testing.T) {
	tests := []struct{ org, user, want string }{
		{"acme", "", "org/acme"},
		{"", "bob", "user/bob"},
		{"", "", "authenticated user"},
	}
	for _, tt := range tests {
		if got := scanTarget(tt.org, tt.user); got != tt.want {
			t.Errorf("scanTarget(%q, %q) = %q, want %q", tt.org, tt.user, got, tt.want)
		}
	}
}

func TestFailOnFlagIsRegistered(t *testing.T) {
	if scanCmd.Flags().Lookup("fail-on") == nil {
		t.Fatal("scan command must expose --fail-on")
	}
}

func TestVersionIsExposed(t *testing.T) {
	if rootCmd.Version == "" {
		t.Error("root command must expose a version")
	}
	if !strings.Contains(rootCmd.Long, "SARIF") {
		t.Error("help text must mention the SARIF report")
	}
}
