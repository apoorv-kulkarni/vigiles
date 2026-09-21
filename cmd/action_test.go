package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real shell wrapper with controlled scanner verdicts. Building the
// real scanner is covered separately; this checks that orchestration cannot turn
// a failed, stale, missing or inconsistent verdict into success.
func TestActionVerdictContract(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable")
	}
	actionPath, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	base, head := strings.Repeat("a", 40), strings.Repeat("b", 40)
	pass := `{"status":"pass","base_commit":"` + base + `","head_commit":"` + head + `","inputs":[{}],"incomplete":[],"signals":[]}`
	for _, tc := range []struct {
		name, report, exit, event string
		wantSuccess               bool
	}{
		{"pass", pass, "0", "pull_request", true},
		{"blocked", `{"status":"blocked","incomplete":[],"signals":[{}]}`, "1", "pull_request", false},
		{"incomplete", `{"status":"incomplete","incomplete":["offline"]}`, "2", "pull_request", false},
		{"ignored error", pass, "1", "pull_request", false},
		{"forged success", `{"status":"blocked"}`, "0", "pull_request", false},
		{"stale", strings.ReplaceAll(pass, head, strings.Repeat("c", 40)), "0", "pull_request", false},
		{"empty scope", strings.ReplaceAll(pass, `[{}]`, `[]`), "0", "pull_request", false},
		{"missing report", "", "0", "pull_request", false},
		{"privileged event", pass, "0", "pull_request_target", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			mockGo := `#!/bin/bash
set -euo pipefail
[[ "$PWD" == "$VIGILES_ACTION_PATH" && "$GOWORK" == off && "$GOFLAGS" == "" && "$GOPROXY" == off ]]
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then cp "$FIXTURE_GATE" "$2"; exit 0; fi
  shift
done
exit 3
`
			mockGate := "#!/bin/bash\ncat \"$FIXTURE_REPORT\"\nexit \"$FIXTURE_EXIT\"\n"
			for name, body := range map[string]string{filepath.Join(bin, "go"): mockGo, filepath.Join(dir, "gate"): mockGate} {
				if err := os.WriteFile(name, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			event, err := json.Marshal(map[string]any{"pull_request": map[string]any{"base": map[string]string{"sha": base}, "head": map[string]string{"sha": head}, "title": "$(touch should-not-execute)"}})
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{"event.json": event, "fixture.json": []byte(tc.report), "outputs": {}, "summary": {}} {
				if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("RUNNER_OS", "Linux")
			t.Setenv("GITHUB_EVENT_NAME", tc.event)
			t.Setenv("GITHUB_EVENT_PATH", filepath.Join(dir, "event.json"))
			t.Setenv("VIGILES_ACTION_PATH", actionPath)
			t.Setenv("GITHUB_WORKSPACE", dir)
			t.Setenv("RUNNER_TEMP", dir)
			t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "outputs"))
			t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary"))
			t.Setenv("FIXTURE_GATE", filepath.Join(dir, "gate"))
			t.Setenv("FIXTURE_REPORT", filepath.Join(dir, "fixture.json"))
			t.Setenv("FIXTURE_EXIT", tc.exit)
			cmd := exec.Command("bash", filepath.Join(actionPath, "scripts", "action-gate.sh"))
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("unexpected wrapper result: %v\n%s", err, out)
			}
			if tc.wantSuccess {
				output, err := os.ReadFile(filepath.Join(dir, "outputs"))
				if err != nil || !strings.Contains(string(output), "verdict=pass") {
					t.Fatalf("missing successful output: %s %v", output, err)
				}
			}
		})
	}
}
