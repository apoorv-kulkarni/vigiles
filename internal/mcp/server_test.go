package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/gate"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type session struct {
	conn net.Conn
	dec  *json.Decoder
	t    *testing.T
}

func testSession(t *testing.T, check func(context.Context) *gate.Report) *session {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, server, io.Discard, "test", check); server.Close() }()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("server did not stop on EOF")
		}
	})
	return &session{client, json.NewDecoder(client), t}
}

func (s *session) send(data string) {
	s.t.Helper()
	s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(s.conn, data+"\n"); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) receive() map[string]json.RawMessage {
	s.t.Helper()
	s.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var response map[string]json.RawMessage
	if err := s.dec.Decode(&response); err != nil {
		s.t.Fatal(err)
	}
	return response
}

func (s *session) initialize() {
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`)
	r := s.receive()
	if r["error"] != nil || !bytes.Contains(r["result"], []byte(protocolVersion)) {
		s.t.Fatalf("initialize: %s", r)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func report() *gate.Report {
	return &gate.Report{Base: strings.Repeat("a", 40), Candidate: "worktree", Policy: &config.Config{}, Inputs: []gate.Input{},
		Signals: []signal.Signal{}, Incomplete: []string{}}
}

func TestSessionLifecycleAndStructuredVerdicts(t *testing.T) {
	for _, status := range []string{"pass", "blocked", "incomplete"} {
		t.Run(status, func(t *testing.T) {
			s := testSession(t, func(context.Context) *gate.Report {
				r := report()
				if status == "blocked" {
					r.Signals = append(r.Signals, signal.Signal{ID: "finding", Type: "heuristic"})
				}
				if status == "incomplete" {
					r.Incomplete = append(r.Incomplete, "missing coverage")
				}
				return r
			})
			s.send(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`)
			if r := s.receive(); !bytes.Contains(r["error"], []byte("-32002")) {
				t.Fatalf("pre-init call accepted: %s", r)
			}
			s.initialize()
			s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
			r := s.receive()
			if !bytes.Contains(r["result"], []byte(toolName)) || !bytes.Contains(r["result"], []byte(`"readOnlyHint":true`)) {
				t.Fatalf("tools: %s", r)
			}
			for i := 0; i < 2; i++ {
				s.send(`{"jsonrpc":"2.0","id":"check","method":"tools/call","params":{"name":"check_dependency_changes","arguments":{}}}`)
				r = s.receive()
				var result struct {
					Structured gate.Report                   `json:"structuredContent"`
					Content    []struct{ Type, Text string } `json:"content"`
					IsError    bool                          `json:"isError"`
				}
				if err := json.Unmarshal(r["result"], &result); err != nil {
					t.Fatal(err)
				}
				if result.Structured.Status != status || result.IsError || result.Structured.Version != "test" {
					t.Fatalf("verdict: %+v", result)
				}
				var text gate.Report
				if len(result.Content) != 1 || json.Unmarshal([]byte(result.Content[0].Text), &text) != nil || text.Status != status {
					t.Fatal("text and structured output disagree")
				}
			}
		})
	}
}

func TestToolArgumentsCannotOverrideStartupConfiguration(t *testing.T) {
	var calls atomic.Int32
	s := testSession(t, func(context.Context) *gate.Report { calls.Add(1); return report() })
	s.initialize()
	for _, params := range []string{
		`{"name":"check_dependency_changes","arguments":{"repo":"/tmp"}}`,
		`{"name":"check_dependency_changes","arguments":{"base":"HEAD"}}`,
		`{"name":"check_dependency_changes","arguments":{"fail_on":"none"}}`,
		`{"name":"check_dependency_changes","arguments":null}`,
		`{"name":"check_dependency_changes","arguments":[]}`,
		`{"name":"check_dependency_changes","arguments":{},"arguments":{"skip":true}}`,
		`{"name":"execute_shell","arguments":{}}`,
	} {
		s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":` + params + `}`)
		if r := s.receive(); r["error"] == nil {
			t.Fatalf("accepted override: %s", params)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid arguments executed a check")
	}
}

func TestCancellationPingAndBusy(t *testing.T) {
	started := make(chan struct{})
	s := testSession(t, func(ctx context.Context) *gate.Report { close(started); <-ctx.Done(); return report() })
	s.initialize()
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_dependency_changes"}}`)
	<-started
	s.send(`{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	if r := s.receive(); string(r["id"]) != "4" || r["error"] != nil {
		t.Fatalf("ping blocked: %s", r)
	}
	s.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"check_dependency_changes"}}`)
	if r := s.receive(); !bytes.Contains(r["error"], []byte("already running")) {
		t.Fatalf("concurrent check accepted: %s", r)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`)
	if r := s.receive(); string(r["id"]) != "3" || !bytes.Contains(r["result"], []byte(`"status":"incomplete"`)) {
		t.Fatalf("canceled check passed: %s", r)
	}
}

func TestMalformedMessagesAndBounds(t *testing.T) {
	s := testSession(t, func(context.Context) *gate.Report { return report() })
	for _, line := range []string{`{`, `[]`, `null`, `{"jsonrpc":"2.0","id":null,"method":"ping"}`, `{"jsonrpc":"2.0","id":{},"method":"ping"}`, `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/list"}`} {
		s.send(line)
		if r := s.receive(); r["error"] == nil {
			t.Fatalf("malformed message accepted: %s", line)
		}
	}
	var out bytes.Buffer
	err := Serve(strings.NewReader(strings.Repeat(" ", maxMessage+1)+"\n"), &out, io.Discard, "test", nil)
	if err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestOversizedReportCannotPass(t *testing.T) {
	s := testSession(t, func(context.Context) *gate.Report {
		r := report()
		r.Signals = []signal.Signal{{Summary: strings.Repeat("x", maxResult)}}
		r.Policy.Policy.FailOn = "none"
		return r
	})
	s.initialize()
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_dependency_changes"}}`)
	r := s.receive()
	if !bytes.Contains(r["result"], []byte(`"status":"incomplete"`)) || len(r["result"]) > maxResult {
		t.Fatal("oversized report passed or was not bounded")
	}
}

func TestProtocolVersionNegotiation(t *testing.T) {
	for _, version := range []string{"2025-06-18", "2025-11-25", "2099-01-01"} {
		t.Run(version, func(t *testing.T) {
			s := testSession(t, nil)
			s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`)
			r := s.receive()
			want := version
			if version == "2099-01-01" {
				want = protocolVersion
			}
			if r["error"] != nil || !bytes.Contains(r["result"], []byte(want)) {
				t.Fatalf("negotiation: %s", r)
			}
		})
	}
}
