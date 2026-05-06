package migrate

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUserToParams(t *testing.T) {
	got := UserToParams(PyUser{
		Email: "a@example.com", PasswordHash: "bcrypt$x", IsAdmin: true, IsActive: true,
	})
	if got.Email != "a@example.com" || !got.IsAdmin || !got.IsActive || got.PasswordHash != "bcrypt$x" {
		t.Fatalf("UserToParams: got %+v", got)
	}
}

func TestAgentToParamsBcrypts(t *testing.T) {
	out, err := AgentToParams(PyAgent{
		AgentID: "abc", Token: "plaintext-token", FriendlyName: "edge-1",
	}, 42)
	if err != nil {
		t.Fatalf("AgentToParams: %v", err)
	}
	if out.UserID != 42 || out.AgentID != "abc" || out.FriendlyName != "edge-1" {
		t.Fatalf("scalar fields wrong: %+v", out)
	}
	// TokenHash must verify against the original plaintext.
	if err := bcrypt.CompareHashAndPassword([]byte(out.TokenHash), []byte("plaintext-token")); err != nil {
		t.Fatalf("bcrypt comparison failed: %v", err)
	}
	// And reject a different password.
	if err := bcrypt.CompareHashAndPassword([]byte(out.TokenHash), []byte("other")); err == nil {
		t.Fatalf("bcrypt should not have matched a different password")
	}
}

func TestAgentToParamsRejectsEmpty(t *testing.T) {
	if _, err := AgentToParams(PyAgent{Token: "x"}, 1); err == nil {
		t.Fatal("missing agent_id should error")
	}
	if _, err := AgentToParams(PyAgent{AgentID: "x"}, 1); err == nil {
		t.Fatal("missing token should error")
	}
}

func TestScopeItemToParams(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantPfx string
		wantLast string
	}{
		{"v4 cidr", "10.0.0.0/24", "10.0.0.0/24", "10.0.0.255"},
		{"v4 single host with prefix", "10.0.0.5/32", "10.0.0.5/32", "10.0.0.5"},
		{"v4 single host no prefix", "10.0.0.5", "10.0.0.5/32", "10.0.0.5"},
		{"v4 unmasked", "10.0.0.5/24", "10.0.0.0/24", "10.0.0.255"},
		{"v6 prefix", "2001:db8::/120", "2001:db8::/120", "2001:db8::ff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ScopeItemToParams(PyScopeItem{Target: c.in})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			want := netip.MustParsePrefix(c.wantPfx)
			if got.CIDR != want {
				t.Errorf("CIDR: got %s, want %s", got.CIDR, want)
			}
			if got.StopAddr.String() != c.wantLast {
				t.Errorf("StopAddr: got %s, want %s", got.StopAddr, c.wantLast)
			}
			if got.StartAddr != want.Addr() {
				t.Errorf("StartAddr: got %s, want %s", got.StartAddr, want.Addr())
			}
		})
	}
}

func TestScopeItemToParamsRejectsGarbage(t *testing.T) {
	if _, err := ScopeItemToParams(PyScopeItem{Target: "not-an-ip"}); err == nil {
		t.Fatal("garbage target should error")
	}
}

func TestFoldRescan(t *testing.T) {
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dispatchedAt := createdAt.Add(time.Hour)
	completedAt := dispatchedAt.Add(time.Hour)

	got, err := FoldRescan(PyRescanTask{
		Target:        "10.0.0.5",
		DateAdded:     &createdAt,
		Dispatched:    true,
		DateDispatch:  &dispatchedAt,
		Complete:      true,
		DateCompleted: &completedAt,
	}, 7)
	if err != nil {
		t.Fatalf("FoldRescan: %v", err)
	}
	if got.UserID != 7 || got.Target.String() != "10.0.0.5" {
		t.Fatalf("UserID/Target wrong: %+v", got)
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, createdAt)
	}
	if got.DispatchedAt == nil || !got.DispatchedAt.Equal(dispatchedAt) {
		t.Errorf("DispatchedAt: got %v, want %v", got.DispatchedAt, dispatchedAt)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt) {
		t.Errorf("CompletedAt: got %v, want %v", got.CompletedAt, completedAt)
	}
}

func TestFoldRescanNotDispatchedYet(t *testing.T) {
	got, err := FoldRescan(PyRescanTask{Target: "10.0.0.5"}, 1)
	if err != nil {
		t.Fatalf("FoldRescan: %v", err)
	}
	if got.DispatchedAt != nil {
		t.Errorf("DispatchedAt should be nil when not dispatched, got %v", got.DispatchedAt)
	}
	if got.CompletedAt != nil {
		t.Errorf("CompletedAt should be nil when not complete, got %v", got.CompletedAt)
	}
	if got.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should default to now when DateAdded missing")
	}
}

func TestAgentConfigConvert(t *testing.T) {
	in := PyAgentConfig{
		VersionDetection: true, OsDetection: true, EnableScripts: true, OnlyOpens: true,
		ScanTimeout: 660, WebScreenshots: true, VncScreenshots: true,
		WebScreenshotTimeout: 60, VncScreenshotTimeout: 60,
		ScriptTimeout: 60, HostTimeout: 600,
		OsScanLimit: true, NoPing: false, UdpScan: false,
		Scripts: []string{"default", "ssl-cert"},
	}
	got := AgentConfigConvert(in)
	if got.ScanTimeoutS != 660 || got.WebScreenshotTimeoutS != 60 {
		t.Errorf("camelCase → _s rename wrong: %+v", got)
	}
	if len(got.Scripts) != 2 || got.Scripts[0] != "default" {
		t.Errorf("Scripts: %v", got.Scripts)
	}
}

func TestAgentConfigConvertNilScripts(t *testing.T) {
	got := AgentConfigConvert(PyAgentConfig{})
	if got.Scripts == nil {
		t.Fatal("Scripts should default to empty slice, not nil (mapping needs []string for JSON)")
	}
	if len(got.Scripts) != 0 {
		t.Errorf("Scripts should be empty, got %v", got.Scripts)
	}
}

func TestTransformESDocumentRenamesElapsed(t *testing.T) {
	doc := map[string]any{"elapsed": 42.5, "ip": "10.0.0.1"}
	out := TransformESDocument(doc)
	if _, has := out["elapsed"]; has {
		t.Errorf("elapsed should be removed; out=%v", out)
	}
	if v, ok := out["elapsed_s"]; !ok || v != 42.5 {
		t.Errorf("elapsed_s should be 42.5; out=%v", out)
	}
	if out["ip"] != "10.0.0.1" {
		t.Errorf("ip should pass through; got %v", out["ip"])
	}
}

func TestTransformESDocumentLeavesExistingElapsedSAlone(t *testing.T) {
	// If the source somehow has both, prefer the existing elapsed_s and just
	// drop elapsed (we don't want to silently overwrite a more-precise value).
	doc := map[string]any{"elapsed": 1, "elapsed_s": 99}
	out := TransformESDocument(doc)
	if out["elapsed_s"] != 99 {
		t.Errorf("existing elapsed_s should win; got %v", out["elapsed_s"])
	}
	if _, has := out["elapsed"]; has {
		t.Errorf("elapsed should still be removed")
	}
}

func TestParsePgTextArray(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"{}", []string{}},
		{"{a}", []string{"a"}},
		{"{a,b,c}", []string{"a", "b", "c"}},
		{`{"hello world","two"}`, []string{"hello world", "two"}},
		{`{"with,comma","plain"}`, []string{"with,comma", "plain"}},
		{`{"a\\b","c"}`, []string{`a\b`, "c"}},
	}
	for _, c := range cases {
		got := parsePgTextArray(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q[%d]: got %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
