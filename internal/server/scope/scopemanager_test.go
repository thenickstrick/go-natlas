package scope

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestScopeManagerEmptyUntilLoad(t *testing.T) {
	m, err := NewScopeManager([]byte("seed"))
	if err != nil {
		t.Fatalf("NewScopeManager: %v", err)
	}
	if _, err := m.NextAddr(context.Background()); !errors.Is(err, ErrNoScope) {
		t.Fatalf("NextAddr on empty: got %v, want ErrNoScope", err)
	}
	if m.IsAcceptable(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("IsAcceptable on empty scope should be false")
	}
}

func TestScopeManagerLoadAndDispatch(t *testing.T) {
	m, err := NewScopeManager([]byte("seed"))
	if err != nil {
		t.Fatalf("NewScopeManager: %v", err)
	}
	entries := []Entry{
		{CIDR: netip.MustParsePrefix("10.0.0.0/30"), IsBlacklist: false},
		{CIDR: netip.MustParsePrefix("10.0.0.3/32"), IsBlacklist: true},
	}
	if err := m.Load(entries); err != nil {
		t.Fatalf("Load: %v", err)
	}

	whitelist, blacklist := m.Sizes()
	if whitelist != 4 || blacklist != 1 {
		t.Fatalf("Sizes: got whitelist=%d, blacklist=%d; want 4,1", whitelist, blacklist)
	}

	// IsAcceptable
	if !m.IsAcceptable(netip.MustParseAddr("10.0.0.0")) {
		t.Fatalf("10.0.0.0 should be acceptable")
	}
	if m.IsAcceptable(netip.MustParseAddr("10.0.0.3")) {
		t.Fatalf("10.0.0.3 should be blacklisted")
	}
	if m.IsAcceptable(netip.MustParseAddr("10.0.0.4")) {
		t.Fatalf("10.0.0.4 should be out of scope")
	}

	// Dispatch should return the 3 acceptable addresses across one cycle.
	seen := map[netip.Addr]struct{}{}
	for range 4 { // size=4 permutation domain; blacklist skip -> 3 unique
		addr, err := m.NextAddr(context.Background())
		if err != nil {
			t.Fatalf("NextAddr: %v", err)
		}
		seen[addr] = struct{}{}
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct addresses, got %d: %v", len(seen), seen)
	}
}

func TestScopeManagerReloadReplacesState(t *testing.T) {
	m, _ := NewScopeManager([]byte("seed"))

	if err := m.Load([]Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}); err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	if w, _ := m.Sizes(); w != 4 {
		t.Fatalf("whitelist after load 1: %d, want 4", w)
	}

	if err := m.Load([]Entry{{CIDR: netip.MustParsePrefix("192.0.2.0/28")}}); err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if w, _ := m.Sizes(); w != 16 {
		t.Fatalf("whitelist after load 2: %d, want 16", w)
	}
	if m.IsAcceptable(netip.MustParseAddr("10.0.0.0")) {
		t.Fatalf("old scope should be gone after reload")
	}
	if !m.IsAcceptable(netip.MustParseAddr("192.0.2.0")) {
		t.Fatalf("new scope should be active after reload")
	}
}
