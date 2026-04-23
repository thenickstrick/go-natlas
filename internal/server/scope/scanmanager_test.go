package scope

import (
	"context"
	"net/netip"
	"sync"
	"testing"
)

func buildScope(t *testing.T, prefixes ...string) *Prefixes {
	t.Helper()
	var pfx []netip.Prefix
	for _, s := range prefixes {
		pfx = append(pfx, mustPrefix(t, s))
	}
	p, err := NewPrefixes(pfx)
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	return p
}

func TestScanManagerCycleCoversEveryAddress(t *testing.T) {
	scope := buildScope(t, "10.0.0.0/29", "192.0.2.0/30") // 8 + 4 = 12 addresses
	sm, err := NewScanManager(scope, nil, []byte("seed"))
	if err != nil {
		t.Fatalf("NewScanManager: %v", err)
	}

	seen := map[netip.Addr]int{}
	for i := 0; i < int(scope.Size()); i++ {
		addr, err := sm.NextAddr(context.Background())
		if err != nil {
			t.Fatalf("NextAddr: %v", err)
		}
		seen[addr]++
	}
	if len(seen) != int(scope.Size()) {
		t.Fatalf("expected %d unique addresses in one cycle, got %d (seen=%v)", scope.Size(), len(seen), seen)
	}
	for addr, n := range seen {
		if n != 1 {
			t.Fatalf("address %v appeared %d times in one cycle", addr, n)
		}
	}
}

func TestScanManagerCycleCompleteFires(t *testing.T) {
	scope := buildScope(t, "10.0.0.0/29") // 8 addresses
	sm, err := NewScanManager(scope, nil, []byte("seed"))
	if err != nil {
		t.Fatalf("NewScanManager: %v", err)
	}

	var mu sync.Mutex
	var messages []string
	sm.OnCycleComplete = func(_ context.Context, msg string) {
		mu.Lock()
		messages = append(messages, msg)
		mu.Unlock()
	}

	// Run two full cycles.
	for i := 0; i < 2*int(scope.Size()); i++ {
		if _, err := sm.NextAddr(context.Background()); err != nil {
			t.Fatalf("NextAddr: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 2 {
		t.Fatalf("expected 2 cycle-complete events, got %d: %v", len(messages), messages)
	}
	stats := sm.Stats()
	if stats.CyclesCompleted != 2 {
		t.Fatalf("Stats.CyclesCompleted: got %d, want 2", stats.CyclesCompleted)
	}
}

func TestScanManagerBlacklistSkipped(t *testing.T) {
	scope := buildScope(t, "10.0.0.0/29") // 10.0.0.0 .. 10.0.0.7
	black := buildScope(t, "10.0.0.4/32", "10.0.0.5/32")
	sm, err := NewScanManager(scope, black, []byte("seed"))
	if err != nil {
		t.Fatalf("NewScanManager: %v", err)
	}

	// Drive enough calls to cover the whole effective set (6 addresses). The
	// blacklisted addresses must never be returned.
	badAddrs := map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.4"): {},
		netip.MustParseAddr("10.0.0.5"): {},
	}
	got := map[netip.Addr]struct{}{}
	// Use scope.Size() calls to ensure we've crossed the whole permutation
	// domain at least once.
	for i := 0; i < int(scope.Size()); i++ {
		addr, err := sm.NextAddr(context.Background())
		if err != nil {
			t.Fatalf("NextAddr: %v", err)
		}
		if _, bad := badAddrs[addr]; bad {
			t.Fatalf("blacklisted address %v returned from NextAddr", addr)
		}
		got[addr] = struct{}{}
	}
	// Over one permutation cycle we should see exactly the 6 non-blacklisted
	// addresses.
	if len(got) != 6 {
		t.Fatalf("expected 6 distinct addresses, got %d: %v", len(got), got)
	}
}

func TestScanManagerFullBlacklist(t *testing.T) {
	scope := buildScope(t, "10.0.0.0/30") // 4 addresses
	black := buildScope(t, "10.0.0.0/30") // same 4 addresses
	sm, err := NewScanManager(scope, black, []byte("seed"))
	if err != nil {
		t.Fatalf("NewScanManager: %v", err)
	}
	if _, err := sm.NextAddr(context.Background()); err == nil {
		t.Fatalf("NextAddr with fully-blacklisted scope should error")
	}
}
