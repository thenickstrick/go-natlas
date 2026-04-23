package scope

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func TestPrefixesEmpty(t *testing.T) {
	p, err := NewPrefixes(nil)
	if err != nil {
		t.Fatalf("NewPrefixes(nil): %v", err)
	}
	if p.Size() != 0 || p.Len() != 0 {
		t.Fatalf("expected empty Prefixes, got size=%d len=%d", p.Size(), p.Len())
	}
	if p.Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Fatalf("empty Prefixes should not contain anything")
	}
}

func TestPrefixesSizeSimple(t *testing.T) {
	p, err := NewPrefixes([]netip.Prefix{
		mustPrefix(t, "10.0.0.0/24"),
		mustPrefix(t, "192.0.2.0/30"),
	})
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	want := uint64(256 + 4)
	if p.Size() != want {
		t.Fatalf("Size: got %d, want %d", p.Size(), want)
	}
}

func TestPrefixesContains(t *testing.T) {
	p, err := NewPrefixes([]netip.Prefix{
		mustPrefix(t, "10.0.0.0/24"),
		mustPrefix(t, "192.0.2.0/30"),
		mustPrefix(t, "2001:db8::/120"),
	})
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	cases := []struct {
		addr string
		want bool
	}{
		{"10.0.0.0", true},
		{"10.0.0.128", true},
		{"10.0.0.255", true},
		{"10.0.1.0", false},
		{"192.0.2.3", true},
		{"192.0.2.4", false},
		{"9.255.255.255", false},
		{"2001:db8::1", true},
		{"2001:db8::ff", true},
		{"2001:db8::100", false},
	}
	for _, c := range cases {
		got := p.Contains(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("Contains(%s): got %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestPrefixesDropsSubsumed(t *testing.T) {
	// /8 fully contains /24 and the duplicate /8.
	p, err := NewPrefixes([]netip.Prefix{
		mustPrefix(t, "10.0.0.0/24"),
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	if p.Len() != 1 {
		t.Fatalf("expected 1 after coalesce, got %d", p.Len())
	}
	if p.Size() != 1<<24 {
		t.Fatalf("expected 2^24, got %d", p.Size())
	}
}

func TestPrefixesAddrAtRoundTrip(t *testing.T) {
	pfx := []netip.Prefix{
		mustPrefix(t, "10.0.0.0/28"),
		mustPrefix(t, "192.0.2.0/30"),
		mustPrefix(t, "172.16.0.0/31"),
	}
	p, err := NewPrefixes(pfx)
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	seen := map[netip.Addr]uint64{}
	for i := uint64(0); i < p.Size(); i++ {
		addr, err := p.AddrAt(i)
		if err != nil {
			t.Fatalf("AddrAt(%d): %v", i, err)
		}
		if !p.Contains(addr) {
			t.Fatalf("AddrAt(%d)=%v not contained in own set", i, addr)
		}
		if prev, dup := seen[addr]; dup {
			t.Fatalf("duplicate address %v at i=%d and i=%d", addr, prev, i)
		}
		seen[addr] = i
	}
	if uint64(len(seen)) != p.Size() {
		t.Fatalf("coverage mismatch: seen=%d, total=%d", len(seen), p.Size())
	}
}

func TestPrefixesIPv6Large(t *testing.T) {
	// Roughly the middle of the uint64 size cap.
	p, err := NewPrefixes([]netip.Prefix{mustPrefix(t, "2001:db8::/65")})
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	if p.Size() != uint64(1)<<63 {
		t.Fatalf("Size: got %d, want 2^63", p.Size())
	}
	// Random spot-check
	rng := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		i := rng.Uint64() % p.Size()
		addr, err := p.AddrAt(i)
		if err != nil {
			t.Fatalf("AddrAt(%d): %v", i, err)
		}
		if !p.Contains(addr) {
			t.Fatalf("AddrAt(%d)=%v not contained", i, addr)
		}
	}
}

func TestPrefixesAddrAtOutOfRange(t *testing.T) {
	p, err := NewPrefixes([]netip.Prefix{mustPrefix(t, "10.0.0.0/30")})
	if err != nil {
		t.Fatalf("NewPrefixes: %v", err)
	}
	if _, err := p.AddrAt(4); err == nil {
		t.Fatalf("AddrAt(size) should error")
	}
}

func TestPrefixesIPv6TooLarge(t *testing.T) {
	// /63 = 2^65 addresses — exceeds uint64 capacity.
	if _, err := NewPrefixes([]netip.Prefix{mustPrefix(t, "2001:db8::/63")}); err == nil {
		t.Fatalf("expected rejection for /63 prefix")
	}
}
