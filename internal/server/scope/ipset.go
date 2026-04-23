// Package scope holds the in-memory scope model: a sorted, coalesced view of
// whitelist and blacklist prefixes, a cycle-walking PRP for fair target
// distribution, and the ScanManager / ScopeManager glue that the HTTP layer
// calls into.
//
// The package uses net/netip throughout; no byte-slice IP representations
// are exposed. IPv4 addresses carry their 4-byte form; IPv6 addresses use
// the 16-byte form. IPv4-mapped-in-IPv6 inputs are collapsed to pure IPv4.
package scope

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
)

// Prefixes is an ordered, coalesced list of netip.Prefix paired with
// cumulative address-count offsets so that the i-th address across the
// combined set can be resolved in O(log k) where k is the number of
// prefixes.
//
// Prefixes is immutable after construction and safe for concurrent use.
type Prefixes struct {
	entries []prefixEntry
	total   uint64
}

type prefixEntry struct {
	prefix netip.Prefix
	size   uint64 // number of addresses in this prefix (2^hostBits)
	offset uint64 // cumulative count of addresses before this prefix
}

// NewPrefixes returns a Prefixes composed of the given (possibly overlapping,
// possibly duplicated) prefixes. Subsumed prefixes are silently dropped.
// An empty input yields an empty Prefixes whose Size is 0.
//
// Prefixes larger than 2^63 addresses (e.g. IPv6 /64 or shorter) are rejected
// because their size does not fit in a uint64 along with additional state.
func NewPrefixes(input []netip.Prefix) (*Prefixes, error) {
	if len(input) == 0 {
		return &Prefixes{}, nil
	}

	// Canonicalize: every prefix normalized to its network address.
	norm := make([]netip.Prefix, 0, len(input))
	for _, p := range input {
		if !p.IsValid() {
			return nil, fmt.Errorf("scope: invalid prefix %q", p)
		}
		norm = append(norm, p.Masked())
	}

	// Sort by (start addr ascending, prefix length ascending). Ascending
	// prefix length puts broader prefixes first, which makes the subsumption
	// pass below a single forward scan.
	sort.Slice(norm, func(i, j int) bool {
		if c := norm[i].Addr().Compare(norm[j].Addr()); c != 0 {
			return c < 0
		}
		return norm[i].Bits() < norm[j].Bits()
	})

	// Drop subsumed prefixes. A prefix p is subsumed if any already-kept
	// prefix q has q.Contains(p.Addr()); since kept prefixes are broader or
	// equal at the same start address, this correctly removes duplicates
	// and nested sub-prefixes.
	disjoint := make([]netip.Prefix, 0, len(norm))
	for _, p := range norm {
		subsumed := false
		for _, q := range disjoint {
			if q.Contains(p.Addr()) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			disjoint = append(disjoint, p)
		}
	}

	entries := make([]prefixEntry, 0, len(disjoint))
	var total uint64
	for _, p := range disjoint {
		size, err := prefixSize(p)
		if err != nil {
			return nil, err
		}
		// Overflow-safe addition.
		if total+size < total {
			return nil, fmt.Errorf("scope: total prefix size overflows uint64")
		}
		entries = append(entries, prefixEntry{prefix: p, size: size, offset: total})
		total += size
	}

	return &Prefixes{entries: entries, total: total}, nil
}

// Size returns the total number of addresses covered across all prefixes.
func (p *Prefixes) Size() uint64 {
	if p == nil {
		return 0
	}
	return p.total
}

// Len returns the number of distinct prefixes after coalescing.
func (p *Prefixes) Len() int {
	if p == nil {
		return 0
	}
	return len(p.entries)
}

// Contains reports whether addr is inside any prefix in the set.
// An invalid or zero Addr returns false.
func (p *Prefixes) Contains(addr netip.Addr) bool {
	if p == nil || len(p.entries) == 0 || !addr.IsValid() {
		return false
	}
	// IPv4-mapped IPv6 addresses are treated as their IPv4 form so lookups
	// are symmetric regardless of caller representation.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	// Binary search for the first entry whose Addr is strictly greater than
	// addr. The entry immediately before that is the only possible match.
	i := sort.Search(len(p.entries), func(k int) bool {
		return p.entries[k].prefix.Addr().Compare(addr) > 0
	})
	if i == 0 {
		return false
	}
	return p.entries[i-1].prefix.Contains(addr)
}

// AddrAt returns the i-th address across the combined set in iteration order
// (prefixes sorted by start address, within each prefix in numeric order).
// Returns an error if i >= Size.
func (p *Prefixes) AddrAt(i uint64) (netip.Addr, error) {
	if p == nil || i >= p.total {
		return netip.Addr{}, fmt.Errorf("scope: index %d out of range [0, %d)", i, p.Size())
	}
	// Binary search for the first entry whose offset is strictly greater
	// than i; the entry before that is the one containing i.
	idx := sort.Search(len(p.entries), func(k int) bool {
		return p.entries[k].offset > i
	})
	idx--
	e := p.entries[idx]
	return addrAdd(e.prefix.Addr(), i-e.offset), nil
}

// prefixSize returns 2^hostBits for the given prefix. IPv4-mapped IPv6 is
// treated as IPv4.
func prefixSize(p netip.Prefix) (uint64, error) {
	addrBits := 32
	if p.Addr().Is6() && !p.Addr().Is4In6() {
		addrBits = 128
	}
	hostBits := addrBits - p.Bits()
	if hostBits < 0 {
		return 0, fmt.Errorf("scope: prefix %v has more bits than address family allows", p)
	}
	if hostBits > 63 {
		return 0, fmt.Errorf("scope: prefix %v too large (hostBits=%d > 63)", p, hostBits)
	}
	return uint64(1) << uint(hostBits), nil
}

// addrAdd returns the address obtained by adding off to a. Over-wide off
// values are allowed; the result wraps modulo the address family's size.
// For IPv4 the fast path uses uint32; for IPv6 we fall back to math/big.
func addrAdd(a netip.Addr, off uint64) netip.Addr {
	if a.Is4() {
		b4 := a.As4()
		base := binary.BigEndian.Uint32(b4[:])
		sum := base + uint32(off)
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], sum)
		return netip.AddrFrom4(out)
	}
	b := a.As16()
	n := new(big.Int).SetBytes(b[:])
	n.Add(n, new(big.Int).SetUint64(off))
	var out [16]byte
	n.FillBytes(out[:])
	return netip.AddrFrom16(out)
}
