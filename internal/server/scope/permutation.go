package scope

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Permutation is a deterministic bijection over [0, N) constructed from a
// balanced Feistel network over the smallest power-of-two domain that covers
// N, combined with cycle-walking to restrict the result to [0, N). The round
// function is HMAC-SHA256 keyed by a seed derived from the caller's input.
//
// Properties:
//   - Stateless: At(k) depends only on k and the seed; there is no hidden
//     per-call state. Safe for concurrent use.
//   - Bijective: over k = 0..N-1, At(k) visits every integer in [0, N)
//     exactly once. This is the core guarantee the scan dispatcher relies on
//     for "scan every target exactly once per cycle".
//   - Deterministic: the same (N, seed) always produces the same permutation.
//
// The construction is not cryptographically secure FPE (6 rounds; SHA-256 is
// overkill for the round function yet the specific parameters are not audited
// for that use case). The guarantee we care about is fairness/unpredictability
// of scan order, not confidentiality.
type Permutation struct {
	n      uint64
	half   uint // half the effective power-of-two domain, in bits
	mask   uint64
	rounds int
	key    [32]byte
}

// NewPermutation returns a Permutation over [0, n). seed may be any length;
// it is expanded through HMAC-SHA256 into a 32-byte key before use. n must
// be >= 2 and <= 2^62 (the cap leaves headroom for the cycle-walking domain,
// which is at most 2n and must fit in uint64 shifts).
func NewPermutation(n uint64, seed []byte) (*Permutation, error) {
	if n < 2 {
		return nil, fmt.Errorf("permutation: n=%d must be >= 2", n)
	}
	if n > 1<<62 {
		return nil, fmt.Errorf("permutation: n=%d exceeds supported maximum 2^62", n)
	}
	if len(seed) == 0 {
		return nil, errors.New("permutation: seed must be non-empty")
	}

	// b = smallest even integer with 2^b >= n. Keeping b even lets the
	// Feistel halves be equal width, which is the simplest construction.
	var b uint
	for (uint64(1) << b) < n {
		b++
	}
	if b < 2 {
		b = 2
	}
	if b%2 == 1 {
		b++
	}
	half := b / 2

	p := &Permutation{
		n:      n,
		half:   half,
		mask:   (uint64(1) << half) - 1,
		rounds: 6,
	}

	// Derive a 32-byte round-function key from the caller's seed. The label
	// is part of the derivation so callers can safely reuse the same seed
	// material for unrelated key schedules elsewhere.
	h := hmac.New(sha256.New, []byte("natlas-scope-permutation-v1"))
	h.Write(seed)
	sum := h.Sum(nil)
	copy(p.key[:], sum)

	return p, nil
}

// N returns the size of the permutation domain.
func (p *Permutation) N() uint64 { return p.n }

// At returns the k-th element of the permutation. k must be in [0, N);
// callers should enforce that externally. Panics on out-of-range k so bugs
// surface immediately rather than being silently absorbed.
func (p *Permutation) At(k uint64) uint64 {
	if k >= p.n {
		panic(fmt.Sprintf("permutation: At(%d) out of range [0, %d)", k, p.n))
	}
	// Cycle walking: apply the base Feistel permutation repeatedly until the
	// output lands in [0, N). Expected iterations is domain/N, bounded by 2.
	x := p.feistel(k)
	for x >= p.n {
		x = p.feistel(x)
	}
	return x
}

// feistel applies the balanced Feistel network over the full power-of-two
// domain. It is a bijection over [0, 2^(2*half)) by construction.
func (p *Permutation) feistel(x uint64) uint64 {
	L := (x >> p.half) & p.mask
	R := x & p.mask
	for i := 0; i < p.rounds; i++ {
		f := p.roundFunc(uint8(i), R) & p.mask
		L, R = R, L^f
	}
	return (L << p.half) | R
}

// roundFunc is the keyed pseudo-random round function. The output is reduced
// to p.mask by the caller.
func (p *Permutation) roundFunc(round uint8, r uint64) uint64 {
	h := hmac.New(sha256.New, p.key[:])
	var buf [9]byte
	buf[0] = round
	binary.BigEndian.PutUint64(buf[1:], r)
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}
