package scope

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func TestPermutationRejectsInvalidN(t *testing.T) {
	if _, err := NewPermutation(0, []byte("seed")); err == nil {
		t.Fatalf("n=0 should error")
	}
	if _, err := NewPermutation(1, []byte("seed")); err == nil {
		t.Fatalf("n=1 should error")
	}
	if _, err := NewPermutation(10, nil); err == nil {
		t.Fatalf("empty seed should error")
	}
}

func TestPermutationBijectionSmall(t *testing.T) {
	// Exhaustive bijection test for all small sizes with a fixed seed.
	for n := uint64(2); n <= 256; n++ {
		assertBijection(t, n, []byte("seed-small"))
	}
}

// TestPermutationBijectionProperty checks bijection over 50 random sizes and
// seeds from a deterministic PCG stream. Covers odd n (forcing cycle walking
// past the naive domain), powers of two (no walking), and near-power sizes.
func TestPermutationBijectionProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 1729))
	for i := 0; i < 50; i++ {
		n := uint64(rng.IntN(4095)) + 2 // [2, 4096]
		seed := make([]byte, 16)
		binary.LittleEndian.PutUint64(seed[:8], rng.Uint64())
		binary.LittleEndian.PutUint64(seed[8:], rng.Uint64())
		assertBijection(t, n, seed)
	}
}

func TestPermutationDeterminism(t *testing.T) {
	seed := []byte("repeatable")
	p1, _ := NewPermutation(1000, seed)
	p2, _ := NewPermutation(1000, seed)
	for k := uint64(0); k < 1000; k++ {
		if p1.At(k) != p2.At(k) {
			t.Fatalf("same (n, seed) disagrees at k=%d: %d vs %d", k, p1.At(k), p2.At(k))
		}
	}
}

func TestPermutationDifferentSeedsDiffer(t *testing.T) {
	// Two different seeds should yield a noticeably different permutation.
	// We don't demand no fixed points, just that the permutations aren't
	// identical — a single-point disagreement suffices.
	p1, _ := NewPermutation(1024, []byte("alpha"))
	p2, _ := NewPermutation(1024, []byte("beta"))
	diff := 0
	for k := uint64(0); k < 1024; k++ {
		if p1.At(k) != p2.At(k) {
			diff++
		}
	}
	if diff == 0 {
		t.Fatalf("two seeds produced identical permutations")
	}
}

func assertBijection(t *testing.T, n uint64, seed []byte) {
	t.Helper()
	p, err := NewPermutation(n, seed)
	if err != nil {
		t.Fatalf("NewPermutation(%d, %q): %v", n, seed, err)
	}
	seen := make([]bool, n)
	for k := uint64(0); k < n; k++ {
		v := p.At(k)
		if v >= n {
			t.Fatalf("At(%d)=%d outside [0, %d)", k, v, n)
		}
		if seen[v] {
			t.Fatalf("At not bijective for n=%d seed=%q: value %d produced twice", n, seed, v)
		}
		seen[v] = true
	}
}
