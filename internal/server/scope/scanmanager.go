package scope

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// ScanManager composes a scope Prefixes, an optional blacklist Prefixes, and
// a cycle-walking Permutation into a deterministic target dispatcher.
//
// NextAddr returns the next scannable address (one the agent should target),
// skipping blacklisted addresses within the same cycle. When the permutation
// cursor wraps past the scope size, the cycle counter increments and the
// optional OnCycleComplete callback fires.
//
// The zero value is not usable; construct via NewScanManager.
type ScanManager struct {
	scope     *Prefixes
	blacklist *Prefixes
	perm      *Permutation

	mu              sync.Mutex
	cursor          uint64
	cycleStart      time.Time
	cyclesCompleted uint64

	// OnCycleComplete, if non-nil, is invoked synchronously at every cycle
	// boundary. Handlers must be cheap; blocking here blocks NextAddr.
	// The message is a pre-formatted operator-readable summary suitable for
	// appending to the scope_log table.
	OnCycleComplete func(ctx context.Context, message string)
}

// Stats is a point-in-time snapshot of the dispatcher's state, suitable for
// the /api/status endpoint.
type Stats struct {
	ScopeSize       uint64
	Cursor          uint64
	CyclesCompleted uint64
	CycleStart      time.Time
}

// NewScanManager returns a manager over the given scope. blacklist may be nil
// or empty; addresses it covers are skipped during NextAddr. seed keys the
// Permutation.
func NewScanManager(scope, blacklist *Prefixes, seed []byte) (*ScanManager, error) {
	if scope == nil || scope.Size() == 0 {
		return nil, errors.New("scan manager: scope is empty")
	}
	perm, err := NewPermutation(scope.Size(), seed)
	if err != nil {
		return nil, fmt.Errorf("scan manager: permutation: %w", err)
	}
	return &ScanManager{
		scope:      scope,
		blacklist:  blacklist,
		perm:       perm,
		cycleStart: time.Now().UTC(),
	}, nil
}

// NextAddr returns the next in-scope, non-blacklisted address. If every
// scope address is blacklisted, an error is returned rather than looping
// forever; callers should treat that as a configuration problem.
func (sm *ScanManager) NextAddr(ctx context.Context) (netip.Addr, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Worst case: every slot in the current cycle is blacklisted. We bound
	// the probe loop to scope.Size() so a fully-blacklisted scope fails fast
	// rather than infinite-looping.
	scopeSize := sm.scope.Size()
	for range scopeSize {
		idx := sm.perm.At(sm.cursor)
		sm.advanceCursor(ctx)

		addr, err := sm.scope.AddrAt(idx)
		if err != nil {
			return netip.Addr{}, err
		}
		if sm.blacklist != nil && sm.blacklist.Contains(addr) {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, errors.New("scan manager: entire scope is blacklisted")
}

// advanceCursor increments the cursor and handles cycle wrap. Caller holds mu.
func (sm *ScanManager) advanceCursor(ctx context.Context) {
	sm.cursor++
	if sm.cursor < sm.scope.Size() {
		return
	}
	// Wrap: one full cycle complete.
	sm.cursor = 0
	sm.cyclesCompleted++
	prev := sm.cycleStart
	now := time.Now().UTC()
	sm.cycleStart = now
	if sm.OnCycleComplete != nil {
		msg := fmt.Sprintf(
			"scan cycle %d complete (scope=%d, elapsed=%s)",
			sm.cyclesCompleted,
			sm.scope.Size(),
			now.Sub(prev).Round(time.Second),
		)
		sm.OnCycleComplete(ctx, msg)
	}
}

// Stats returns a snapshot of the dispatcher state. Safe for concurrent use.
func (sm *ScanManager) Stats() Stats {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return Stats{
		ScopeSize:       sm.scope.Size(),
		Cursor:          sm.cursor,
		CyclesCompleted: sm.cyclesCompleted,
		CycleStart:      sm.cycleStart,
	}
}
