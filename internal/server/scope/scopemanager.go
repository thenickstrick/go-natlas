package scope

import (
	"context"
	"errors"
	"net/netip"
	"sync"
)

// Entry is the scope-package-local representation of a single scope row.
// The caller (typically the HTTP bootstrap) maps data.ScopeItem -> Entry so
// this package has no dependency on the persistence layer.
type Entry struct {
	CIDR        netip.Prefix
	IsBlacklist bool
}

// ScopeManager owns the current whitelist/blacklist Prefixes and the active
// ScanManager. It is safe for concurrent use: readers take a shared snapshot,
// writers swap the whole state atomically on Load.
//
// The manager is *not* responsible for loading scope from the database; the
// caller passes in a slice of Entry values. Reloading on scope change is the
// caller's responsibility (admin routes call Load after writes).
type ScopeManager struct {
	seed []byte

	mu        sync.RWMutex
	scope     *Prefixes
	blacklist *Prefixes
	scan      *ScanManager

	// onCycleComplete is optionally wired into every freshly-constructed
	// ScanManager so that cycle events survive Load().
	onCycleComplete func(ctx context.Context, message string)
}

// NewScopeManager returns an empty manager keyed by seed. Load must be called
// before NextAddr returns anything useful.
//
// seed must be non-empty; callers that want a random-per-startup order should
// generate one with crypto/rand. A persisted seed yields a repeatable cycle
// order across restarts (the plan's CONSISTENT_SCAN_CYCLE behavior).
func NewScopeManager(seed []byte) (*ScopeManager, error) {
	if len(seed) == 0 {
		return nil, errors.New("scope manager: seed must be non-empty")
	}
	// Copy to detach from caller mutation.
	s := make([]byte, len(seed))
	copy(s, seed)
	return &ScopeManager{seed: s}, nil
}

// SetOnCycleComplete installs a callback invoked at every cycle boundary.
// Setting it after Load applies to subsequent reloads; the existing scan
// manager's callback is not updated in-place. Callers that care about
// cycle events should set the callback before the first Load.
func (m *ScopeManager) SetOnCycleComplete(f func(ctx context.Context, message string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCycleComplete = f
}

// Load rebuilds the manager from entries. Whitelist items go to scope;
// is_blacklist=true items go to the blacklist. An empty scope is accepted —
// NextAddr will return ErrNoScope until scope is populated. Partial failures
// roll back: the existing state survives a bad Load.
func (m *ScopeManager) Load(entries []Entry) error {
	var whitelist, blacklist []netip.Prefix
	for _, e := range entries {
		if e.IsBlacklist {
			blacklist = append(blacklist, e.CIDR)
		} else {
			whitelist = append(whitelist, e.CIDR)
		}
	}
	scope, err := NewPrefixes(whitelist)
	if err != nil {
		return err
	}
	black, err := NewPrefixes(blacklist)
	if err != nil {
		return err
	}

	var scan *ScanManager
	if scope.Size() > 0 {
		scan, err = NewScanManager(scope, black, m.seed)
		if err != nil {
			return err
		}
		m.mu.RLock()
		scan.OnCycleComplete = m.onCycleComplete
		m.mu.RUnlock()
	}

	m.mu.Lock()
	m.scope = scope
	m.blacklist = black
	m.scan = scan
	m.mu.Unlock()
	return nil
}

// ErrNoScope is returned by NextAddr when the manager has no whitelist
// configured (either Load was never called or Load was called with no
// non-blacklist entries).
var ErrNoScope = errors.New("scope manager: no scope configured")

// IsAcceptable reports whether addr is within the current scope and not
// within the current blacklist. Returns false for zero/invalid addresses.
func (m *ScopeManager) IsAcceptable(addr netip.Addr) bool {
	m.mu.RLock()
	scope, black := m.scope, m.blacklist
	m.mu.RUnlock()

	if scope == nil || !scope.Contains(addr) {
		return false
	}
	if black != nil && black.Contains(addr) {
		return false
	}
	return true
}

// NextAddr returns the next scannable address from the dispatcher. Returns
// ErrNoScope if scope is empty.
func (m *ScopeManager) NextAddr(ctx context.Context) (netip.Addr, error) {
	m.mu.RLock()
	scan := m.scan
	m.mu.RUnlock()
	if scan == nil {
		return netip.Addr{}, ErrNoScope
	}
	return scan.NextAddr(ctx)
}

// Stats returns a snapshot of the dispatcher's progress, or a zero-valued
// Stats with ScopeSize=0 if no scope is loaded.
func (m *ScopeManager) Stats() Stats {
	m.mu.RLock()
	scan := m.scan
	m.mu.RUnlock()
	if scan == nil {
		return Stats{}
	}
	return scan.Stats()
}

// Sizes returns the current whitelist and blacklist address counts. Useful
// for the status page.
func (m *ScopeManager) Sizes() (whitelist, blacklist uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scope.Size(), m.blacklist.Size()
}
