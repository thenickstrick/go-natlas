package rescan_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/rescan"
)

// newStore is a tiny helper that gives each test its own SQLite-backed Store.
func newStore(t *testing.T) data.Store {
	t.Helper()
	store, err := data.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "rescan.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// seedDispatchedTask creates + dispatches a rescan_task and returns its id.
// Real dispatch sets dispatched_at = now(); tests set a NEGATIVE Threshold
// so the reap cutoff (now - threshold) lands in the future, guaranteeing
// any already-dispatched row is past the cutoff regardless of clock skew.
func seedDispatchedTask(t *testing.T, store data.Store) int64 {
	t.Helper()
	user, err := store.UserCreate(context.Background(), data.UserCreateParams{
		Email: "u@example.com", PasswordHash: "x", IsActive: true,
	})
	if err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	task, err := store.RescanTaskCreate(context.Background(), user.ID, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("RescanTaskCreate: %v", err)
	}
	if err := store.RescanTaskDispatch(context.Background(), task.ID, "scan-stale"); err != nil {
		t.Fatalf("RescanTaskDispatch: %v", err)
	}
	return task.ID
}

func TestReaperRequeuesStaleDispatch(t *testing.T) {
	store := newStore(t)
	id := seedDispatchedTask(t, store)

	r := rescan.New(store, rescan.Options{Interval: time.Hour, Threshold: -time.Hour})
	if err := r.Reap(context.Background()); err != nil {
		t.Fatalf("Reap: %v", err)
	}

	// After reap the task should pop again from NextPending with both
	// dispatched_at and scan_id cleared.
	got, err := store.RescanTaskNextPending(context.Background())
	if err != nil {
		t.Fatalf("NextPending after reap: %v", err)
	}
	if got.ID != id {
		t.Fatalf("expected reaped task %d, got %d", id, got.ID)
	}
	if got.DispatchedAt != nil {
		t.Fatalf("dispatched_at should be cleared, got %v", got.DispatchedAt)
	}
	if got.ScanID != nil {
		t.Fatalf("scan_id should be cleared, got %v", got.ScanID)
	}
}

func TestReaperLeavesFreshDispatchAlone(t *testing.T) {
	store := newStore(t)
	id := seedDispatchedTask(t, store)

	// Threshold of 1 hour: the just-dispatched task is well within the
	// fresh window and should NOT be requeued.
	r := rescan.New(store, rescan.Options{Interval: time.Hour, Threshold: time.Hour})
	if err := r.Reap(context.Background()); err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if _, err := store.RescanTaskNextPending(context.Background()); err == nil {
		t.Fatalf("NextPending should have nothing pending; the fresh task must stay dispatched")
	}
	got, err := store.RescanTaskGetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DispatchedAt == nil || got.ScanID == nil {
		t.Fatalf("fresh dispatch should retain state, got %+v", got)
	}
}

func TestReaperLeavesCompletedAlone(t *testing.T) {
	store := newStore(t)
	id := seedDispatchedTask(t, store)
	if _, err := store.RescanTaskCompleteByScanID(context.Background(), "scan-stale"); err != nil {
		t.Fatalf("CompleteByScanID: %v", err)
	}

	r := rescan.New(store, rescan.Options{Threshold: -time.Hour})
	if err := r.Reap(context.Background()); err != nil {
		t.Fatalf("Reap: %v", err)
	}

	got, err := store.RescanTaskGetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CompletedAt == nil {
		t.Fatalf("completed task should remain completed after reap")
	}
}
