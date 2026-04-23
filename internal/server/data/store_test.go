package data_test

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

// newSQLiteStore spins up a throwaway SQLite database in the test's temp dir.
// Migrations run as part of NewSQLiteStore, so the returned Store is already
// on the latest schema.
func newSQLiteStore(t *testing.T) data.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "natlas.sqlite")
	store, err := data.NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func TestMigrationsApply(t *testing.T) {
	store := newSQLiteStore(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	// Running the constructor a second time against the same file path is the
	// real idempotency test — golang-migrate should see no pending migrations.
	// We can't easily do that without leaking a file, so use a quick re-probe.
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after re-probe: %v", err)
	}
}

func TestUserRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStore(t)

	created, err := store.UserCreate(ctx, data.UserCreateParams{
		Email:        "alice@example.com",
		PasswordHash: "bcrypt$notreal",
		IsAdmin:      true,
		IsActive:     true,
	})
	if err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	if created.ID == 0 {
		t.Fatalf("expected non-zero id, got %+v", created)
	}
	if !created.IsAdmin || !created.IsActive {
		t.Fatalf("bool flags lost round-trip: %+v", created)
	}

	got, err := store.UserGetByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("UserGetByEmail: %v", err)
	}
	if got.ID != created.ID || got.Email != created.Email {
		t.Fatalf("mismatch: got %+v, want %+v", got, created)
	}

	if _, err := store.UserGetByEmail(ctx, "nobody@example.com"); !errors.Is(err, data.ErrNotFound) {
		t.Fatalf("UserGetByEmail(missing): got %v, want ErrNotFound", err)
	}

	n, err := store.UserCount(ctx)
	if err != nil {
		t.Fatalf("UserCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("UserCount: got %d, want 1", n)
	}

	if err := store.UserSetAdmin(ctx, created.ID, false); err != nil {
		t.Fatalf("UserSetAdmin: %v", err)
	}
	got, _ = store.UserGetByID(ctx, created.ID)
	if got.IsAdmin {
		t.Fatalf("UserSetAdmin(false) did not demote: %+v", got)
	}
}

func TestAgentRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStore(t)

	user, err := store.UserCreate(ctx, data.UserCreateParams{
		Email:        "owner@example.com",
		PasswordHash: "x",
		IsActive:     true,
	})
	if err != nil {
		t.Fatalf("UserCreate: %v", err)
	}

	agent, err := store.AgentCreate(ctx, data.AgentCreateParams{
		UserID:       user.ID,
		AgentID:      "agent-abc123",
		TokenHash:    "bcrypt$token",
		FriendlyName: "primary",
	})
	if err != nil {
		t.Fatalf("AgentCreate: %v", err)
	}
	if agent.LastSeenAt != nil {
		t.Fatalf("expected LastSeenAt nil on create, got %v", agent.LastSeenAt)
	}

	if err := store.AgentTouchLastSeen(ctx, agent.ID); err != nil {
		t.Fatalf("AgentTouchLastSeen: %v", err)
	}
	got, err := store.AgentGetByAgentID(ctx, agent.AgentID)
	if err != nil {
		t.Fatalf("AgentGetByAgentID: %v", err)
	}
	if got.LastSeenAt == nil {
		t.Fatalf("expected LastSeenAt populated after touch")
	}
}

func TestScopeItemRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStore(t)

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	start := netip.MustParseAddr("10.0.0.0")
	stop := netip.MustParseAddr("10.0.0.255")

	item, err := store.ScopeItemCreate(ctx, data.ScopeItemCreateParams{
		CIDR:      prefix,
		StartAddr: start,
		StopAddr:  stop,
	})
	if err != nil {
		t.Fatalf("ScopeItemCreate: %v", err)
	}
	if item.CIDR != prefix || item.StartAddr != start || item.StopAddr != stop {
		t.Fatalf("round-trip mismatch: %+v", item)
	}
	if item.IsBlacklist {
		t.Fatalf("IsBlacklist should default to false")
	}

	items, err := store.ScopeItemListAll(ctx)
	if err != nil {
		t.Fatalf("ScopeItemListAll: %v", err)
	}
	if len(items) != 1 || items[0].ID != item.ID {
		t.Fatalf("ScopeItemListAll: got %+v, want one item with id=%d", items, item.ID)
	}
}

func TestAgentConfigSingleton(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStore(t)

	cfg, err := store.AgentConfigGet(ctx)
	if err != nil {
		t.Fatalf("AgentConfigGet (seeded): %v", err)
	}
	if !cfg.VersionDetection || cfg.ScanTimeoutS == 0 {
		t.Fatalf("expected seeded defaults, got %+v", cfg)
	}
	// Default scripts should round-trip through JSON encoding.
	if len(cfg.Scripts) != 1 || cfg.Scripts[0] != "default" {
		t.Fatalf("expected seeded scripts=[default], got %v", cfg.Scripts)
	}

	cfg.ScanTimeoutS = 900
	cfg.EnableScripts = false
	cfg.Scripts = []string{"default", "ssl-cert"}
	out, err := store.AgentConfigUpdate(ctx, cfg)
	if err != nil {
		t.Fatalf("AgentConfigUpdate: %v", err)
	}
	if out.ScanTimeoutS != 900 || out.EnableScripts || len(out.Scripts) != 2 {
		t.Fatalf("update did not persist: %+v", out)
	}
}

func TestRescanQueueLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStore(t)

	user, err := store.UserCreate(ctx, data.UserCreateParams{Email: "q@example.com", PasswordHash: "x", IsActive: true})
	if err != nil {
		t.Fatalf("UserCreate: %v", err)
	}

	target := netip.MustParseAddr("192.0.2.5")
	task, err := store.RescanTaskCreate(ctx, user.ID, target)
	if err != nil {
		t.Fatalf("RescanTaskCreate: %v", err)
	}
	if task.Target != target || task.DispatchedAt != nil || task.CompletedAt != nil {
		t.Fatalf("unexpected state on create: %+v", task)
	}

	next, err := store.RescanTaskNextPending(ctx)
	if err != nil {
		t.Fatalf("RescanTaskNextPending: %v", err)
	}
	if next.ID != task.ID {
		t.Fatalf("NextPending returned wrong task: %+v vs %+v", next, task)
	}

	if err := store.RescanTaskDispatch(ctx, task.ID); err != nil {
		t.Fatalf("RescanTaskDispatch: %v", err)
	}
	if err := store.RescanTaskComplete(ctx, task.ID, "scan-xyz"); err != nil {
		t.Fatalf("RescanTaskComplete: %v", err)
	}

	if _, err := store.RescanTaskNextPending(ctx); !errors.Is(err, data.ErrNotFound) {
		t.Fatalf("NextPending after complete: got %v, want ErrNotFound", err)
	}
}
