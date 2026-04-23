package data

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	sqgen "github.com/thenickstrick/go-natlas/internal/server/data/sqlite/gen"
)

// sqliteStore is the Store implementation for SQLite. IPs and timestamps are
// stored as text; this layer converts to/from the domain types.
type sqliteStore struct {
	db *sql.DB
	q  *sqgen.Queries
}

// NewSQLiteStore opens (or creates) a SQLite database at the given path and
// applies outstanding migrations. Foreign keys are enabled on each new
// connection. For a single-node dev deployment we cap to 1 writer to sidestep
// SQLITE_BUSY on concurrent writes; reads are concurrent.
func NewSQLiteStore(ctx context.Context, path string) (Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// Pure-Go SQLite + WAL is fine with multiple readers and one writer; we
	// serialize writes at the connection-pool level to avoid retry storms.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := Migrate(ctx, DialectSQLite, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}
	return &sqliteStore{db: db, q: sqgen.New(db)}, nil
}

func (s *sqliteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *sqliteStore) Close() {
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

func (s *sqliteStore) UserCreate(ctx context.Context, p UserCreateParams) (User, error) {
	row, err := s.q.UserCreate(ctx, sqgen.UserCreateParams{
		Email:        p.Email,
		PasswordHash: p.PasswordHash,
		IsAdmin:      boolToInt64(p.IsAdmin),
		IsActive:     boolToInt64(p.IsActive),
	})
	if err != nil {
		return User{}, err
	}
	return sqUserToDomain(row)
}

func (s *sqliteStore) UserGetByEmail(ctx context.Context, email string) (User, error) {
	row, err := s.q.UserGetByEmail(ctx, email)
	if err != nil {
		return User{}, sqMapNotFound(err)
	}
	return sqUserToDomain(row)
}

func (s *sqliteStore) UserGetByID(ctx context.Context, id int64) (User, error) {
	row, err := s.q.UserGetByID(ctx, id)
	if err != nil {
		return User{}, sqMapNotFound(err)
	}
	return sqUserToDomain(row)
}

func (s *sqliteStore) UserList(ctx context.Context, limit, offset int32) ([]User, error) {
	rows, err := s.q.UserList(ctx, sqgen.UserListParams{Limit: int64(limit), Offset: int64(offset)})
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		u, err := sqUserToDomain(r)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func (s *sqliteStore) UserCount(ctx context.Context) (int64, error) {
	return s.q.UserCount(ctx)
}

func (s *sqliteStore) UserSetAdmin(ctx context.Context, id int64, isAdmin bool) error {
	return s.q.UserSetAdmin(ctx, sqgen.UserSetAdminParams{ID: id, IsAdmin: boolToInt64(isAdmin)})
}

func (s *sqliteStore) UserSetPasswordHash(ctx context.Context, id int64, hash string) error {
	return s.q.UserSetPasswordHash(ctx, sqgen.UserSetPasswordHashParams{ID: id, PasswordHash: hash})
}

func (s *sqliteStore) UserDelete(ctx context.Context, id int64) error {
	return s.q.UserDelete(ctx, id)
}

// -----------------------------------------------------------------------------
// Agents
// -----------------------------------------------------------------------------

func (s *sqliteStore) AgentCreate(ctx context.Context, p AgentCreateParams) (Agent, error) {
	row, err := s.q.AgentCreate(ctx, sqgen.AgentCreateParams{
		UserID:       p.UserID,
		AgentID:      p.AgentID,
		TokenHash:    p.TokenHash,
		FriendlyName: p.FriendlyName,
	})
	if err != nil {
		return Agent{}, err
	}
	return sqAgentToDomain(row)
}

func (s *sqliteStore) AgentGetByAgentID(ctx context.Context, agentID string) (Agent, error) {
	row, err := s.q.AgentGetByAgentID(ctx, agentID)
	if err != nil {
		return Agent{}, sqMapNotFound(err)
	}
	return sqAgentToDomain(row)
}

func (s *sqliteStore) AgentListByUser(ctx context.Context, userID int64) ([]Agent, error) {
	rows, err := s.q.AgentListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, r := range rows {
		a, err := sqAgentToDomain(r)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *sqliteStore) AgentListAll(ctx context.Context) ([]Agent, error) {
	rows, err := s.q.AgentListAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, r := range rows {
		a, err := sqAgentToDomain(r)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *sqliteStore) AgentSetTokenHash(ctx context.Context, id int64, hash string) error {
	return s.q.AgentSetTokenHash(ctx, sqgen.AgentSetTokenHashParams{ID: id, TokenHash: hash})
}

func (s *sqliteStore) AgentSetFriendlyName(ctx context.Context, id int64, name string) error {
	return s.q.AgentSetFriendlyName(ctx, sqgen.AgentSetFriendlyNameParams{ID: id, FriendlyName: name})
}

func (s *sqliteStore) AgentTouchLastSeen(ctx context.Context, id int64) error {
	return s.q.AgentTouchLastSeen(ctx, id)
}

func (s *sqliteStore) AgentDelete(ctx context.Context, id int64) error {
	return s.q.AgentDelete(ctx, id)
}

// -----------------------------------------------------------------------------
// Scope
// -----------------------------------------------------------------------------

func (s *sqliteStore) ScopeItemCreate(ctx context.Context, p ScopeItemCreateParams) (ScopeItem, error) {
	row, err := s.q.ScopeItemCreate(ctx, sqgen.ScopeItemCreateParams{
		Cidr:        p.CIDR.String(),
		IsBlacklist: boolToInt64(p.IsBlacklist),
		StartAddr:   p.StartAddr.String(),
		StopAddr:    p.StopAddr.String(),
	})
	if err != nil {
		return ScopeItem{}, err
	}
	return sqScopeItemToDomain(row)
}

func (s *sqliteStore) ScopeItemListAll(ctx context.Context) ([]ScopeItem, error) {
	rows, err := s.q.ScopeItemListAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ScopeItem, 0, len(rows))
	for _, r := range rows {
		si, err := sqScopeItemToDomain(r)
		if err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, nil
}

func (s *sqliteStore) ScopeItemList(ctx context.Context, isBlacklist bool) ([]ScopeItem, error) {
	rows, err := s.q.ScopeItemList(ctx, boolToInt64(isBlacklist))
	if err != nil {
		return nil, err
	}
	out := make([]ScopeItem, 0, len(rows))
	for _, r := range rows {
		si, err := sqScopeItemToDomain(r)
		if err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, nil
}

func (s *sqliteStore) ScopeItemDelete(ctx context.Context, id int64) error {
	return s.q.ScopeItemDelete(ctx, id)
}

func (s *sqliteStore) ScopeLogAppend(ctx context.Context, message string) error {
	return s.q.ScopeLogAppend(ctx, message)
}

// -----------------------------------------------------------------------------
// Agent config + services
// -----------------------------------------------------------------------------

func (s *sqliteStore) AgentConfigGet(ctx context.Context) (AgentConfig, error) {
	row, err := s.q.AgentConfigGet(ctx)
	if err != nil {
		return AgentConfig{}, sqMapNotFound(err)
	}
	return sqAgentConfigToDomain(row)
}

func (s *sqliteStore) AgentConfigUpdate(ctx context.Context, c AgentConfig) (AgentConfig, error) {
	scripts, err := marshalScripts(c.Scripts)
	if err != nil {
		return AgentConfig{}, err
	}
	row, err := s.q.AgentConfigUpdate(ctx, sqgen.AgentConfigUpdateParams{
		VersionDetection:      boolToInt64(c.VersionDetection),
		OsDetection:           boolToInt64(c.OsDetection),
		EnableScripts:         boolToInt64(c.EnableScripts),
		OnlyOpens:             boolToInt64(c.OnlyOpens),
		ScanTimeoutS:          int64(c.ScanTimeoutS),
		WebScreenshots:        boolToInt64(c.WebScreenshots),
		VncScreenshots:        boolToInt64(c.VncScreenshots),
		WebScreenshotTimeoutS: int64(c.WebScreenshotTimeoutS),
		VncScreenshotTimeoutS: int64(c.VncScreenshotTimeoutS),
		ScriptTimeoutS:        int64(c.ScriptTimeoutS),
		HostTimeoutS:          int64(c.HostTimeoutS),
		OsScanLimit:           boolToInt64(c.OsScanLimit),
		NoPing:                boolToInt64(c.NoPing),
		UdpScan:               boolToInt64(c.UdpScan),
		Scripts:               scripts,
	})
	if err != nil {
		return AgentConfig{}, err
	}
	return sqAgentConfigToDomain(row)
}

func (s *sqliteStore) NatlasServicesGet(ctx context.Context) (NatlasServices, error) {
	row, err := s.q.NatlasServicesGet(ctx)
	if err != nil {
		return NatlasServices{}, sqMapNotFound(err)
	}
	ts, err := parseSQLiteTime(row.UpdatedAt)
	if err != nil {
		return NatlasServices{}, err
	}
	return NatlasServices{SHA256: row.Sha256, Services: row.Services, UpdatedAt: ts}, nil
}

func (s *sqliteStore) NatlasServicesUpdate(ctx context.Context, sha256, services string) error {
	return s.q.NatlasServicesUpdate(ctx, sqgen.NatlasServicesUpdateParams{
		Sha256:   sha256,
		Services: services,
	})
}

// -----------------------------------------------------------------------------
// Rescan queue
// -----------------------------------------------------------------------------

func (s *sqliteStore) RescanTaskCreate(ctx context.Context, userID int64, target netip.Addr) (RescanTask, error) {
	row, err := s.q.RescanTaskCreate(ctx, sqgen.RescanTaskCreateParams{
		UserID: userID,
		Target: target.String(),
	})
	if err != nil {
		return RescanTask{}, err
	}
	return sqRescanToDomain(row)
}

func (s *sqliteStore) RescanTaskNextPending(ctx context.Context) (RescanTask, error) {
	row, err := s.q.RescanTaskNextPending(ctx)
	if err != nil {
		return RescanTask{}, sqMapNotFound(err)
	}
	return sqRescanToDomain(row)
}

func (s *sqliteStore) RescanTaskDispatch(ctx context.Context, id int64) error {
	return s.q.RescanTaskDispatch(ctx, id)
}

func (s *sqliteStore) RescanTaskComplete(ctx context.Context, id int64, scanID string) error {
	return s.q.RescanTaskComplete(ctx, sqgen.RescanTaskCompleteParams{
		ID:     id,
		ScanID: sql.NullString{String: scanID, Valid: true},
	})
}

func (s *sqliteStore) RescanTaskReapStale(ctx context.Context, before time.Time) ([]int64, error) {
	return s.q.RescanTaskReapStale(ctx, sql.NullString{String: formatSQLiteTime(before), Valid: true})
}

// -----------------------------------------------------------------------------
// Conversion helpers (SQLite strings/ints <-> Go types)
// -----------------------------------------------------------------------------

const sqliteTimeLayout = "2006-01-02T15:04:05.000Z"

func parseSQLiteTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	// strftime('%Y-%m-%dT%H:%M:%fZ', 'now') emits millisecond precision; fall back
	// to RFC3339Nano for anything the application writes directly.
	if t, err := time.Parse(sqliteTimeLayout, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse sqlite time %q: %w", s, err)
	}
	return t.UTC(), nil
}

func formatSQLiteTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

func parseSQLiteNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseSQLiteTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func nullStringToPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func int64ToBool(i int64) bool { return i != 0 }

func marshalScripts(s []string) (string, error) {
	if s == nil {
		s = []string{}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal scripts: %w", err)
	}
	return string(b), nil
}

func unmarshalScripts(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("unmarshal scripts: %w", err)
	}
	return out, nil
}

func sqUserToDomain(r sqgen.User) (User, error) {
	createdAt, err := parseSQLiteTime(r.CreatedAt)
	if err != nil {
		return User{}, err
	}
	resetExp, err := parseSQLiteNullTime(r.PasswordResetExpiresAt)
	if err != nil {
		return User{}, err
	}
	return User{
		ID:                     r.ID,
		Email:                  r.Email,
		PasswordHash:           r.PasswordHash,
		IsAdmin:                int64ToBool(r.IsAdmin),
		ResultsPerPage:         int32(r.ResultsPerPage),
		PreviewLength:          int32(r.PreviewLength),
		ResultFormat:           int32(r.ResultFormat),
		PasswordResetToken:     nullStringToPtr(r.PasswordResetToken),
		PasswordResetExpiresAt: resetExp,
		CreatedAt:              createdAt,
		IsActive:               int64ToBool(r.IsActive),
	}, nil
}

func sqAgentToDomain(r sqgen.Agent) (Agent, error) {
	createdAt, err := parseSQLiteTime(r.CreatedAt)
	if err != nil {
		return Agent{}, err
	}
	lastSeen, err := parseSQLiteNullTime(r.LastSeenAt)
	if err != nil {
		return Agent{}, err
	}
	return Agent{
		ID:           r.ID,
		UserID:       r.UserID,
		AgentID:      r.AgentID,
		TokenHash:    r.TokenHash,
		FriendlyName: r.FriendlyName,
		CreatedAt:    createdAt,
		LastSeenAt:   lastSeen,
	}, nil
}

func sqScopeItemToDomain(r sqgen.ScopeItem) (ScopeItem, error) {
	prefix, err := netip.ParsePrefix(r.Cidr)
	if err != nil {
		return ScopeItem{}, fmt.Errorf("scope_items.cidr %q: %w", r.Cidr, err)
	}
	start, err := netip.ParseAddr(r.StartAddr)
	if err != nil {
		return ScopeItem{}, fmt.Errorf("scope_items.start_addr %q: %w", r.StartAddr, err)
	}
	stop, err := netip.ParseAddr(r.StopAddr)
	if err != nil {
		return ScopeItem{}, fmt.Errorf("scope_items.stop_addr %q: %w", r.StopAddr, err)
	}
	createdAt, err := parseSQLiteTime(r.CreatedAt)
	if err != nil {
		return ScopeItem{}, err
	}
	return ScopeItem{
		ID:          r.ID,
		CIDR:        prefix,
		IsBlacklist: int64ToBool(r.IsBlacklist),
		StartAddr:   start,
		StopAddr:    stop,
		CreatedAt:   createdAt,
	}, nil
}

func sqAgentConfigToDomain(r sqgen.AgentConfig) (AgentConfig, error) {
	scripts, err := unmarshalScripts(r.Scripts)
	if err != nil {
		return AgentConfig{}, err
	}
	return AgentConfig{
		VersionDetection:      int64ToBool(r.VersionDetection),
		OsDetection:           int64ToBool(r.OsDetection),
		EnableScripts:         int64ToBool(r.EnableScripts),
		OnlyOpens:             int64ToBool(r.OnlyOpens),
		ScanTimeoutS:          int32(r.ScanTimeoutS),
		WebScreenshots:        int64ToBool(r.WebScreenshots),
		VncScreenshots:        int64ToBool(r.VncScreenshots),
		WebScreenshotTimeoutS: int32(r.WebScreenshotTimeoutS),
		VncScreenshotTimeoutS: int32(r.VncScreenshotTimeoutS),
		ScriptTimeoutS:        int32(r.ScriptTimeoutS),
		HostTimeoutS:          int32(r.HostTimeoutS),
		OsScanLimit:           int64ToBool(r.OsScanLimit),
		NoPing:                int64ToBool(r.NoPing),
		UdpScan:               int64ToBool(r.UdpScan),
		Scripts:               scripts,
	}, nil
}

func sqRescanToDomain(r sqgen.RescanTask) (RescanTask, error) {
	target, err := netip.ParseAddr(r.Target)
	if err != nil {
		return RescanTask{}, fmt.Errorf("rescan_tasks.target %q: %w", r.Target, err)
	}
	createdAt, err := parseSQLiteTime(r.CreatedAt)
	if err != nil {
		return RescanTask{}, err
	}
	dispatchedAt, err := parseSQLiteNullTime(r.DispatchedAt)
	if err != nil {
		return RescanTask{}, err
	}
	completedAt, err := parseSQLiteNullTime(r.CompletedAt)
	if err != nil {
		return RescanTask{}, err
	}
	return RescanTask{
		ID:           r.ID,
		UserID:       r.UserID,
		Target:       target,
		ScanID:       nullStringToPtr(r.ScanID),
		CreatedAt:    createdAt,
		DispatchedAt: dispatchedAt,
		CompletedAt:  completedAt,
	}, nil
}

func sqMapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
