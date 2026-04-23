package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	pgen "github.com/thenickstrick/go-natlas/internal/server/data/postgres/gen"
)

// postgresStore is the Store implementation for PostgreSQL. It owns a pgxpool
// for the lifetime of the process and delegates most logic to sqlc-generated
// Queries; the glue code here converts pgtype values to the domain types.
type postgresStore struct {
	pool *pgxpool.Pool
	q    *pgen.Queries
}

// NewPostgresStore builds a Store against the given connection string. It
// opens the pgx connection pool, runs a Ping to fail fast on bad configs, and
// applies outstanding migrations before returning.
func NewPostgresStore(ctx context.Context, url string) (Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("postgres: pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	// Migrations need a *sql.DB via the pgx stdlib driver. Open a disposable
	// connection just for that, then close it.
	sdb, err := sql.Open("pgx", url)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: open (migrations): %w", err)
	}
	if err := Migrate(ctx, DialectPostgres, sdb); err != nil {
		_ = sdb.Close()
		pool.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}
	_ = sdb.Close()

	return &postgresStore{pool: pool, q: pgen.New(pool)}, nil
}

func (s *postgresStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *postgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

func (s *postgresStore) UserCreate(ctx context.Context, p UserCreateParams) (User, error) {
	row, err := s.q.UserCreate(ctx, pgen.UserCreateParams{
		Email:        p.Email,
		PasswordHash: p.PasswordHash,
		IsAdmin:      p.IsAdmin,
		IsActive:     p.IsActive,
	})
	if err != nil {
		return User{}, err
	}
	return pgUserToDomain(row), nil
}

func (s *postgresStore) UserGetByEmail(ctx context.Context, email string) (User, error) {
	row, err := s.q.UserGetByEmail(ctx, email)
	if err != nil {
		return User{}, pgMapNotFound(err)
	}
	return pgUserToDomain(row), nil
}

func (s *postgresStore) UserGetByID(ctx context.Context, id int64) (User, error) {
	row, err := s.q.UserGetByID(ctx, id)
	if err != nil {
		return User{}, pgMapNotFound(err)
	}
	return pgUserToDomain(row), nil
}

func (s *postgresStore) UserList(ctx context.Context, limit, offset int32) ([]User, error) {
	rows, err := s.q.UserList(ctx, pgen.UserListParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]User, len(rows))
	for i, r := range rows {
		out[i] = pgUserToDomain(r)
	}
	return out, nil
}

func (s *postgresStore) UserCount(ctx context.Context) (int64, error) {
	return s.q.UserCount(ctx)
}

func (s *postgresStore) UserSetAdmin(ctx context.Context, id int64, isAdmin bool) error {
	return s.q.UserSetAdmin(ctx, pgen.UserSetAdminParams{ID: id, IsAdmin: isAdmin})
}

func (s *postgresStore) UserSetPasswordHash(ctx context.Context, id int64, hash string) error {
	return s.q.UserSetPasswordHash(ctx, pgen.UserSetPasswordHashParams{ID: id, PasswordHash: hash})
}

func (s *postgresStore) UserDelete(ctx context.Context, id int64) error {
	return s.q.UserDelete(ctx, id)
}

// -----------------------------------------------------------------------------
// Agents
// -----------------------------------------------------------------------------

func (s *postgresStore) AgentCreate(ctx context.Context, p AgentCreateParams) (Agent, error) {
	row, err := s.q.AgentCreate(ctx, pgen.AgentCreateParams{
		UserID:       p.UserID,
		AgentID:      p.AgentID,
		TokenHash:    p.TokenHash,
		FriendlyName: p.FriendlyName,
	})
	if err != nil {
		return Agent{}, err
	}
	return pgAgentToDomain(row), nil
}

func (s *postgresStore) AgentGetByAgentID(ctx context.Context, agentID string) (Agent, error) {
	row, err := s.q.AgentGetByAgentID(ctx, agentID)
	if err != nil {
		return Agent{}, pgMapNotFound(err)
	}
	return pgAgentToDomain(row), nil
}

func (s *postgresStore) AgentListByUser(ctx context.Context, userID int64) ([]Agent, error) {
	rows, err := s.q.AgentListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, len(rows))
	for i, r := range rows {
		out[i] = pgAgentToDomain(r)
	}
	return out, nil
}

func (s *postgresStore) AgentListAll(ctx context.Context) ([]Agent, error) {
	rows, err := s.q.AgentListAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, len(rows))
	for i, r := range rows {
		out[i] = pgAgentToDomain(r)
	}
	return out, nil
}

func (s *postgresStore) AgentSetTokenHash(ctx context.Context, id int64, hash string) error {
	return s.q.AgentSetTokenHash(ctx, pgen.AgentSetTokenHashParams{ID: id, TokenHash: hash})
}

func (s *postgresStore) AgentSetFriendlyName(ctx context.Context, id int64, name string) error {
	return s.q.AgentSetFriendlyName(ctx, pgen.AgentSetFriendlyNameParams{ID: id, FriendlyName: name})
}

func (s *postgresStore) AgentTouchLastSeen(ctx context.Context, id int64) error {
	return s.q.AgentTouchLastSeen(ctx, id)
}

func (s *postgresStore) AgentDelete(ctx context.Context, id int64) error {
	return s.q.AgentDelete(ctx, id)
}

// -----------------------------------------------------------------------------
// Scope
// -----------------------------------------------------------------------------

func (s *postgresStore) ScopeItemCreate(ctx context.Context, p ScopeItemCreateParams) (ScopeItem, error) {
	row, err := s.q.ScopeItemCreate(ctx, pgen.ScopeItemCreateParams{
		Cidr:        p.CIDR,
		IsBlacklist: p.IsBlacklist,
		StartAddr:   p.StartAddr,
		StopAddr:    p.StopAddr,
	})
	if err != nil {
		return ScopeItem{}, err
	}
	return pgScopeItemToDomain(row), nil
}

func (s *postgresStore) ScopeItemListAll(ctx context.Context) ([]ScopeItem, error) {
	rows, err := s.q.ScopeItemListAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ScopeItem, len(rows))
	for i, r := range rows {
		out[i] = pgScopeItemToDomain(r)
	}
	return out, nil
}

func (s *postgresStore) ScopeItemList(ctx context.Context, isBlacklist bool) ([]ScopeItem, error) {
	rows, err := s.q.ScopeItemList(ctx, isBlacklist)
	if err != nil {
		return nil, err
	}
	out := make([]ScopeItem, len(rows))
	for i, r := range rows {
		out[i] = pgScopeItemToDomain(r)
	}
	return out, nil
}

func (s *postgresStore) ScopeItemDelete(ctx context.Context, id int64) error {
	return s.q.ScopeItemDelete(ctx, id)
}

func (s *postgresStore) ScopeLogAppend(ctx context.Context, message string) error {
	return s.q.ScopeLogAppend(ctx, message)
}

// -----------------------------------------------------------------------------
// Agent config + services
// -----------------------------------------------------------------------------

func (s *postgresStore) AgentConfigGet(ctx context.Context) (AgentConfig, error) {
	row, err := s.q.AgentConfigGet(ctx)
	if err != nil {
		return AgentConfig{}, pgMapNotFound(err)
	}
	return pgAgentConfigToDomain(row), nil
}

func (s *postgresStore) AgentConfigUpdate(ctx context.Context, c AgentConfig) (AgentConfig, error) {
	row, err := s.q.AgentConfigUpdate(ctx, pgen.AgentConfigUpdateParams{
		VersionDetection:      c.VersionDetection,
		OsDetection:           c.OsDetection,
		EnableScripts:         c.EnableScripts,
		OnlyOpens:             c.OnlyOpens,
		ScanTimeoutS:          c.ScanTimeoutS,
		WebScreenshots:        c.WebScreenshots,
		VncScreenshots:        c.VncScreenshots,
		WebScreenshotTimeoutS: c.WebScreenshotTimeoutS,
		VncScreenshotTimeoutS: c.VncScreenshotTimeoutS,
		ScriptTimeoutS:        c.ScriptTimeoutS,
		HostTimeoutS:          c.HostTimeoutS,
		OsScanLimit:           c.OsScanLimit,
		NoPing:                c.NoPing,
		UdpScan:               c.UdpScan,
		Scripts:               c.Scripts,
	})
	if err != nil {
		return AgentConfig{}, err
	}
	return pgAgentConfigToDomain(row), nil
}

func (s *postgresStore) NatlasServicesGet(ctx context.Context) (NatlasServices, error) {
	row, err := s.q.NatlasServicesGet(ctx)
	if err != nil {
		return NatlasServices{}, pgMapNotFound(err)
	}
	return NatlasServices{
		SHA256:    row.Sha256,
		Services:  row.Services,
		UpdatedAt: row.UpdatedAt.Time,
	}, nil
}

func (s *postgresStore) NatlasServicesUpdate(ctx context.Context, sha256, services string) error {
	return s.q.NatlasServicesUpdate(ctx, pgen.NatlasServicesUpdateParams{
		Sha256:   sha256,
		Services: services,
	})
}

// -----------------------------------------------------------------------------
// Rescan queue
// -----------------------------------------------------------------------------

func (s *postgresStore) RescanTaskCreate(ctx context.Context, userID int64, target netip.Addr) (RescanTask, error) {
	row, err := s.q.RescanTaskCreate(ctx, pgen.RescanTaskCreateParams{
		UserID: userID,
		Target: target,
	})
	if err != nil {
		return RescanTask{}, err
	}
	return pgRescanToDomain(row), nil
}

func (s *postgresStore) RescanTaskNextPending(ctx context.Context) (RescanTask, error) {
	row, err := s.q.RescanTaskNextPending(ctx)
	if err != nil {
		return RescanTask{}, pgMapNotFound(err)
	}
	return pgRescanToDomain(row), nil
}

func (s *postgresStore) RescanTaskDispatch(ctx context.Context, id int64) error {
	return s.q.RescanTaskDispatch(ctx, id)
}

func (s *postgresStore) RescanTaskComplete(ctx context.Context, id int64, scanID string) error {
	return s.q.RescanTaskComplete(ctx, pgen.RescanTaskCompleteParams{
		ID:     id,
		ScanID: pgtype.Text{String: scanID, Valid: true},
	})
}

func (s *postgresStore) RescanTaskReapStale(ctx context.Context, before time.Time) ([]int64, error) {
	return s.q.RescanTaskReapStale(ctx, pgtype.Timestamptz{Time: before, Valid: true})
}

// -----------------------------------------------------------------------------
// Conversion helpers
// -----------------------------------------------------------------------------

func pgUserToDomain(r pgen.User) User {
	return User{
		ID:                     r.ID,
		Email:                  r.Email,
		PasswordHash:           r.PasswordHash,
		IsAdmin:                r.IsAdmin,
		ResultsPerPage:         r.ResultsPerPage,
		PreviewLength:          r.PreviewLength,
		ResultFormat:           r.ResultFormat,
		PasswordResetToken:     pgTextToPtr(r.PasswordResetToken),
		PasswordResetExpiresAt: pgTimeToPtr(r.PasswordResetExpiresAt),
		CreatedAt:              r.CreatedAt.Time,
		IsActive:               r.IsActive,
	}
}

func pgAgentToDomain(r pgen.Agent) Agent {
	return Agent{
		ID:           r.ID,
		UserID:       r.UserID,
		AgentID:      r.AgentID,
		TokenHash:    r.TokenHash,
		FriendlyName: r.FriendlyName,
		CreatedAt:    r.CreatedAt.Time,
		LastSeenAt:   pgTimeToPtr(r.LastSeenAt),
	}
}

func pgScopeItemToDomain(r pgen.ScopeItem) ScopeItem {
	return ScopeItem{
		ID:          r.ID,
		CIDR:        r.Cidr,
		IsBlacklist: r.IsBlacklist,
		StartAddr:   r.StartAddr,
		StopAddr:    r.StopAddr,
		CreatedAt:   r.CreatedAt.Time,
	}
}

func pgAgentConfigToDomain(r pgen.AgentConfig) AgentConfig {
	return AgentConfig{
		VersionDetection:      r.VersionDetection,
		OsDetection:           r.OsDetection,
		EnableScripts:         r.EnableScripts,
		OnlyOpens:             r.OnlyOpens,
		ScanTimeoutS:          r.ScanTimeoutS,
		WebScreenshots:        r.WebScreenshots,
		VncScreenshots:        r.VncScreenshots,
		WebScreenshotTimeoutS: r.WebScreenshotTimeoutS,
		VncScreenshotTimeoutS: r.VncScreenshotTimeoutS,
		ScriptTimeoutS:        r.ScriptTimeoutS,
		HostTimeoutS:          r.HostTimeoutS,
		OsScanLimit:           r.OsScanLimit,
		NoPing:                r.NoPing,
		UdpScan:               r.UdpScan,
		Scripts:               append([]string(nil), r.Scripts...),
	}
}

func pgRescanToDomain(r pgen.RescanTask) RescanTask {
	return RescanTask{
		ID:           r.ID,
		UserID:       r.UserID,
		Target:       r.Target,
		ScanID:       pgTextToPtr(r.ScanID),
		CreatedAt:    r.CreatedAt.Time,
		DispatchedAt: pgTimeToPtr(r.DispatchedAt),
		CompletedAt:  pgTimeToPtr(r.CompletedAt),
	}
}

func pgTextToPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	v := t.String
	return &v
}

func pgTimeToPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// pgMapNotFound converts pgx's sentinel ErrNoRows into our ErrNotFound so
// callers can switch on errors.Is uniformly across dialects.
func pgMapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
