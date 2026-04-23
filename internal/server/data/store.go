package data

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrNotFound is returned by single-row Get queries when no row matches.
var ErrNotFound = errors.New("data: not found")

// Store is the backend-agnostic contract exposed to the rest of the server.
// Implementations (postgresStore, sqliteStore) wrap sqlc-generated Queriers
// and convert between dialect-specific raw types and these domain types.
type Store interface {
	// Users
	UserCreate(ctx context.Context, p UserCreateParams) (User, error)
	UserGetByEmail(ctx context.Context, email string) (User, error)
	UserGetByID(ctx context.Context, id int64) (User, error)
	UserList(ctx context.Context, limit, offset int32) ([]User, error)
	UserCount(ctx context.Context) (int64, error)
	UserSetAdmin(ctx context.Context, id int64, isAdmin bool) error
	UserSetPasswordHash(ctx context.Context, id int64, passwordHash string) error
	UserDelete(ctx context.Context, id int64) error

	// Agents
	AgentCreate(ctx context.Context, p AgentCreateParams) (Agent, error)
	AgentGetByAgentID(ctx context.Context, agentID string) (Agent, error)
	AgentListByUser(ctx context.Context, userID int64) ([]Agent, error)
	AgentListAll(ctx context.Context) ([]Agent, error)
	AgentSetTokenHash(ctx context.Context, id int64, tokenHash string) error
	AgentSetFriendlyName(ctx context.Context, id int64, name string) error
	AgentTouchLastSeen(ctx context.Context, id int64) error
	AgentDelete(ctx context.Context, id int64) error

	// Scope
	ScopeItemCreate(ctx context.Context, p ScopeItemCreateParams) (ScopeItem, error)
	ScopeItemListAll(ctx context.Context) ([]ScopeItem, error)
	ScopeItemList(ctx context.Context, isBlacklist bool) ([]ScopeItem, error)
	ScopeItemDelete(ctx context.Context, id int64) error
	ScopeLogAppend(ctx context.Context, message string) error

	// Agent config + services
	AgentConfigGet(ctx context.Context) (AgentConfig, error)
	AgentConfigUpdate(ctx context.Context, c AgentConfig) (AgentConfig, error)
	NatlasServicesGet(ctx context.Context) (NatlasServices, error)
	NatlasServicesUpdate(ctx context.Context, sha256, services string) error

	// Rescan queue
	RescanTaskCreate(ctx context.Context, userID int64, target netip.Addr) (RescanTask, error)
	RescanTaskNextPending(ctx context.Context) (RescanTask, error)
	RescanTaskDispatch(ctx context.Context, id int64) error
	RescanTaskComplete(ctx context.Context, id int64, scanID string) error
	RescanTaskReapStale(ctx context.Context, before time.Time) ([]int64, error)

	// Lifecycle
	Ping(ctx context.Context) error
	Close()
}

// -----------------------------------------------------------------------------
// Domain types. All timestamps are UTC; all nullable columns are Go pointers
// (nil == SQL NULL). IPs/prefixes are always netip types.
// -----------------------------------------------------------------------------

type User struct {
	ID                     int64
	Email                  string
	PasswordHash           string
	IsAdmin                bool
	ResultsPerPage         int32
	PreviewLength          int32
	ResultFormat           int32
	PasswordResetToken     *string
	PasswordResetExpiresAt *time.Time
	CreatedAt              time.Time
	IsActive               bool
}

type UserCreateParams struct {
	Email        string
	PasswordHash string
	IsAdmin      bool
	IsActive     bool
}

type Agent struct {
	ID           int64
	UserID       int64
	AgentID      string
	TokenHash    string
	FriendlyName string
	CreatedAt    time.Time
	LastSeenAt   *time.Time
}

type AgentCreateParams struct {
	UserID       int64
	AgentID      string
	TokenHash    string
	FriendlyName string
}

type ScopeItem struct {
	ID          int64
	CIDR        netip.Prefix
	IsBlacklist bool
	StartAddr   netip.Addr
	StopAddr    netip.Addr
	CreatedAt   time.Time
}

type ScopeItemCreateParams struct {
	CIDR        netip.Prefix
	IsBlacklist bool
	StartAddr   netip.Addr
	StopAddr    netip.Addr
}

// AgentConfig is the singleton row. Fields mirror the column set exactly.
type AgentConfig struct {
	VersionDetection      bool
	OsDetection           bool
	EnableScripts         bool
	OnlyOpens             bool
	ScanTimeoutS          int32
	WebScreenshots        bool
	VncScreenshots        bool
	WebScreenshotTimeoutS int32
	VncScreenshotTimeoutS int32
	ScriptTimeoutS        int32
	HostTimeoutS          int32
	OsScanLimit           bool
	NoPing                bool
	UdpScan               bool
	Scripts               []string
}

type NatlasServices struct {
	SHA256    string
	Services  string
	UpdatedAt time.Time
}

type RescanTask struct {
	ID           int64
	UserID       int64
	Target       netip.Addr
	ScanID       *string
	CreatedAt    time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
}
