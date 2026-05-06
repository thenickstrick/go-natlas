// Package migrate ports a Python natlas deployment (PostgreSQL + Elasticsearch
// 7.17) into the Go natlas world (PostgreSQL or SQLite + OpenSearch 3.6).
//
// Schema differences the migrator papers over:
//
//   - User columns: creation_date → created_at, password_reset_expiration →
//     password_reset_expires_at. Direct value transfer otherwise.
//   - Agent: agentid → agent_id, date_created → created_at. token (PLAINTEXT
//     in Python) is bcrypt-hashed during migration so existing agents keep
//     working without a redeploy. Operators who want fresh tokens use
//     `natlas-admin agent rotate-token` after migration.
//   - ScopeItem: target (string) → cidr (netip.Prefix); start_addr/stop_addr
//     are recomputed from the prefix (Python stored them as raw bytes that
//     don't round-trip cleanly into our inet/text columns).
//   - Tag/scopetags: direct rename to scope_item_tags.
//   - RescanTask: dispatched (bool) + date_dispatched → dispatched_at
//     (NULL when not dispatched, the timestamp when dispatched). Same shape
//     for complete + date_completed → completed_at.
//   - AgentConfig: camelCase columns → snake_case (versionDetection →
//     version_detection, etc).
//   - ScopeLog: timestamp → ts.
//   - UserInvitation: invited → invited_at, expires → expires_at.
//   - Elasticsearch nmap docs: elapsed → elapsed_s (we standardized on the
//     "_s" suffix for second-valued integers in the Go mapping).
//
// transform.go holds only the pure functions. Connecting to the source PG /
// Elasticsearch and writing into the destination Store / Searcher lives in
// postgres.go and elastic.go alongside it.
package migrate

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

// PyUser mirrors the Python natlas "user" row shape.
type PyUser struct {
	Email                   string
	PasswordHash            string
	IsAdmin                 bool
	ResultsPerPage          int32
	PreviewLength           int32
	ResultFormat            int32
	PasswordResetToken      *string
	PasswordResetExpiration *time.Time
	CreationDate            *time.Time
	IsActive                bool
}

// PyAgent mirrors the Python "agent" row. Token is plaintext.
type PyAgent struct {
	OwnerEmail   string // looked up via FK during read
	AgentID      string
	Token        string // PLAINTEXT — bcrypted during transform
	FriendlyName string
	DateCreated  *time.Time
}

// PyScopeItem mirrors the Python "scope_item" row.
type PyScopeItem struct {
	Target    string // "10.0.0.0/24" — parsed into netip.Prefix
	Blacklist bool
	Tags      []string // resolved via scopetags JOIN before reaching us
}

// PyRescanTask mirrors the Python "rescan_task" row.
type PyRescanTask struct {
	OwnerEmail    string
	Target        string // single IP
	ScanID        *string
	DateAdded     *time.Time
	Dispatched    bool
	DateDispatch  *time.Time
	Complete      bool
	DateCompleted *time.Time
}

// PyAgentConfig mirrors the Python "agent_config" singleton row.
type PyAgentConfig struct {
	VersionDetection      bool
	OsDetection           bool
	EnableScripts         bool
	OnlyOpens             bool
	ScanTimeout           int32
	WebScreenshots        bool
	VncScreenshots        bool
	WebScreenshotTimeout  int32
	VncScreenshotTimeout  int32
	ScriptTimeout         int32
	HostTimeout           int32
	OsScanLimit           bool
	NoPing                bool
	UdpScan               bool
	Scripts               []string
}

// PyNatlasServices mirrors the Python "natlas_services" singleton row.
type PyNatlasServices struct {
	SHA256   string
	Services string
}

// PyScopeLog mirrors a single "scope_log" row.
type PyScopeLog struct {
	Message   string
	Timestamp *time.Time
}

// PyUserInvitation mirrors a "user_invitation" row.
type PyUserInvitation struct {
	Email       string
	IsAdmin     bool
	InviteToken string
	Invited     *time.Time
	Expires     *time.Time
	Accepted    bool
}

// -----------------------------------------------------------------------------
// Pure transforms
// -----------------------------------------------------------------------------

// UserToParams maps a Python user row onto the destination Store's
// UserCreateParams. password_hash flows through unchanged because Python
// natlas already used bcrypt.
func UserToParams(u PyUser) data.UserCreateParams {
	return data.UserCreateParams{
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		IsAdmin:      u.IsAdmin,
		IsActive:     u.IsActive,
	}
}

// AgentToParams maps a Python agent row + the new owner's id. The plaintext
// token is bcrypt-hashed here so existing deployed agents continue to
// authenticate against the new server.
//
// bcrypt is intentionally invoked at the default cost; we don't expose a
// flag to lower it. Migrations are one-shot operations where a few hundred
// ms per agent is acceptable.
func AgentToParams(a PyAgent, newOwnerID int64) (data.AgentCreateParams, error) {
	if a.AgentID == "" {
		return data.AgentCreateParams{}, errors.New("migrate: agent missing agent_id")
	}
	if a.Token == "" {
		return data.AgentCreateParams{}, errors.New("migrate: agent missing token")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(a.Token), bcrypt.DefaultCost)
	if err != nil {
		return data.AgentCreateParams{}, fmt.Errorf("migrate: bcrypt agent %q: %w", a.AgentID, err)
	}
	return data.AgentCreateParams{
		UserID:       newOwnerID,
		AgentID:      a.AgentID,
		TokenHash:    string(hash),
		FriendlyName: a.FriendlyName,
	}, nil
}

// ScopeItemToParams parses Python's free-form target string into a
// netip.Prefix and recomputes start/stop addresses. Python's BYTEA encoding
// for these columns isn't preserved.
func ScopeItemToParams(s PyScopeItem) (data.ScopeItemCreateParams, error) {
	prefix, err := netip.ParsePrefix(s.Target)
	if err != nil {
		// Single IPs were sometimes stored without /32 suffix.
		if addr, err2 := netip.ParseAddr(s.Target); err2 == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		} else {
			return data.ScopeItemCreateParams{}, fmt.Errorf("migrate: parse scope target %q: %w", s.Target, err)
		}
	}
	prefix = prefix.Masked()
	return data.ScopeItemCreateParams{
		CIDR:        prefix,
		IsBlacklist: s.Blacklist,
		StartAddr:   prefix.Addr(),
		StopAddr:    lastAddr(prefix),
	}, nil
}

// RescanFold collapses Python's split bool+timestamp pairs into the Go
// schema's single-pointer-timestamp shape. dispatched=true with no
// date_dispatched is treated as "dispatched at zero time" — unusual but
// possible in legacy data; we surface it rather than silently lose state.
type RescanFold struct {
	UserID       int64 // resolved before calling
	Target       netip.Addr
	ScanID       *string
	CreatedAt    time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
}

// FoldRescan converts a PyRescanTask into the destination's logical shape.
// A non-nil DispatchedAt / CompletedAt encodes the bool flag automatically.
func FoldRescan(r PyRescanTask, newOwnerID int64) (RescanFold, error) {
	addr, err := netip.ParseAddr(r.Target)
	if err != nil {
		return RescanFold{}, fmt.Errorf("migrate: parse rescan target %q: %w", r.Target, err)
	}
	out := RescanFold{
		UserID: newOwnerID,
		Target: addr,
		ScanID: r.ScanID,
	}
	if r.DateAdded != nil {
		out.CreatedAt = *r.DateAdded
	} else {
		out.CreatedAt = time.Now().UTC()
	}
	if r.Dispatched {
		t := time.Time{}
		if r.DateDispatch != nil {
			t = *r.DateDispatch
		}
		out.DispatchedAt = &t
	}
	if r.Complete {
		t := time.Time{}
		if r.DateCompleted != nil {
			t = *r.DateCompleted
		}
		out.CompletedAt = &t
	}
	return out, nil
}

// AgentConfigConvert remaps the camelCase Python columns to snake_case Go
// fields. Defaults flow through unchanged when both sides agree.
func AgentConfigConvert(c PyAgentConfig) data.AgentConfig {
	scripts := c.Scripts
	if scripts == nil {
		scripts = []string{}
	}
	return data.AgentConfig{
		VersionDetection:      c.VersionDetection,
		OsDetection:           c.OsDetection,
		EnableScripts:         c.EnableScripts,
		OnlyOpens:             c.OnlyOpens,
		ScanTimeoutS:          c.ScanTimeout,
		WebScreenshots:        c.WebScreenshots,
		VncScreenshots:        c.VncScreenshots,
		WebScreenshotTimeoutS: c.WebScreenshotTimeout,
		VncScreenshotTimeoutS: c.VncScreenshotTimeout,
		ScriptTimeoutS:        c.ScriptTimeout,
		HostTimeoutS:          c.HostTimeout,
		OsScanLimit:           c.OsScanLimit,
		NoPing:                c.NoPing,
		UdpScan:               c.UdpScan,
		Scripts:               scripts,
	}
}

// TransformESDocument applies the field renames the Go OpenSearch mapping
// expects when migrating a Python-natlas Elasticsearch document. The input
// is a raw JSON map (the Elasticsearch _source); the output is the same map
// mutated in place, returned for chaining.
//
// Renames applied:
//
//   - elapsed → elapsed_s (Python integer seconds; we standardized on _s
//     suffix for second-valued ints in the Go mapping).
//
// Anything not explicitly renamed flows through. Unknown fields are kept;
// the Go index has dynamic: false but operators can hand-amend the mapping
// before running migration if they have custom enrichment fields they want
// to preserve.
func TransformESDocument(src map[string]any) map[string]any {
	if v, ok := src["elapsed"]; ok {
		if _, has := src["elapsed_s"]; !has {
			src["elapsed_s"] = v
		}
		delete(src, "elapsed")
	}
	return src
}

// -----------------------------------------------------------------------------
// helpers (private)
// -----------------------------------------------------------------------------

// lastAddr returns the highest address in p. Mirrors the helper in the web
// admin/scope handler so ad-hoc imports compute identical start/stop pairs.
func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		base := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		host := uint32(1)<<uint(32-p.Bits()) - 1
		last := base | host
		return netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	}
	bytes := p.Addr().As16()
	flip := 128 - p.Bits()
	for i := 15; i >= 0 && flip > 0; i-- {
		if flip >= 8 {
			bytes[i] = 0xFF
			flip -= 8
		} else {
			bytes[i] |= byte(1<<uint(flip)) - 1
			flip = 0
		}
	}
	return netip.AddrFrom16(bytes)
}
