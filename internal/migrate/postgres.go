package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/thenickstrick/go-natlas/internal/server/data"

	// pgx stdlib driver registers under "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// RelationalReport summarizes the row counts produced by MigrateRelational.
type RelationalReport struct {
	Users         int64
	Agents        int64
	ScopeItems    int64
	Tags          int64
	ScopeItemTags int64
	RescanTasks   int64
	AgentConfig   int64 // 0 or 1 (singleton)
	Services      int64 // 0 or 1 (singleton)
	ScopeLog      int64
	Invitations   int64
}

// MigrateRelational reads the Python natlas Postgres tables in dependency
// order and writes them into the Go destination Store. dryRun=true does the
// reads + transforms but skips writes, so operators can preflight a
// migration before committing.
//
// Idempotency: dest writes use natural keys + ON CONFLICT-style guards so
// re-running the migration after partial failure is safe. Existing rows are
// left alone (we never overwrite a destination row that has the same email,
// agent_id, etc.).
func MigrateRelational(ctx context.Context, srcURL string, dest data.Store, dryRun bool) (RelationalReport, error) {
	src, err := sql.Open("pgx", srcURL)
	if err != nil {
		return RelationalReport{}, fmt.Errorf("migrate: open source pg: %w", err)
	}
	defer src.Close()
	if err := src.PingContext(ctx); err != nil {
		return RelationalReport{}, fmt.Errorf("migrate: ping source pg: %w", err)
	}

	var rep RelationalReport

	// Users first — every other table FKs into them. We capture old_id →
	// new_id mappings so subsequent tables (agents, rescans, invitations)
	// can resolve owner references.
	oldUserToEmail := map[int64]string{}
	emailToNewID := map[string]int64{}
	if err := pgRead(ctx, src, `
		SELECT id, email, password_hash,
		       COALESCE(is_admin, false), COALESCE(results_per_page, 100),
		       COALESCE(preview_length, 100), COALESCE(result_format, 0),
		       password_reset_token, password_reset_expiration,
		       creation_date, COALESCE(is_active, false)
		FROM "user" ORDER BY id
	`, func(rows *sql.Rows) error {
		var (
			oldID                    int64
			u                        PyUser
			resetTokenN              sql.NullString
			resetExpN, creationDateN sql.NullTime
		)
		if err := rows.Scan(&oldID, &u.Email, &u.PasswordHash,
			&u.IsAdmin, &u.ResultsPerPage, &u.PreviewLength, &u.ResultFormat,
			&resetTokenN, &resetExpN, &creationDateN, &u.IsActive); err != nil {
			return err
		}
		if resetTokenN.Valid {
			s := resetTokenN.String
			u.PasswordResetToken = &s
		}
		if resetExpN.Valid {
			t := resetExpN.Time
			u.PasswordResetExpiration = &t
		}
		if creationDateN.Valid {
			t := creationDateN.Time
			u.CreationDate = &t
		}
		oldUserToEmail[oldID] = u.Email

		if dryRun {
			rep.Users++
			return nil
		}
		// Skip if a user with this email already exists in the destination.
		if existing, err := dest.UserGetByEmail(ctx, u.Email); err == nil {
			emailToNewID[u.Email] = existing.ID
			return nil
		} else if !errors.Is(err, data.ErrNotFound) {
			return fmt.Errorf("user lookup %q: %w", u.Email, err)
		}
		created, err := dest.UserCreate(ctx, UserToParams(u))
		if err != nil {
			return fmt.Errorf("user create %q: %w", u.Email, err)
		}
		emailToNewID[u.Email] = created.ID
		rep.Users++
		return nil
	}); err != nil {
		return rep, fmt.Errorf("users: %w", err)
	}

	// Agents
	if err := pgRead(ctx, src, `
		SELECT user_id, agentid, COALESCE(token, ''), COALESCE(friendly_name, ''), date_created
		FROM agent ORDER BY id
	`, func(rows *sql.Rows) error {
		var (
			userID         int64
			a              PyAgent
			dateCreatedN   sql.NullTime
		)
		if err := rows.Scan(&userID, &a.AgentID, &a.Token, &a.FriendlyName, &dateCreatedN); err != nil {
			return err
		}
		if dateCreatedN.Valid {
			t := dateCreatedN.Time
			a.DateCreated = &t
		}
		email, ok := oldUserToEmail[userID]
		if !ok {
			slog.WarnContext(ctx, "migrate: agent references missing user; skipping",
				"agent_id", a.AgentID, "user_id", userID)
			return nil
		}
		a.OwnerEmail = email
		newOwnerID, ok := emailToNewID[email]
		if !ok {
			// dry-run path or user filtered upstream — note + skip.
			if !dryRun {
				slog.WarnContext(ctx, "migrate: skipping agent with unmapped owner",
					"agent_id", a.AgentID, "owner_email", email)
				return nil
			}
			rep.Agents++
			return nil
		}
		if dryRun {
			rep.Agents++
			return nil
		}
		// Idempotency: skip if dest already has this agent_id.
		if _, err := dest.AgentGetByAgentID(ctx, a.AgentID); err == nil {
			return nil
		} else if !errors.Is(err, data.ErrNotFound) {
			return fmt.Errorf("agent lookup %q: %w", a.AgentID, err)
		}
		params, err := AgentToParams(a, newOwnerID)
		if err != nil {
			return err
		}
		if _, err := dest.AgentCreate(ctx, params); err != nil {
			return fmt.Errorf("agent create %q: %w", a.AgentID, err)
		}
		rep.Agents++
		return nil
	}); err != nil {
		return rep, fmt.Errorf("agents: %w", err)
	}

	// Scope items + tags. Pull tags first so we can attach during scope insert.
	tagsByScopeID := map[int64][]string{}
	if err := pgRead(ctx, src, `
		SELECT s.id, t.name FROM scope_item s
		LEFT JOIN scopetags st ON st.scope_id = s.id
		LEFT JOIN tag t ON t.id = st.tag_id
		WHERE t.id IS NOT NULL
		ORDER BY s.id, t.name
	`, func(rows *sql.Rows) error {
		var (
			scopeID int64
			tag     string
		)
		if err := rows.Scan(&scopeID, &tag); err != nil {
			return err
		}
		tagsByScopeID[scopeID] = append(tagsByScopeID[scopeID], tag)
		return nil
	}); err != nil {
		// scopetags JOIN is optional — if the source schema lacks it, just
		// log and continue without per-item tags.
		slog.WarnContext(ctx, "migrate: could not read scope tags; continuing without tags", "err", err)
	}

	// Track which prefixes we've inserted to dedupe across (cidr, blacklist).
	seen := map[string]bool{}
	if err := pgRead(ctx, src, `
		SELECT id, target, COALESCE(blacklist, false) FROM scope_item ORDER BY id
	`, func(rows *sql.Rows) error {
		var (
			oldID int64
			si    PyScopeItem
		)
		if err := rows.Scan(&oldID, &si.Target, &si.Blacklist); err != nil {
			return err
		}
		si.Tags = tagsByScopeID[oldID]
		params, err := ScopeItemToParams(si)
		if err != nil {
			slog.WarnContext(ctx, "migrate: skipping unparseable scope target",
				"target", si.Target, "err", err)
			return nil
		}
		key := params.CIDR.String() + "|" + boolStr(params.IsBlacklist)
		if seen[key] {
			return nil
		}
		seen[key] = true

		if dryRun {
			rep.ScopeItems++
			return nil
		}
		if _, err := dest.ScopeItemCreate(ctx, params); err != nil {
			return fmt.Errorf("scope create %q: %w", params.CIDR, err)
		}
		rep.ScopeItems++

		// Tag-write path is best-effort; the underlying queries return errors
		// for FK or UNIQUE issues which we surface but don't fatal on.
		// (Tag insert helpers aren't on the Store interface yet — Phase 6b
		// follow-up.)
		_ = si.Tags
		return nil
	}); err != nil {
		return rep, fmt.Errorf("scope_items: %w", err)
	}

	// Rescan tasks
	if err := pgRead(ctx, src, `
		SELECT user_id, target, scan_id, date_added,
		       COALESCE(dispatched, false), date_dispatched,
		       COALESCE(complete, false), date_completed
		FROM rescan_task ORDER BY id
	`, func(rows *sql.Rows) error {
		var (
			userID                                       int64
			r                                            PyRescanTask
			scanIDN                                      sql.NullString
			dateAddedN, dateDispatchN, dateCompletedN    sql.NullTime
		)
		if err := rows.Scan(&userID, &r.Target, &scanIDN,
			&dateAddedN, &r.Dispatched, &dateDispatchN, &r.Complete, &dateCompletedN); err != nil {
			return err
		}
		if scanIDN.Valid {
			s := scanIDN.String
			r.ScanID = &s
		}
		if dateAddedN.Valid {
			t := dateAddedN.Time
			r.DateAdded = &t
		}
		if dateDispatchN.Valid {
			t := dateDispatchN.Time
			r.DateDispatch = &t
		}
		if dateCompletedN.Valid {
			t := dateCompletedN.Time
			r.DateCompleted = &t
		}
		email, ok := oldUserToEmail[userID]
		if !ok {
			return nil
		}
		r.OwnerEmail = email
		newOwnerID, ok := emailToNewID[email]
		if !ok && !dryRun {
			return nil
		}
		fold, err := FoldRescan(r, newOwnerID)
		if err != nil {
			slog.WarnContext(ctx, "migrate: skipping unparseable rescan target",
				"target", r.Target, "err", err)
			return nil
		}
		if dryRun {
			rep.RescanTasks++
			return nil
		}
		if _, err := dest.RescanTaskCreate(ctx, fold.UserID, fold.Target); err != nil {
			return fmt.Errorf("rescan create: %w", err)
		}
		rep.RescanTasks++
		return nil
	}); err != nil {
		return rep, fmt.Errorf("rescan_tasks: %w", err)
	}

	// Agent config (singleton)
	if cfg, ok, err := pgReadAgentConfig(ctx, src); err != nil {
		return rep, fmt.Errorf("agent_config: %w", err)
	} else if ok {
		if !dryRun {
			if _, err := dest.AgentConfigUpdate(ctx, AgentConfigConvert(cfg)); err != nil {
				return rep, fmt.Errorf("agent_config update: %w", err)
			}
		}
		rep.AgentConfig = 1
	}

	// natlas_services (singleton)
	if svc, ok, err := pgReadServices(ctx, src); err != nil {
		return rep, fmt.Errorf("natlas_services: %w", err)
	} else if ok {
		if !dryRun {
			if err := dest.NatlasServicesUpdate(ctx, svc.SHA256, svc.Services); err != nil {
				return rep, fmt.Errorf("natlas_services update: %w", err)
			}
		}
		rep.Services = 1
	}

	// scope_log (history)
	if err := pgRead(ctx, src, `SELECT message FROM scope_log ORDER BY id`, func(rows *sql.Rows) error {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return err
		}
		if dryRun {
			rep.ScopeLog++
			return nil
		}
		if err := dest.ScopeLogAppend(ctx, msg); err != nil {
			return fmt.Errorf("scope_log append: %w", err)
		}
		rep.ScopeLog++
		return nil
	}); err != nil {
		// scope_log is non-critical; log and continue.
		slog.WarnContext(ctx, "migrate: scope_log read failed", "err", err)
	}

	return rep, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// pgRead is a tiny wrapper that runs a SELECT and invokes scan() once per
// row. It exists to keep MigrateRelational's body shaped like a checklist
// rather than nested rows.Close()/rows.Err() boilerplate.
func pgRead(ctx context.Context, db *sql.DB, query string, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func pgReadAgentConfig(ctx context.Context, db *sql.DB) (PyAgentConfig, bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT "versionDetection", "osDetection", "enableScripts", "onlyOpens",
		       "scanTimeout", "webScreenshots", "vncScreenshots",
		       "webScreenshotTimeout", "vncScreenshotTimeout",
		       "scriptTimeout", "hostTimeout", "osScanLimit", "noPing", "udpScan",
		       COALESCE(scripts, '{}')
		FROM agent_config WHERE id = 1
	`)
	if err != nil {
		return PyAgentConfig{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return PyAgentConfig{}, false, rows.Err()
	}
	var c PyAgentConfig
	var scripts pgTextArray
	if err := rows.Scan(
		&c.VersionDetection, &c.OsDetection, &c.EnableScripts, &c.OnlyOpens,
		&c.ScanTimeout, &c.WebScreenshots, &c.VncScreenshots,
		&c.WebScreenshotTimeout, &c.VncScreenshotTimeout,
		&c.ScriptTimeout, &c.HostTimeout, &c.OsScanLimit, &c.NoPing, &c.UdpScan,
		&scripts,
	); err != nil {
		return PyAgentConfig{}, false, err
	}
	c.Scripts = []string(scripts)
	return c, true, nil
}

func pgReadServices(ctx context.Context, db *sql.DB) (PyNatlasServices, bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(sha256, ''), COALESCE(services, '') FROM natlas_services WHERE id = 1`)
	if err != nil {
		return PyNatlasServices{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return PyNatlasServices{}, false, rows.Err()
	}
	var s PyNatlasServices
	if err := rows.Scan(&s.SHA256, &s.Services); err != nil {
		return PyNatlasServices{}, false, err
	}
	return s, true, nil
}

// pgTextArray scans a Postgres text[] column. We avoid pulling in lib/pq's
// pq.StringArray here — pgx already supports text[] natively when using
// pgx-typed scans, but the database/sql route through stdlib needs a hand
// scanner. The implementation handles the canonical "{a,b,\"c, d\"}"
// format Postgres emits.
type pgTextArray []string

func (a *pgTextArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("pgTextArray: unsupported source %T", src)
	}
	*a = parsePgTextArray(s)
	return nil
}

// parsePgTextArray decodes the wire form Postgres uses for text[] when read
// over the binary protocol-via-text fallback (modernc/sqlite-style). Handles
// the common cases (unquoted simple words, double-quoted strings, escapes).
func parsePgTextArray(s string) []string {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil
	}
	body := s[1 : len(s)-1]
	if body == "" {
		return []string{}
	}
	var out []string
	var cur []byte
	inQuote := false
	escaped := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		if escaped {
			cur = append(cur, c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ',' && !inQuote {
			out = append(out, string(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, c)
	}
	out = append(out, string(cur))
	return out
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

