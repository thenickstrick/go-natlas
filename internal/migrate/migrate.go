package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

// Options is the top-level configuration for migrate-from-py. Fields are a
// flattening of the relational + search migrators so the cobra command can
// stitch them together with a single struct.
type Options struct {
	// Source Postgres URL (Python natlas DB). When empty, the relational
	// migration is skipped entirely.
	SrcPostgresURL string

	// Source Elasticsearch URL + auth (Python natlas search). When empty, the
	// search migration is skipped entirely.
	SrcElasticURL      string
	SrcElasticUser     string
	SrcElasticPassword string
	SrcElasticInsecure bool

	// Destination — provided by the caller as already-open clients so the
	// cobra subcommand can reuse the same Store + OpenSearch endpoints the
	// rest of natlas-admin uses.
	DestStore     data.Store
	DestOpenSURL  string
	DestOpenSUser string
	DestOpenSPass string
	DestOpenSInsecure bool

	// BatchSize for ES scrolls (default 500 if 0).
	BatchSize int

	// DryRun reads + transforms but skips writes on both sides.
	DryRun bool
}

// Report combines the per-pipeline counts.
type Report struct {
	Relational RelationalReport
	Search     SearchReport
}

// Run executes both pipelines (relational + search). Either can be skipped
// by leaving its source URL empty. Errors from one pipeline don't stop the
// other — the caller gets back whatever counts were achieved before the
// failure plus the error itself.
func Run(ctx context.Context, opts Options) (Report, error) {
	var (
		rep  Report
		errs []error
	)

	if opts.SrcPostgresURL != "" {
		if opts.DestStore == nil {
			return rep, errors.New("migrate: DestStore required when SrcPostgresURL set")
		}
		slog.InfoContext(ctx, "migrate: relational pipeline starting", "dry_run", opts.DryRun)
		r, err := MigrateRelational(ctx, opts.SrcPostgresURL, opts.DestStore, opts.DryRun)
		rep.Relational = r
		if err != nil {
			errs = append(errs, fmt.Errorf("relational: %w", err))
		} else {
			slog.InfoContext(ctx, "migrate: relational pipeline finished", "report", r)
		}
	}

	if opts.SrcElasticURL != "" {
		if opts.DestOpenSURL == "" {
			return rep, errors.New("migrate: DestOpenSURL required when SrcElasticURL set")
		}
		slog.InfoContext(ctx, "migrate: search pipeline starting", "dry_run", opts.DryRun)
		s, err := MigrateSearch(ctx, SearchOptions{
			SourceURL:      opts.SrcElasticURL,
			SourceUser:     opts.SrcElasticUser,
			SourcePassword: opts.SrcElasticPassword,
			SourceInsecure: opts.SrcElasticInsecure,
			DestURL:        opts.DestOpenSURL,
			DestUser:       opts.DestOpenSUser,
			DestPassword:   opts.DestOpenSPass,
			DestInsecure:   opts.DestOpenSInsecure,
			BatchSize:      opts.BatchSize,
		}, opts.DryRun)
		rep.Search = s
		if err != nil {
			errs = append(errs, fmt.Errorf("search: %w", err))
		} else {
			slog.InfoContext(ctx, "migrate: search pipeline finished", "report", s)
		}
	}

	if len(errs) > 0 {
		return rep, errors.Join(errs...)
	}
	return rep, nil
}
