package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/thenickstrick/go-natlas/internal/migrate"
)

func newMigrateCmd(env *adminEnv) *cobra.Command {
	var opts migrate.Options
	cmd := &cobra.Command{
		Use:   "migrate-from-py",
		Short: "Import a Python natlas deployment into the Go control plane",
		Long: `Read a running Python natlas deployment (PostgreSQL + Elasticsearch 7.17)
and write its data into the Go destination (PostgreSQL or SQLite + OpenSearch).

Either pipeline can be skipped by leaving its source URL empty. Re-running is
safe: relational rows skip on natural-key conflicts, and search docs PUT by
deterministic ID so they overwrite cleanly.

NOTE: agent tokens are bcrypt-hashed during migration. Existing deployed
agents continue to authenticate with their existing plaintext tokens; if you
want fresh tokens, run "natlas-admin agent rotate-token <id>" afterwards.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			opts.DestStore = store
			rep, err := migrate.Run(cmd.Context(), opts)
			printReport(cmd, rep)
			return err
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.SrcPostgresURL, "src-pg-url", "", "Source Python natlas Postgres URL (postgres://user:pass@host/db)")
	f.StringVar(&opts.SrcElasticURL, "src-es-url", "", "Source Elasticsearch URL (http(s)://host:9200)")
	f.StringVar(&opts.SrcElasticUser, "src-es-user", "", "Source Elasticsearch basic-auth user")
	f.StringVar(&opts.SrcElasticPassword, "src-es-password", "", "Source Elasticsearch basic-auth password")
	f.BoolVar(&opts.SrcElasticInsecure, "src-es-insecure-tls", false, "Skip TLS verification on the source Elasticsearch")
	f.StringVar(&opts.DestOpenSURL, "dest-os-url", "", "Destination OpenSearch URL")
	f.StringVar(&opts.DestOpenSUser, "dest-os-user", "", "Destination OpenSearch basic-auth user")
	f.StringVar(&opts.DestOpenSPass, "dest-os-password", "", "Destination OpenSearch basic-auth password")
	f.BoolVar(&opts.DestOpenSInsecure, "dest-os-insecure-tls", false, "Skip TLS verification on the destination OpenSearch")
	f.IntVar(&opts.BatchSize, "batch-size", 500, "Bulk batch size for ES → OpenSearch reindex")
	f.BoolVar(&opts.DryRun, "dry-run", false, "Read + transform but write nothing on either side")

	return cmd
}

func printReport(cmd *cobra.Command, rep migrate.Report) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Migration report:")
	fmt.Fprintln(w, "  Relational")
	fmt.Fprintf(w, "    users:           %d\n", rep.Relational.Users)
	fmt.Fprintf(w, "    agents:          %d\n", rep.Relational.Agents)
	fmt.Fprintf(w, "    scope_items:     %d\n", rep.Relational.ScopeItems)
	fmt.Fprintf(w, "    rescan_tasks:    %d\n", rep.Relational.RescanTasks)
	fmt.Fprintf(w, "    agent_config:    %d\n", rep.Relational.AgentConfig)
	fmt.Fprintf(w, "    natlas_services: %d\n", rep.Relational.Services)
	fmt.Fprintf(w, "    scope_log:       %d\n", rep.Relational.ScopeLog)
	fmt.Fprintln(w, "  Search")
	fmt.Fprintf(w, "    nmap (latest):   %d\n", rep.Search.Latest)
	fmt.Fprintf(w, "    nmap_history:    %d\n", rep.Search.History)
}
