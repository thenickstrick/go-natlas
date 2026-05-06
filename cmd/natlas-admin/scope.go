package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

func newScopeCmd(env *adminEnv) *cobra.Command {
	scope := &cobra.Command{
		Use:   "scope",
		Short: "Manage scope and blacklist (server restart needed for hot pickup)",
		Long: `Manage scope and blacklist entries.

Scope mutations made via this CLI take effect when the natlas-server reloads
its in-memory ScopeManager — that is, on next process restart. Use the web
/admin/scope page if you need hot reload.`,
	}
	scope.AddCommand(
		newScopeAddCmd(env, false),
		newScopeAddCmd(env, true),
		newScopeRemoveCmd(env),
		newScopeListCmd(env),
		newScopeImportCmd(env),
		newScopeExportCmd(env),
	)
	return scope
}

// newScopeAddCmd builds either "add" (whitelist) or "blacklist" depending
// on the flag. They share an implementation.
func newScopeAddCmd(env *adminEnv, blacklist bool) *cobra.Command {
	verb := "add"
	desc := "Add a CIDR to the scan whitelist"
	if blacklist {
		verb = "blacklist"
		desc = "Add a CIDR to the blacklist"
	}
	return &cobra.Command{
		Use:   verb + " <cidr>",
		Short: desc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			item, err := addScopeItem(cmd.Context(), store, args[0], blacklist)
			if err != nil {
				return err
			}
			label := "scope"
			if blacklist {
				label = "blacklist"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added %s entry %s (id=%d)\n", label, item.CIDR, item.ID)
			return nil
		},
	}
}

func newScopeRemoveCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <cidr>",
		Short: "Remove a scope or blacklist entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			prefix, err := netip.ParsePrefix(args[0])
			if err != nil {
				return fmt.Errorf("parse cidr: %w", err)
			}
			prefix = prefix.Masked()
			items, err := store.ScopeItemListAll(cmd.Context())
			if err != nil {
				return fmt.Errorf("list scope: %w", err)
			}
			matches := 0
			for _, it := range items {
				if it.CIDR == prefix {
					if err := store.ScopeItemDelete(cmd.Context(), it.ID); err != nil {
						return fmt.Errorf("delete %d: %w", it.ID, err)
					}
					matches++
				}
			}
			if matches == 0 {
				return fmt.Errorf("no scope entry matches %s", prefix)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %d scope entry/entries for %s\n", matches, prefix)
			return nil
		},
	}
}

func newScopeListCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List scope + blacklist entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			items, err := store.ScopeItemListAll(cmd.Context())
			if err != nil {
				return fmt.Errorf("list scope: %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tCIDR\tROLE\tCREATED")
			for _, it := range items {
				role := "scope"
				if it.IsBlacklist {
					role = "blacklist"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n",
					it.ID, it.CIDR, role, it.CreatedAt.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}
}

func newScopeImportCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import scope entries from a CSV (cidr[,blacklist[,tag1,tag2,...]])",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rows, err := readScopeCSV(args[0])
			if err != nil {
				return err
			}
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			created, skipped := 0, 0
			for _, row := range rows {
				if _, err := addScopeItem(cmd.Context(), store, row.CIDR, row.Blacklist); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "skip %s: %v\n", row.CIDR, err)
					skipped++
					continue
				}
				created++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Imported %d entries (%d skipped)\n", created, skipped)
			return nil
		},
	}
}

func newScopeExportCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export scope entries as CSV to stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			items, err := store.ScopeItemListAll(cmd.Context())
			if err != nil {
				return fmt.Errorf("list scope: %w", err)
			}
			w := csv.NewWriter(cmd.OutOrStdout())
			defer w.Flush()
			for _, it := range items {
				blk := "0"
				if it.IsBlacklist {
					blk = "1"
				}
				if err := w.Write([]string{it.CIDR.String(), blk}); err != nil {
					return err
				}
			}
			return w.Error()
		},
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// addScopeItem normalizes a CIDR + writes the row. ON CONFLICT DO UPDATE in
// the underlying SQL means re-importing the same prefix is idempotent.
func addScopeItem(ctx context.Context, store data.Store, cidrStr string, blacklist bool) (data.ScopeItem, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidrStr))
	if err != nil {
		return data.ScopeItem{}, fmt.Errorf("parse cidr %q: %w", cidrStr, err)
	}
	prefix = prefix.Masked()
	start := prefix.Addr()
	stop := lastAddrInPrefix(prefix)
	return store.ScopeItemCreate(ctx, data.ScopeItemCreateParams{
		CIDR:        prefix,
		IsBlacklist: blacklist,
		StartAddr:   start,
		StopAddr:    stop,
	})
}

// scopeRow is the parsed shape of a single line in the import CSV. Tags are
// captured but not yet persisted — Phase 7 reserved scope_item_tags for the
// follow-up admin UI; the CLI passes them through as a placeholder.
type scopeRow struct {
	CIDR      string
	Blacklist bool
	Tags      []string
}

// readScopeCSV parses cidr[,blacklist[,tag,...]] lines. Blank lines and
// lines starting with '#' are ignored.
func readScopeCSV(path string) ([]scopeRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return parseScopeCSV(f)
}

func parseScopeCSV(r io.Reader) ([]scopeRow, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var rows []scopeRow
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		row := scopeRow{CIDR: strings.TrimSpace(parts[0])}
		if row.CIDR == "" {
			return nil, fmt.Errorf("line %d: empty cidr", lineNo)
		}
		if len(parts) > 1 {
			b, err := strconv.ParseBool(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("line %d: blacklist column not bool-like: %w", lineNo, err)
			}
			row.Blacklist = b
		}
		if len(parts) > 2 {
			for _, t := range parts[2:] {
				t = strings.TrimSpace(t)
				if t != "" {
					row.Tags = append(row.Tags, t)
				}
			}
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("no scope rows found")
	}
	return rows, nil
}

// lastAddrInPrefix returns the highest address contained in a prefix. v4 fast
// path uses uint32; v6 walks 16 bytes flipping host bits.
func lastAddrInPrefix(p netip.Prefix) netip.Addr {
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
