package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

func newAgentCmd(env *adminEnv) *cobra.Command {
	agent := &cobra.Command{
		Use:   "agent",
		Short: "Manage scan agents",
	}
	agent.AddCommand(
		newAgentCreateCmd(env),
		newAgentListCmd(env),
		newAgentRotateTokenCmd(env),
		newAgentRenameCmd(env),
		newAgentDeleteCmd(env),
	)
	return agent
}

func newAgentCreateCmd(env *adminEnv) *cobra.Command {
	var friendly string
	cmd := &cobra.Command{
		Use:   "create <owner-email>",
		Short: "Register a new agent owned by a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			owner, err := store.UserGetByEmail(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup owner: %w", err)
			}
			id, token, err := generateAgentCredentials()
			if err != nil {
				return fmt.Errorf("generate credentials: %w", err)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash token: %w", err)
			}
			a, err := store.AgentCreate(cmd.Context(), data.AgentCreateParams{
				UserID:       owner.ID,
				AgentID:      id,
				TokenHash:    string(hash),
				FriendlyName: friendly,
			})
			if err != nil {
				return fmt.Errorf("create agent: %w", err)
			}
			printAgentCredentials(cmd, a, token)
			return nil
		},
	}
	cmd.Flags().StringVarP(&friendly, "name", "n", "", "Friendly name (free-form)")
	return cmd
}

func newAgentRotateTokenCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-token <agent_id>",
		Short: "Mint a fresh bearer token for an existing agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			a, err := store.AgentGetByAgentID(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup agent: %w", err)
			}
			token, err := generateAgentToken()
			if err != nil {
				return fmt.Errorf("generate token: %w", err)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash token: %w", err)
			}
			if err := store.AgentSetTokenHash(cmd.Context(), a.ID, string(hash)); err != nil {
				return fmt.Errorf("update token: %w", err)
			}
			a.TokenHash = string(hash)
			printAgentCredentials(cmd, a, token)
			return nil
		},
	}
}

func newAgentRenameCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <agent_id> <name>",
		Short: "Update an agent's friendly name",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			a, err := store.AgentGetByAgentID(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup agent: %w", err)
			}
			if err := store.AgentSetFriendlyName(cmd.Context(), a.ID, args[1]); err != nil {
				return fmt.Errorf("rename: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s renamed to %q\n", a.AgentID, args[1])
			return nil
		},
	}
}

func newAgentDeleteCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <agent_id>",
		Short: "Remove an agent (token immediately invalidated)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			a, err := store.AgentGetByAgentID(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup agent: %w", err)
			}
			if err := store.AgentDelete(cmd.Context(), a.ID); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted agent %s\n", a.AgentID)
			return nil
		},
	}
}

func newAgentListCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered agents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			agents, err := store.AgentListAll(cmd.Context())
			if err != nil {
				return fmt.Errorf("list agents: %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "AGENT_ID\tOWNER_USER_ID\tNAME\tCREATED\tLAST_SEEN")
			for _, a := range agents {
				lastSeen := "-"
				if a.LastSeenAt != nil {
					lastSeen = a.LastSeenAt.Format("2006-01-02 15:04")
				}
				name := a.FriendlyName
				if name == "" {
					name = "-"
				}
				fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n",
					a.AgentID, a.UserID, name, a.CreatedAt.Format("2006-01-02"), lastSeen)
			}
			return tw.Flush()
		},
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// generateAgentCredentials mints a fresh agent_id + token pair. agent_id is
// 16 hex chars (8 random bytes); token is 39 base32 chars (24 random bytes,
// no padding) — high enough entropy that bcrypt-hashing it is safe and the
// dot-separated bearer header is operator-paste-friendly.
func generateAgentCredentials() (id string, token string, err error) {
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", "", err
	}
	token, err = generateAgentToken()
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(idBytes[:]), token, nil
}

func generateAgentToken() (string, error) {
	var tokBytes [24]byte
	if _, err := rand.Read(tokBytes[:]); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	tok := enc.EncodeToString(tokBytes[:])
	tok = strings.ToLower(tok)
	if strings.ContainsRune(tok, '.') {
		// base32 alphabet excludes ".", but defense-in-depth: the bearer
		// header parser splits on the first dot so a token containing one
		// would be misread. crypto/rand never makes this happen, but if it
		// somehow did we'd rather error than silently break auth.
		return "", errors.New("generated token contained '.' — refusing")
	}
	return tok, nil
}

func printAgentCredentials(cmd *cobra.Command, a data.Agent, plaintextToken string) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Agent credentials minted. Save them NOW; the token cannot be retrieved later.")
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintf(w, "  Agent DB ID : %d\n", a.ID)
	fmt.Fprintf(w, "  Agent ID    : %s\n", a.AgentID)
	fmt.Fprintf(w, "  Token       : %s\n", plaintextToken)
	fmt.Fprintf(w, "  Bearer      : %s.%s\n", a.AgentID, plaintextToken)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintln(w, "Configure the agent with:")
	fmt.Fprintf(w, "  NATLAS_AGENT_ID=%s\n", a.AgentID)
	fmt.Fprintf(w, "  NATLAS_AGENT_TOKEN=%s\n", plaintextToken)
}

// keep strconv referenced for future agent-id-by-int lookups.
var _ = strconv.Atoi
