package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

func newUserCmd(env *adminEnv) *cobra.Command {
	user := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}
	user.AddCommand(
		newUserCreateCmd(env),
		newUserListCmd(env),
		newUserPromoteCmd(env, true),
		newUserPromoteCmd(env, false),
		newUserDeleteCmd(env),
	)
	return user
}

func newUserCreateCmd(env *adminEnv) *cobra.Command {
	var asAdmin bool
	cmd := &cobra.Command{
		Use:   "create <email>",
		Short: "Create a user (prompts for password)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			email := strings.TrimSpace(args[0])
			if email == "" {
				return errors.New("email must not be empty")
			}
			pwd, err := promptPassword("Password: ")
			if err != nil {
				return err
			}
			confirm, err := promptPassword("Confirm:  ")
			if err != nil {
				return err
			}
			if pwd != confirm {
				return errors.New("passwords do not match")
			}
			if len(pwd) < 8 {
				return errors.New("password must be at least 8 characters")
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			u, err := store.UserCreate(cmd.Context(), data.UserCreateParams{
				Email:        email,
				PasswordHash: string(hash),
				IsAdmin:      asAdmin,
				IsActive:     true,
			})
			if err != nil {
				return fmt.Errorf("create user: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "User created: id=%d email=%s admin=%t active=%t\n",
				u.ID, u.Email, u.IsAdmin, u.IsActive)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asAdmin, "admin", false, "Grant administrator privileges")
	return cmd
}

func newUserListCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			users, err := store.UserList(cmd.Context(), 1000, 0)
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tEMAIL\tADMIN\tACTIVE\tCREATED")
			for _, u := range users {
				fmt.Fprintf(tw, "%d\t%s\t%t\t%t\t%s\n",
					u.ID, u.Email, u.IsAdmin, u.IsActive, u.CreatedAt.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}
}

// newUserPromoteCmd builds either "promote" or "demote" depending on the
// flag. Sharing the body keeps the two flows from drifting.
func newUserPromoteCmd(env *adminEnv, promote bool) *cobra.Command {
	verb := "promote"
	desc := "Grant admin privileges to a user"
	if !promote {
		verb = "demote"
		desc = "Revoke admin privileges from a user"
	}
	return &cobra.Command{
		Use:   verb + " <email>",
		Short: desc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			u, err := store.UserGetByEmail(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup user: %w", err)
			}
			if err := store.UserSetAdmin(cmd.Context(), u.ID, promote); err != nil {
				return fmt.Errorf("set admin: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: admin=%t\n", u.Email, promote)
			return nil
		},
	}
}

func newUserDeleteCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <email>",
		Short: "Delete a user (and all owned agents/rescans via cascade)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			u, err := store.UserGetByEmail(cmd.Context(), strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("lookup user: %w", err)
			}
			if err := store.UserDelete(cmd.Context(), u.ID); err != nil {
				return fmt.Errorf("delete user: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted user %s (id=%d)\n", u.Email, u.ID)
			return nil
		},
	}
}

// promptPassword reads from /dev/tty (or the controlling terminal) without
// echoing characters. Falls back to plain stdin when the process isn't
// attached to a TTY (e.g. CI piping a password in) — that path is the
// caller's responsibility to rate-limit.
func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive: read a single line.
		var s string
		_, err := fmt.Fscanln(os.Stdin, &s)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return s, nil
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// suppress unused-import warning when the file is included alone.
var _ = context.Background
