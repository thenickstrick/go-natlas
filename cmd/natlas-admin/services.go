package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newServicesCmd(env *adminEnv) *cobra.Command {
	services := &cobra.Command{
		Use:   "services",
		Short: "Manage the custom nmap services database distributed to agents",
	}
	services.AddCommand(newServicesUploadCmd(env))
	services.AddCommand(newServicesShowCmd(env))
	return services
}

func newServicesUploadCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "upload <file>",
		Short: "Replace the natlas_services blob with the contents of <file>",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			sum := sha256.Sum256(body)
			hash := hex.EncodeToString(sum[:])
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			if err := store.NatlasServicesUpdate(cmd.Context(), hash, string(body)); err != nil {
				return fmt.Errorf("update services: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Uploaded %d bytes (sha256=%s)\n", len(body), hash)
			fmt.Fprintln(cmd.OutOrStdout(), "Agents will pick up the new file the next time their cached hash drifts.")
			return nil
		},
	}
}

func newServicesShowCmd(env *adminEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the currently-distributed services blob and its sha256",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := env.openStore(cmd.Context())
			if err != nil {
				return err
			}
			s, err := store.NatlasServicesGet(cmd.Context())
			if err != nil {
				return fmt.Errorf("get services: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "sha256=%s updated_at=%s bytes=%d\n",
				s.SHA256, s.UpdatedAt.Format("2006-01-02 15:04:05 UTC"), len(s.Services))
			fmt.Fprint(cmd.OutOrStdout(), s.Services)
			return nil
		},
	}
}
