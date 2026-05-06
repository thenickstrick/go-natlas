// natlas is the operator entry point for the dev compose stack and the
// in-cluster admin CLI. It is a thin wrapper around `docker compose` and
// `docker compose exec server /natlas-admin` so day-to-day commands collapse
// to a single short verb:
//
//	natlas up                 # build + start the stack
//	natlas rebuild            # rebuild + recreate server + agent (inner loop)
//	natlas rebuild server     # rebuild + recreate one service
//	natlas logs               # tail everything
//	natlas logs server        # tail one service
//	natlas ps                 # container state
//	natlas down               # stop (volumes preserved)
//	natlas nuke               # stop + delete every named volume
//	natlas restart server     # restart one service (no rebuild)
//	natlas psql               # interactive psql against the dev DB
//	natlas admin user list    # forward to the in-cluster natlas-admin
//	natlas admin scope add 10.0.0.0/24
//	natlas version            # this binary's version
//
// The binary searches up from the current working directory for
// deploy/docker-compose.yml so it can be invoked from any subdirectory of
// the repo. It does not need natlas-server / natlas-agent to be running —
// every subcommand is a stateless shell-out.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "natlas:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "natlas",
		Short:         "Operator entry point for the natlas dev stack",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		upCmd(),
		downCmd(),
		nukeCmd(),
		logsCmd(),
		psCmd(),
		restartCmd(),
		buildCmd(),
		rebuildCmd(),
		psqlCmd(),
		adminCmd(),
		versionCmd(),
	)
	return root
}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

func upCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Build images + start the dev stack in the background",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return docker(composeArgs("up", "-d", "--build")...)
		},
	}
}

func downCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Stop the dev stack (volumes preserved)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return docker(composeArgs("down")...)
		},
	}
}

func nukeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "nuke",
		Short: "Stop the stack AND delete every named volume",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return docker(composeArgs("down", "-v")...)
		},
	}
}

func logsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logs [service...]",
		Short: "Tail logs for the stack (or specific services)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			return docker(composeArgs(append([]string{"logs", "-f"}, args...)...)...)
		},
	}
}

func psCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List dev stack containers",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return docker(composeArgs("ps")...)
		},
	}
}

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart [service...]",
		Short: "Restart one or more services (default: server + agent)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"server", "agent"}
			}
			return docker(composeArgs(append([]string{"restart"}, args...)...)...)
		},
	}
}

func buildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "build [service...]",
		Short: "Rebuild images without starting (default: server + agent)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"server", "agent"}
			}
			return docker(composeArgs(append([]string{"build"}, args...)...)...)
		},
	}
}

// rebuildCmd is the inner-loop verb for "I changed Go code, give me the new
// version running". Combines `--build` (rebuild the image) and
// `--force-recreate` (recreate the container even when compose config is
// unchanged) in one shot. Defaults to server + agent — both depend on the
// repo source — but accepts explicit service names to narrow the rebuild
// when only one side changed.
func rebuildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild [service...]",
		Short: "Rebuild images and recreate containers (default: server + agent)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"server", "agent"}
			}
			return docker(composeArgs(append(
				[]string{"up", "-d", "--build", "--force-recreate"},
				args...,
			)...)...)
		},
	}
}

// -----------------------------------------------------------------------------
// Convenience: psql shell into the dev Postgres
// -----------------------------------------------------------------------------

func psqlCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "psql",
		Short: "Interactive psql shell against the dev Postgres",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return docker(composeArgs(
				"exec", "postgres",
				"psql", "-U", "natlas", "-d", "natlas",
			)...)
		},
	}
}

// -----------------------------------------------------------------------------
// admin: pass-through to /natlas-admin inside the server container
// -----------------------------------------------------------------------------

func adminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "admin [args...]",
		Short:              "Run a natlas-admin subcommand inside the server container",
		Long: `Forwards every argument to /natlas-admin running inside the live server
container. The server image bundles natlas-admin so this works without a
local Go toolchain.

Examples:
  natlas admin version
  natlas admin user list
  natlas admin user create --admin you@example.com
  natlas admin scope add 10.0.0.0/24
  natlas admin agent create --name primary you@example.com`,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return docker(composeArgs(append(
				[]string{"exec", "server", "/natlas-admin"},
				args...,
			)...)...)
		},
	}
	return cmd
}

// -----------------------------------------------------------------------------
// version
// -----------------------------------------------------------------------------

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print this CLI's version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "natlas %s\n", Version)
		},
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// composeArgs prepends the compose file path so every subcommand reaches the
// same stack regardless of where the user invoked natlas from.
func composeArgs(rest ...string) []string {
	out := []string{"compose", "-f", findComposeFile()}
	return append(out, rest...)
}

// findComposeFile walks up from the current working directory looking for
// deploy/docker-compose.yml so `natlas` works from any subdirectory of the
// repo. Falls back to a relative path if nothing is found — docker compose
// will then fail with its own clear error.
func findComposeFile() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "deploy/docker-compose.yml"
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "deploy", "docker-compose.yml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "deploy/docker-compose.yml"
		}
		dir = parent
	}
}

// docker runs the docker CLI with the given args, wiring stdio through so
// `natlas logs -f` streams in real time and `natlas psql` is interactive.
func docker(args ...string) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker CLI not found in PATH: %w", err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
