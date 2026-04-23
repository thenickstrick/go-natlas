// natlas-admin is the operator CLI for the natlas control plane. It subsumes
// the scattered Flask CLI + shell helpers of the Python deployment.
//
// Phase 1 stub: only `version` is implemented; all other subcommands are wired
// in later phases (user/agent/scope/services/migrate-from-py).
package main

import (
	"fmt"
	"os"
)

var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("natlas-admin %s\n", Version)
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "natlas-admin: unknown subcommand %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `natlas-admin — operator CLI for the natlas control plane

Usage:
  natlas-admin <command> [flags]

Commands (planned):
  user      create|invite|promote|delete
  agent     create|rotate-token|rename|delete
  scope     import|export|add|remove|blacklist
  services  upload <file>
  migrate-from-py --pg-url ... --os-url ... --out-pg ... --out-os ...
  version`)
}
