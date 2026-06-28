package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/engagement"
	"github.com/IvanShishkin/houndoom/internal/remote"
	"github.com/IvanShishkin/houndoom/internal/remote/binaries"
	"github.com/IvanShishkin/houndoom/internal/report"
	"github.com/spf13/cobra"
)

// remoteScanCmd runs a recon-only scan against a remote target over SSH.
func remoteScanCmd() *cobra.Command {
	var (
		host    string
		path    string
		mode    string
		output  string
		plan    bool
		yes     bool
		timeout time.Duration
		maxSize string
	)

	cmd := &cobra.Command{
		Use:   "remote-scan",
		Short: "Recon-only scan of a remote host over SSH (agentless)",
		Long: `Deliver the scanner to a remote host over SSH (keys via ssh-agent),
run a read-only scan, and collect the JSON report to a per-engagement directory.

Authorization is by SSH key possession; there is no in-app allowlist. SSH key
material is never read by this command directly — it is provided by ssh-agent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := remote.Options{Host: host, Path: path, Mode: mode, Plan: plan, Timeout: timeout, MaxSize: maxSize}

			// Resolve output path: explicit --output overrides the per-engagement dir.
			if !plan {
				resolved, err := resolveOutput(output, host)
				if err != nil {
					return err
				}
				opts.Output = resolved.reportPath

				operator := os.Getenv("USER")
				if operator == "" {
					if u, uerr := user.Current(); uerr == nil && u.Username != "" {
						operator = u.Username
					} else {
						operator = "unknown"
					}
				}
				auditFile, err := os.OpenFile(resolved.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					return err
				}
				defer auditFile.Close()

				deps := remote.Deps{
					Connect:  remote.NewSSHConnector(),
					Binaries: binaries.FS,
					Audit:    remote.NewAuditLog(auditFile, operator, host),
					Confirm:  func(target string) bool { return yes || confirmTarget(target) },
					Now:      time.Now,
				}
				reportPath, err := remote.Run(context.Background(), opts, deps)
				if err != nil {
					return err
				}
				fmt.Printf("Report: %s\n", reportPath)

				// Render a standalone HTML view locally, next to the JSON report.
				// This is a local post-processing step; the target is never touched.
				htmlPath := strings.TrimSuffix(reportPath, filepath.Ext(reportPath)) + ".html"
				if rerr := report.RenderHTMLFromJSON(reportPath, htmlPath); rerr != nil {
					fmt.Fprintf(os.Stderr, "warning: HTML report generation failed: %v\n", rerr)
				} else {
					fmt.Printf("HTML Report: %s\n", htmlPath)
				}
				return nil
			}

			// Plan mode: no output, no connection.
			_, err := remote.Run(context.Background(), opts, remote.Deps{})
			return err
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Target in user@host form (required)")
	cmd.Flags().StringVar(&path, "path", "", "Absolute path on the target to scan (required)")
	cmd.Flags().StringVar(&mode, "mode", "normal", "Scan mode: fast, normal, paranoid")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Optional report path override (default: per-engagement directory)")
	cmd.Flags().BoolVar(&plan, "plan", false, "Print the execution plan without connecting")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation gate")
	cmd.Flags().DurationVar(&timeout, "timeout", 1*time.Hour, "Wall-clock limit for the remote scan process (passed to timeout(1))")
	cmd.Flags().StringVar(&maxSize, "max-size", "", "Optional max file size to scan (e.g. 500M); passed through to the remote scanner")
	_ = cmd.MarkFlagRequired("host")
	return cmd
}

type resolvedOutput struct {
	reportPath string
	auditPath  string
}

// resolveOutput creates the per-engagement directory and returns report/audit paths.
// An explicit --output overrides only the report path; the audit log still lands
// in the engagement directory.
func resolveOutput(output, host string) (resolvedOutput, error) {
	root, err := engagement.DefaultRoot()
	if err != nil {
		return resolvedOutput{}, err
	}
	dir, err := engagement.Create(root, host, time.Now())
	if err != nil {
		return resolvedOutput{}, err
	}
	reportPath := filepath.Join(dir, "report.json")
	if output != "" {
		reportPath = output
	}
	return resolvedOutput{reportPath: reportPath, auditPath: filepath.Join(dir, "audit.log")}, nil
}

// confirmTarget prints the exact target and asks for explicit confirmation.
func confirmTarget(target string) bool {
	fmt.Printf("\n  About to connect for a recon-only scan:\n  %s\n", target)
	fmt.Printf("  Proceed? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}
