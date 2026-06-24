package main

import (
	"fmt"
	"time"

	"github.com/IvanShishkin/houndoom/internal/engagement"
	"github.com/spf13/cobra"
)

// engagementsCmd manages stored engagement output directories.
func engagementsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engagements",
		Short: "Manage stored scan engagement outputs",
	}
	cmd.AddCommand(engagementsPurgeCmd())
	return cmd
}

func engagementsPurgeCmd() *cobra.Command {
	var olderThan time.Duration
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete engagement outputs older than a retention window",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := engagement.DefaultRoot()
			if err != nil {
				return err
			}
			removed, err := engagement.Purge(root, olderThan, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("Purged %d engagement(s) older than %s\n", len(removed), olderThan)
			for _, p := range removed {
				fmt.Printf("  removed %s\n", p)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&olderThan, "older-than", 30*24*time.Hour, "Retention window (e.g. 720h for 30 days)")
	return cmd
}
