package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/internal/core"
	"github.com/IvanShishkin/houndoom/internal/deobfuscator"
	deobfPHP "github.com/IvanShishkin/houndoom/internal/deobfuscator/php"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ANSI colors
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorOrange = "\033[38;5;208m"
	colorYellow = "\033[38;5;220m"
	colorGray   = "\033[38;5;245m"
	colorCyan   = "\033[36m"
)


var (
	version = "0.0.1"
	logger  *zap.Logger
	verbose bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "houndoom",
		Short: "Houndoom - Advanced Security Scanner for Web Applications",
		Long: `High-performance security scanner for detecting malicious code, backdoors,
web shells, and vulnerabilities in web applications.`,
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			printMainBanner()
			cmd.Help()
		},
	}

	// Global verbose flag
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	// Disable built-in help command
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	// Add commands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(deobCmd())
	rootCmd.AddCommand(detectorsCmd())
	rootCmd.AddCommand(helpCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// printMainBanner prints the main banner
func printMainBanner() {
	fmt.Println()
	fmt.Printf("%s", colorOrange)
	fmt.Println("██  ██ ▄████▄ ██  ██ ███  ██ ████▄  ▄████▄ ▄████▄ ██▄  ▄██")
	fmt.Println("██████ ██  ██ ██  ██ ██ ▀▄██ ██  ██ ██  ██ ██  ██ ██ ▀▀ ██")
	fmt.Println("██  ██ ▀████▀ ▀████▀ ██   ██ ████▀  ▀████▀ ▀████▀ ██    ██")
	fmt.Printf("%s", colorReset)
	fmt.Println()
	fmt.Printf("%sSecurity Scanner v%s%s\n", colorGray, version, colorReset)
	fmt.Println()
}

// scanCmd creates the scan command
func scanCmd() *cobra.Command {
	var (
		mode         string
		workers      int
		maxSize      string
		extensions   []string
		exclude      []string
		reportFormat string
		outputFile   string
		noHTML       bool
		detectors    []string
		disable      []string
		experimental bool
		cmsType      string
		// AI flags
		aiEnabled bool
		aiModel   string
		aiToken   string
		aiLang    string
		aiSmart   bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan directory for malware and vulnerabilities",
		Long:  `Recursively scan a directory for malicious code, backdoors, shells, and other threats.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			// Validate flags before doing anything
			if err := validateFlags(mode, reportFormat, aiModel, aiLang, cmsType); err != nil {
				fmt.Printf("\n  %s✗ Invalid parameter:%s %s\n\n", colorRed, colorReset, err.Error())
				return err
			}

			// Initialize logger based on verbose flag
			var err error
			if verbose {
				logger, err = zap.NewDevelopment()
			} else {
				// Silent logger - only errors
				cfg := zap.Config{
					Level:            zap.NewAtomicLevelAt(zapcore.ErrorLevel),
					Encoding:         "json",
					OutputPaths:      []string{"stderr"},
					ErrorOutputPaths: []string{"stderr"},
					EncoderConfig:    zap.NewProductionEncoderConfig(),
				}
				logger, err = cfg.Build()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
				return err
			}
			defer logger.Sync()

			// Print banner
			printBanner(path, mode)

			// Load configuration
			cfg, err := config.LoadConfig()
			if err != nil {
				logger.Error("Failed to load config", zap.Error(err))
				return err
			}

			// Override config with CLI flags
			if mode != "" {
				cfg.Mode = mode
			}
			if workers > 0 {
				cfg.Workers = workers
			}
			if maxSize != "" {
				cfg.MaxSize = maxSize
			}
			if len(extensions) > 0 {
				cfg.Extensions = extensions
			}
			if len(exclude) > 0 {
				cfg.Exclude = exclude
			}
			if reportFormat != "" {
				cfg.ReportFormat = reportFormat
			}
			if outputFile != "" {
				cfg.OutputFile = outputFile
			}
			cfg.NoHTML = noHTML
			if len(detectors) > 0 {
				cfg.Detectors = detectors
			}
			if len(disable) > 0 {
				cfg.Disable = disable
			}
			if experimental {
				cfg.EnableExperimental = true
			}
			if cmsType != "" {
				cfg.ForceCMS = cmsType
			}

			// AI configuration overrides
			if aiEnabled {
				cfg.AI.Enabled = true
			}
			if aiModel != "" {
				cfg.AI.Model = aiModel
			}
			if aiToken != "" {
				cfg.AI.APIToken = aiToken
			}
			if aiLang != "" {
				cfg.AI.Language = aiLang
			}
			if aiSmart {
				cfg.AI.SmartMode = true
				cfg.AI.Enabled = true // Enable AI if smart mode is set
			}

			// Interactive AI wizard if --ai is enabled but no token provided
			if cfg.AI.Enabled && cfg.AI.APIToken == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
				wizardResult, err := runAIWizard()
				if err != nil {
					fmt.Printf("  %s⚠ AI wizard cancelled:%s %v\n", colorYellow, colorReset, err)
					fmt.Printf("  %sProceeding without AI analysis...%s\n\n", colorGray, colorReset)
					cfg.AI.Enabled = false
				} else {
					cfg.AI.APIToken = wizardResult.Token
					if wizardResult.Model != "" {
						cfg.AI.Model = wizardResult.Model
					}
					if wizardResult.Language != "" {
						cfg.AI.Language = wizardResult.Language
					}
				}
			}

			// Create scanner
			scanner := core.NewScanner(cfg, logger)

			// Set up progress callback
			lastPhase := ""
			scanner.SetProgressCallback(func(phase string, current, total int, message string) {
				// Clear previous line if same phase
				if lastPhase == phase && phase != "counting" && phase != "started" {
					fmt.Print("\033[1A\033[K")
				}
				lastPhase = phase

				switch phase {
				case "counting":
					if current == 0 && total == 0 {
						// First call - show "Starting scan..."
						fmt.Printf("\n  %sStarting scan...%s\n", colorReset, colorReset)
					}
					if total > 0 {
						fmt.Printf("  %sFiles:%s      %s\n", colorGray, colorReset, message)
					}
				case "scanning":
					if total > 0 {
						pct := float64(current) / float64(total) * 100
						barWidth := 30
						filled := int(float64(barWidth) * float64(current) / float64(total))
						bar := fmt.Sprintf("%s%s", repeat("█", filled), repeat("░", barWidth-filled))
						fmt.Printf("  %sScanning:%s  [%s%s%s] %s%.1f%%%s (%d/%d)\n",
							colorGray, colorReset, colorOrange, bar, colorReset, colorOrange, pct, colorReset, current, total)
					}
				case "ai_init":
					fmt.Printf("\n  %s%sAI Analysis%s\n", colorBold, colorRed, colorReset)
					fmt.Printf("  %sInitializing...%s\n", colorGray, colorReset)
				case "ai_analysis":
					if total > 0 {
						pct := float64(current) / float64(total) * 100
						barWidth := 30
						filled := int(float64(barWidth) * float64(current) / float64(total))
						bar := fmt.Sprintf("%s%s", repeat("█", filled), repeat("░", barWidth-filled))
						// Truncate message if too long
						msg := message
						if len(msg) > 40 {
							msg = msg[:37] + "..."
						}
						fmt.Printf("  %sAnalyzing:%s [%s%s%s] %s%.1f%%%s (%d/%d) %s%s%s\n",
							colorGray, colorReset, colorRed, bar, colorReset, colorRed, pct, colorReset, current, total, colorGray, msg, colorReset)
					}
				case "ai_complete":
					// current = tokens used, total = findings analyzed
					tokensUsed := current
					if tokensUsed > 0 {
						fmt.Printf("  %s✓ AI complete%s %s(%d tokens used)%s\n\n", colorRed, colorReset, colorGray, tokensUsed, colorReset)
					} else {
						fmt.Printf("  %s✓ AI analysis complete%s\n\n", colorRed, colorReset)
					}
				case "ai_skipped":
					fmt.Printf("  %s⊘ AI analysis skipped%s\n\n", colorGray, colorReset)
				case "ai_error":
					fmt.Printf("  %s⚠ %s%s\n\n", colorYellow, message, colorReset)
				}
			})

			// Set up AI confirmation callback
			scanner.SetAIConfirmCallback(func(estimate *ai.CostEstimate) bool {
				fmt.Printf("\n  %s%sAI Analysis Cost Estimate%s\n", colorBold, colorRed, colorReset)
				fmt.Printf("  %sFindings:%s      %d\n", colorGray, colorReset, estimate.FindingsCount)
				fmt.Printf("  %sModel:%s         %s\n", colorGray, colorReset, estimate.Model)

				// Show mode
				if estimate.SmartMode {
					fmt.Printf("  %sMode:%s          %ssmart%s (dedupe + sample)\n", colorGray, colorReset, colorOrange, colorReset)
					fmt.Printf("  %sTo Analyze:%s    %d samples\n", colorGray, colorReset, estimate.SampledCount)
				} else {
					fmt.Printf("  %sQuick Filter:%s  %v\n", colorGray, colorReset, estimate.QuickFilter)
				}

				fmt.Printf("  %sEst. Tokens:%s   ~%dk\n", colorGray, colorReset, estimate.EstimatedTokens/1000)
				fmt.Printf("  %sEst. Cost:%s     %s$%.2f%s\n", colorGray, colorReset, colorYellow, estimate.EstimatedCostUSD, colorReset)
				fmt.Println()

				// Ask for confirmation
				fmt.Printf("  %sProceed with AI analysis? [Y/n]:%s ", colorBold, colorReset)

				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return false
				}

				input = strings.TrimSpace(strings.ToLower(input))
				return input == "" || input == "y" || input == "yes"
			})

			// Run scan
			results, err := scanner.Scan(path)
			if err != nil {
				logger.Error("Scan failed", zap.Error(err))
				return err
			}

			// Print report path if generated
			if results.ReportPath != "" {
				fmt.Printf("  %sReport:%s    %s%s%s\n", colorGray, colorReset, colorOrange, results.ReportPath, colorReset)
				fmt.Println()
			}

			return nil
		},
	}

	// Flags
	cmd.Flags().StringVar(&mode, "mode", "normal", "Scan mode: fast, normal, paranoid")
	cmd.Flags().IntVar(&workers, "workers", 0, "Number of worker goroutines (default: CPU cores * 2)")
	cmd.Flags().StringVar(&maxSize, "max-size", "650K", "Maximum file size to scan")
	cmd.Flags().StringSliceVar(&extensions, "extensions", nil, "File extensions to scan (comma-separated)")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "Directories to exclude (comma-separated)")
	cmd.Flags().StringVarP(&reportFormat, "report", "r", "", "Report format: txt, html, json, xml, md (default: console output)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	cmd.Flags().BoolVar(&noHTML, "no-html", false, "Disable HTML report generation")
	cmd.Flags().StringSliceVar(&detectors, "detectors", nil, "Enable specific detectors (comma-separated)")
	cmd.Flags().StringSliceVar(&disable, "disable", nil, "Disable specific detectors (comma-separated)")
	cmd.Flags().BoolVar(&experimental, "experimental", false, "Enable experimental detectors (heuristic, adware, phishing, doorway, XSS, iframe)")
	cmd.Flags().StringVar(&cmsType, "cms", "", "Force specific CMS detector (bitrix, wordpress, laravel, symfony, drupal, joomla). Auto-detect if not specified.")

	// AI flags
	cmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered analysis of findings")
	cmd.Flags().StringVar(&aiModel, "ai-model", "", "AI model: haiku, sonnet, opus (default: sonnet)")
	cmd.Flags().StringVar(&aiToken, "ai-token", "", "Anthropic API token (or set ANTHROPIC_API_KEY)")
	cmd.Flags().StringVar(&aiLang, "ai-lang", "", "AI report language: en, ru, es (default: en)")
	cmd.Flags().BoolVar(&aiSmart, "ai-smart", false, "Smart AI mode: dedupe by signature, sample 3 per type, prioritize by severity")

	return cmd
}

// deobCmd creates the deobfuscate command
func deobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deob <file>",
		Short: "Deobfuscate a file and print result to stdout",
		Long:  `Apply all available deobfuscators to a file and print the result to stdout.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			// Check if file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("file not found: %s", filePath)
			}

			// Read file content
			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			// Initialize deobfuscator manager
			manager := deobfuscator.NewManager(100)
			manager.Register(deobfPHP.NewBase64Deobfuscator())
			manager.Register(deobfPHP.NewEvalDeobfuscator())
			manager.Register(deobfPHP.NewLockItDeobfuscator())
			manager.Register(deobfPHP.NewALSDeobfuscator())
			manager.Register(deobfPHP.NewByteRunDeobfuscator())
			manager.Register(deobfPHP.NewFOPODeobfuscator())
			manager.Register(deobfPHP.NewGlobalsDeobfuscator())
			manager.Register(deobfPHP.NewURLDecodeDeobfuscator())

			// Deobfuscate
			result, modified := manager.Deobfuscate(string(content))

			if !modified {
				fmt.Fprintf(os.Stderr, "%s⚠ No obfuscation detected or nothing to deobfuscate%s\n", colorYellow, colorReset)
				fmt.Print(string(content))
				return nil
			}

			fmt.Fprintf(os.Stderr, "%s✓ Deobfuscation applied%s\n\n", colorOrange, colorReset)
			fmt.Print(result)

			return nil
		},
	}

	return cmd
}


// validateFlags validates CLI flag values
func validateFlags(mode, reportFormat, aiModel, aiLang, cmsType string) error {
	// Validate mode
	if mode != "" {
		validModes := []string{"fast", "normal", "paranoid"}
		if !contains(validModes, mode) {
			return fmt.Errorf("--mode must be one of: %s (got: %s)", strings.Join(validModes, ", "), mode)
		}
	}

	// Validate report format
	if reportFormat != "" {
		validFormats := []string{"text", "html", "json", "xml", "md", "markdown"}
		if !contains(validFormats, reportFormat) {
			return fmt.Errorf("--report must be one of: %s (got: %s)", strings.Join(validFormats, ", "), reportFormat)
		}
	}

	// Validate AI model
	if aiModel != "" {
		validModels := []string{"haiku", "sonnet", "opus"}
		if !contains(validModels, aiModel) {
			return fmt.Errorf("--ai-model must be one of: %s (got: %s)", strings.Join(validModels, ", "), aiModel)
		}
	}

	// Validate AI language
	if aiLang != "" {
		validLangs := []string{"en", "ru", "es", "de", "zh"}
		if !contains(validLangs, aiLang) {
			return fmt.Errorf("--ai-lang must be one of: %s (got: %s)", strings.Join(validLangs, ", "), aiLang)
		}
	}

	// Validate CMS type
	if cmsType != "" {
		validCMS := []string{"bitrix", "wordpress", "laravel", "symfony", "drupal", "joomla"}
		if !contains(validCMS, cmsType) {
			return fmt.Errorf("--cms must be one of: %s (got: %s)", strings.Join(validCMS, ", "), cmsType)
		}
	}

	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// repeat returns a string with character c repeated n times
func repeat(c string, n int) string {
	if n <= 0 {
		return ""
	}
	result := ""
	for i := 0; i < n; i++ {
		result += c
	}
	return result
}

// printBanner prints the startup banner
func printBanner(path string, mode string) {
	if mode == "" {
		mode = "normal"
	}
	fmt.Println()
	fmt.Printf("%s", colorOrange)
	fmt.Println("██  ██ ▄████▄ ██  ██ ███  ██ ████▄  ▄████▄ ▄████▄ ██▄  ▄██")
	fmt.Println("██████ ██  ██ ██  ██ ██ ▀▄██ ██  ██ ██  ██ ██  ██ ██ ▀▀ ██")
	fmt.Println("██  ██ ▀████▀ ▀████▀ ██   ██ ████▀  ▀████▀ ▀████▀ ██    ██")
	fmt.Printf("%s", colorReset)
	fmt.Println()
	fmt.Printf("%sSecurity Scanner v%s%s\n", colorGray, version, colorReset)
	fmt.Println()
	fmt.Printf("  %sScanning:%s  %s\n", colorGray, colorReset, path)
	fmt.Printf("  %sMode:%s      %s\n", colorGray, colorReset, mode)
	fmt.Println()
}

// detectorsCmd creates the detectors command
func detectorsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detectors list",
		Short: "List available detectors",
		Long:  `Display a list of all available threat detectors and their status.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("CRITICAL DETECTORS (always enabled):")
			fmt.Println("  ✓ php-critical      Critical PHP vulnerabilities and malware")
			fmt.Println("  ✓ php-backdoor      PHP backdoors and web shells")
			fmt.Println("  ✓ php-injection     SQL/Code injection vulnerabilities")
			fmt.Println("  ✓ js-malicious      Malicious JavaScript code")
			fmt.Println("  ✓ executable        Suspicious executable files")
			fmt.Println("")
			fmt.Println("CMS-SPECIFIC DETECTORS (auto-detected or use --cms flag):")
			fmt.Println("  ◆ bitrix            Bitrix CMS dangerous methods & WordPress detection")
			fmt.Println("  ◇ wordpress         WordPress detector (not implemented yet)")
			fmt.Println("  ◇ drupal            Drupal detector (not implemented yet)")
			fmt.Println("  ◇ laravel           Laravel detector (not implemented yet)")
			fmt.Println("")
			fmt.Println("EXPERIMENTAL DETECTORS (use --experimental to enable):")
			fmt.Println("  ○ js-iframe         JavaScript iframe injections")
			fmt.Println("  ○ js-xss            XSS vulnerabilities")
			fmt.Println("  ○ adware            Adware and spam links")
			fmt.Println("  ○ phishing          Phishing pages")
			fmt.Println("  ○ doorway           Doorway pages (SEO spam)")
			fmt.Println("  ○ heuristic         Heuristic analyzer (entropy, patterns)")
			fmt.Println("")
			fmt.Println("CMS AUTO-DETECTION:")
			fmt.Println("  The scanner automatically detects CMS type (Bitrix, WordPress, Laravel, etc)")
			fmt.Println("  and enables corresponding detectors. Use --cms flag to force specific CMS.")
			fmt.Println("")
			fmt.Println("AI ANALYSIS MODES (use --ai to enable):")
			fmt.Println("  --ai              Standard mode - analyze each finding individually")
			fmt.Println("  --ai-smart        Smart mode - dedupe by signature, sample 3 per type, prioritize by severity")
			fmt.Println("")
			fmt.Println("EXAMPLES:")
			fmt.Println("  houndoom scan /var/www/bitrix                  # Auto-detect CMS")
			fmt.Println("  houndoom scan --cms=bitrix /var/www/project    # Force Bitrix detector")
			fmt.Println("  houndoom scan --experimental /var/www/site     # Enable all detectors")
			fmt.Println("  houndoom scan --ai /var/www/site               # Enable AI analysis")
			fmt.Println("  houndoom scan --ai-smart /var/www/site         # AI with smart sampling")
		},
	}
}

// helpCmd creates a detailed help command
func helpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "help",
		Short: "Show detailed help and documentation",
		Long:  `Display complete documentation including all commands, flags, and examples.`,
		Run: func(cmd *cobra.Command, args []string) {
			printMainBanner()

			fmt.Printf("%s%sABOUT%s\n\n", colorBold, colorOrange, colorReset)
			fmt.Printf("  Houndoom is a high-performance security scanner designed for detecting\n")
			fmt.Printf("  malicious code in web applications. It finds PHP backdoors, web shells,\n")
			fmt.Printf("  JavaScript malware, phishing pages, and other threats.\n\n")

			fmt.Printf("  %sKey features:%s\n", colorBold, colorReset)
			fmt.Printf("  • Multi-threaded scanning with configurable worker pool\n")
			fmt.Printf("  • 7+ deobfuscators (base64, eval, LockIt, ByteRun, FOPO, etc.)\n")
			fmt.Printf("  • AI-powered analysis using Claude for deep threat assessment\n")
			fmt.Printf("  • Multiple output formats: HTML, JSON, Markdown, XML, text\n")
			fmt.Printf("  • Heuristic analysis with entropy and pattern detection\n\n")

			fmt.Printf("%s%sCOMMANDS%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %sscan <path>%s       Scan directory for malware and vulnerabilities\n", colorBold, colorReset)
			fmt.Printf("  %sdeob <file>%s       Deobfuscate a file and print result to stdout\n", colorBold, colorReset)
			fmt.Printf("  %sdetectors list%s    Show all available threat detectors\n", colorBold, colorReset)

			fmt.Printf("\n%s%sSCAN FLAGS%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %s--mode%s <mode>      Scan mode: %sfast%s, %snormal%s, %sparanoid%s (default: normal)\n",
				colorBold, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset)
			fmt.Printf("                      fast     - Critical files only (.php, .js, .html, .htaccess)\n")
			fmt.Printf("                      normal   - Standard scan with heuristics\n")
			fmt.Printf("                      paranoid - Deep scan with full deobfuscation\n")
			fmt.Println()
			fmt.Printf("  %s--workers%s <n>      Number of parallel workers (default: CPU cores × 2)\n", colorBold, colorReset)
			fmt.Printf("  %s--max-size%s <size>  Maximum file size to scan (default: 650K)\n", colorBold, colorReset)
			fmt.Printf("  %s--extensions%s       File extensions to scan (comma-separated)\n", colorBold, colorReset)
			fmt.Printf("  %s--exclude%s          Directories to exclude (comma-separated)\n", colorBold, colorReset)
			fmt.Printf("  %s--cms%s <type>       Force CMS: bitrix, wordpress, laravel, symfony, drupal, joomla\n", colorBold, colorReset)
			fmt.Printf("  %s--experimental%s     Enable experimental detectors (heuristic, adware, phishing, etc.)\n", colorBold, colorReset)
			fmt.Printf("  %s--detectors%s        Enable only specific detectors (comma-separated)\n", colorBold, colorReset)
			fmt.Printf("  %s--disable%s          Disable specific detectors (comma-separated)\n", colorBold, colorReset)

			fmt.Printf("\n%s%sREPORT FLAGS%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %s-r, --report%s <fmt> Report format: %stxt%s, %shtml%s, %sjson%s, %sxml%s, %smd%s\n",
				colorBold, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset)
			fmt.Printf("  %s-o, --output%s <file> Output file path\n", colorBold, colorReset)
			fmt.Printf("  %s--no-html%s          Disable automatic HTML report generation\n", colorBold, colorReset)

			fmt.Printf("\n%s%sAI ANALYSIS FLAGS%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %s--ai%s               Enable AI-powered deep analysis of findings\n", colorBold, colorReset)
			fmt.Printf("  %s--ai-smart%s         Smart mode: dedupe by signature, sample 3 per type (cost-effective)\n", colorBold, colorReset)
			fmt.Printf("  %s--ai-model%s <model> AI model: %shaiku%s (fast), %ssonnet%s (default), %sopus%s (best)\n",
				colorBold, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset)
			fmt.Printf("  %s--ai-token%s <token> Anthropic API token (or set ANTHROPIC_API_KEY env)\n", colorBold, colorReset)
			fmt.Printf("  %s--ai-lang%s <lang>   Report language: en, ru, es, de, zh (default: en)\n", colorBold, colorReset)

			fmt.Printf("\n%s%sGLOBAL FLAGS%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %s-v, --verbose%s      Enable verbose logging\n", colorBold, colorReset)
			fmt.Printf("  %s-h, --help%s         Show help for any command\n", colorBold, colorReset)
			fmt.Printf("  %s--version%s          Show version\n", colorBold, colorReset)

			fmt.Printf("\n%s%sEXAMPLES%s\n\n", colorBold, colorOrange, colorReset)

			fmt.Printf("  %s# Basic scan%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan /var/www/site\n\n")

			fmt.Printf("  %s# Deep scan with all detectors%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan --mode=paranoid --experimental /var/www/site\n\n")

			fmt.Printf("  %s# Scan with AI analysis%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan --ai /var/www/site\n\n")

			fmt.Printf("  %s# Cost-effective AI for large codebases%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan --ai-smart /var/www/site\n\n")

			fmt.Printf("  %s# Force Bitrix CMS detection%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan --cms=bitrix /var/www/bitrix\n\n")

			fmt.Printf("  %s# Generate JSON report%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom scan --report=json --output=report.json /var/www/site\n\n")

			fmt.Printf("  %s# Deobfuscate a suspicious file%s\n", colorGray, colorReset)
			fmt.Printf("  houndoom deob suspicious.php\n\n")
		},
	}
}

// AIWizardResult holds the wizard configuration results
type AIWizardResult struct {
	Token    string
	Model    string
	Language string
}

// runAIWizard runs an interactive wizard to configure AI settings
func runAIWizard() (*AIWizardResult, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Printf("  %s%sAI Analysis Configuration%s\n", colorBold, colorRed, colorReset)
	fmt.Printf("  %s─────────────────────────%s\n", colorRed, colorReset)
	fmt.Println()

	// Prompt for API token
	fmt.Printf("  %sEnter Anthropic API token%s (or 'skip' to disable AI):\n", colorBold, colorReset)
	fmt.Printf("  %s> %s", colorRed, colorReset)

	tokenInput, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	token := strings.TrimSpace(tokenInput)
	if token == "" || strings.ToLower(token) == "skip" {
		return nil, fmt.Errorf("skipped by user")
	}

	// Validate token format
	if !strings.HasPrefix(token, "sk-ant-") {
		fmt.Printf("\n  %s⚠ Warning:%s Token doesn't start with 'sk-ant-', but continuing anyway.\n", colorYellow, colorReset)
	}

	// Prompt for model selection
	fmt.Println()
	fmt.Printf("  %sSelect AI model:%s\n", colorBold, colorReset)
	fmt.Printf("  %s[1]%s haiku   %s- Fast & cheap, good for filtering%s\n", colorRed, colorReset, colorGray, colorReset)
	fmt.Printf("  %s[2]%s sonnet  %s- Balanced, recommended for most cases%s %s(default)%s\n", colorRed, colorReset, colorGray, colorReset, colorOrange, colorReset)
	fmt.Printf("  %s[3]%s opus    %s- Most capable, best for complex analysis%s\n", colorRed, colorReset, colorGray, colorReset)
	fmt.Println()
	fmt.Printf("  %sEnter choice [1-3]%s (or press Enter for sonnet):\n", colorBold, colorReset)
	fmt.Printf("  %s> %s", colorRed, colorReset)

	modelInput, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	modelChoice := strings.TrimSpace(modelInput)
	var model string

	switch modelChoice {
	case "1":
		model = "haiku"
		fmt.Printf("\n  %s✓%s Selected: %shaiku%s\n", colorRed, colorReset, colorBold, colorReset)
	case "3":
		model = "opus"
		fmt.Printf("\n  %s✓%s Selected: %sopus%s\n", colorRed, colorReset, colorBold, colorReset)
	default:
		model = "sonnet"
		fmt.Printf("\n  %s✓%s Selected: %ssonnet%s\n", colorRed, colorReset, colorBold, colorReset)
	}

	// Prompt for language selection
	fmt.Println()
	fmt.Printf("  %sSelect report language:%s\n", colorBold, colorReset)
	fmt.Printf("  %s[1]%s English  %s(default)%s\n", colorRed, colorReset, colorOrange, colorReset)
	fmt.Printf("  %s[2]%s Русский\n", colorRed, colorReset)
	fmt.Printf("  %s[3]%s Español\n", colorRed, colorReset)
	fmt.Println()
	fmt.Printf("  %sEnter choice [1-3]%s (or press Enter for English):\n", colorBold, colorReset)
	fmt.Printf("  %s> %s", colorRed, colorReset)

	langInput, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	langChoice := strings.TrimSpace(langInput)
	var language string

	switch langChoice {
	case "2":
		language = "ru"
		fmt.Printf("\n  %s✓%s Selected: %sРусский%s\n", colorRed, colorReset, colorBold, colorReset)
	case "3":
		language = "es"
		fmt.Printf("\n  %s✓%s Selected: %sEspañol%s\n", colorRed, colorReset, colorBold, colorReset)
	default:
		language = "en"
		fmt.Printf("\n  %s✓%s Selected: %sEnglish%s\n", colorRed, colorReset, colorBold, colorReset)
	}

	fmt.Println()
	fmt.Printf("  %sTip:%s To skip this wizard, set ANTHROPIC_API_KEY environment variable\n", colorGray, colorReset)
	fmt.Printf("  %s     or use --ai-token, --ai-model, and --ai-lang flags.%s\n", colorGray, colorReset)
	fmt.Println()

	return &AIWizardResult{
		Token:    token,
		Model:    model,
		Language: language,
	}, nil
}

