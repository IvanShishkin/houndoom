package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Client wraps the Anthropic API client
type Client struct {
	client    *anthropic.Client
	model     string
	timeout   time.Duration
}

// NewClient creates a new AI client
func NewClient(model string, apiToken string, timeoutSeconds int) (*Client, error) {
	// Resolve API token: parameter > environment variable
	token := apiToken
	if token == "" {
		token = os.Getenv("ANTHROPIC_API_KEY")
	}
	if token == "" {
		return nil, errors.New("no API token provided: set --ai-token flag or ANTHROPIC_API_KEY environment variable")
	}

	// Create client with token
	client := anthropic.NewClient(option.WithAPIKey(token))

	// Map model name to model ID
	modelID := mapModelName(model)

	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		client:  client,
		model:   modelID,
		timeout: timeout,
	}, nil
}

// mapModelName converts friendly model names to model IDs
func mapModelName(name string) string {
	switch strings.ToLower(name) {
	case "haiku":
		return "claude-3-5-haiku-latest"
	case "sonnet":
		return "claude-sonnet-4-20250514"
	case "opus":
		return "claude-opus-4-20250514"
	default:
		// Default to sonnet if unknown
		return "claude-sonnet-4-20250514"
	}
}

// Analyze sends a finding for deep analysis
func (c *Client) Analyze(ctx context.Context, req *AnalysisRequest, lang string) (*AnalysisResponse, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Build the prompt
	userPrompt := BuildDeepAnalysisPrompt(req, lang)

	// Call the API
	message, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.F(c.model),
		MaxTokens: anthropic.F(int64(1024)),
		System: anthropic.F([]anthropic.TextBlockParam{
			anthropic.NewTextBlock(DeepAnalysisSystemPrompt),
		}),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	// Extract text content
	responseText := extractTextContent(message)
	if responseText == "" {
		return nil, errors.New("empty response from API")
	}

	// Parse JSON response
	response, err := parseAnalysisResponse(responseText, req.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Add token usage
	response.TokensUsed = int(message.Usage.InputTokens + message.Usage.OutputTokens)

	return response, nil
}

// QuickFilter sends a finding for quick filtering with Haiku
func (c *Client) QuickFilter(ctx context.Context, req *AnalysisRequest, lang string) (*QuickFilterResult, error) {
	// Create context with timeout (shorter for quick filter)
	ctx, cancel := context.WithTimeout(ctx, c.timeout/2)
	defer cancel()

	// Build the prompt (lang not used for quick filter, but passed for consistency)
	userPrompt := BuildQuickFilterPrompt(req, lang)

	// Always use Haiku for quick filtering
	message, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.F("claude-3-5-haiku-latest"),
		MaxTokens: anthropic.F(int64(256)),
		System: anthropic.F([]anthropic.TextBlockParam{
			anthropic.NewTextBlock(QuickFilterSystemPrompt),
		}),
		Messages: anthropic.F([]anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	// Extract text content
	responseText := extractTextContent(message)
	if responseText == "" {
		return nil, errors.New("empty response from API")
	}

	// Parse JSON response
	result, err := parseQuickFilterResult(responseText, req.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Add token usage
	result.TokensUsed = int(message.Usage.InputTokens + message.Usage.OutputTokens)

	return result, nil
}

// extractTextContent extracts text from the message response
func extractTextContent(message *anthropic.Message) string {
	var text strings.Builder
	for _, block := range message.Content {
		if block.Type == anthropic.ContentBlockTypeText {
			text.WriteString(block.Text)
		}
	}
	return text.String()
}

// parseAnalysisResponse parses the JSON response into AnalysisResponse
func parseAnalysisResponse(text string, findingID string) (*AnalysisResponse, error) {
	// Clean up the response - extract JSON from potential markdown
	text = extractJSON(text)

	var raw struct {
		Verdict     string   `json:"verdict"`
		Confidence  int      `json:"confidence"`
		Explanation string   `json:"explanation"`
		Remediation string   `json:"remediation"`
		Indicators  []string `json:"indicators"`
		RiskLevel   string   `json:"risk_level"`
	}

	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}

	return &AnalysisResponse{
		FindingID:   findingID,
		Verdict:     Verdict(raw.Verdict),
		Confidence:  raw.Confidence,
		Explanation: raw.Explanation,
		Remediation: raw.Remediation,
		Indicators:  raw.Indicators,
		RiskLevel:   raw.RiskLevel,
	}, nil
}

// parseQuickFilterResult parses the JSON response into QuickFilterResult
func parseQuickFilterResult(text string, findingID string) (*QuickFilterResult, error) {
	// Clean up the response - extract JSON from potential markdown
	text = extractJSON(text)

	var raw struct {
		NeedsAnalysis bool   `json:"needs_analysis"`
		Reason        string `json:"reason"`
		Confidence    int    `json:"confidence"`
	}

	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}

	return &QuickFilterResult{
		FindingID:     findingID,
		NeedsAnalysis: raw.NeedsAnalysis,
		Reason:        raw.Reason,
		Confidence:    raw.Confidence,
	}, nil
}

// extractJSON extracts JSON from text that might contain markdown code blocks
func extractJSON(text string) string {
	text = strings.TrimSpace(text)

	// Try to extract from code blocks
	if strings.Contains(text, "```") {
		// Find JSON in code block
		start := strings.Index(text, "```json")
		if start == -1 {
			start = strings.Index(text, "```")
		}
		if start != -1 {
			// Find the end of the opening marker
			contentStart := strings.Index(text[start:], "\n")
			if contentStart != -1 {
				start = start + contentStart + 1
			}
		}

		end := strings.LastIndex(text, "```")
		if start != -1 && end > start {
			text = text[start:end]
		}
	}

	// Try to find JSON object boundaries
	text = strings.TrimSpace(text)
	jsonStart := strings.Index(text, "{")
	jsonEnd := strings.LastIndex(text, "}")

	if jsonStart != -1 && jsonEnd > jsonStart {
		text = text[jsonStart : jsonEnd+1]
	}

	return strings.TrimSpace(text)
}

// GetModel returns the current model being used
func (c *Client) GetModel() string {
	return c.model
}

