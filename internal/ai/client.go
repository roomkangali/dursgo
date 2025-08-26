package ai

import (
	"Dursgo/internal/config"
	"Dursgo/internal/scanner"
	"context"
	"fmt"

	"github.com/google/generative-ai-go/genai"
	"github.com/sashabaranov/go-openai"
	"google.golang.org/api/option"
)

// AIClient defines the interface for an AI analysis client.
type AIClient interface {
	AnalyzeVulnerability(ctx context.Context, vuln scanner.VulnerabilityResult) (string, error)
}

// client implements the AIClient interface.
type client struct {
	cfg          *config.AIConfig
	geminiClient *genai.GenerativeModel
	openaiClient *openai.Client // Used for both OpenAI and Groq
}

// NewAIClient creates a new client for AI analysis based on the provided configuration.
func NewAIClient(cfg *config.AIConfig) (AIClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("AI analysis is not enabled in the configuration")
	}

	switch cfg.Provider {
	case "gemini":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("Gemini API key is not configured in config.yaml")
		}
		ctx := context.Background()
		genaiClient, err := genai.NewClient(ctx, option.WithAPIKey(cfg.APIKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create Gemini client: %w", err)
		}
		model := genaiClient.GenerativeModel(cfg.Model)
		return &client{cfg: cfg, geminiClient: model}, nil

	case "openai", "groq":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("%s API key is not configured in config.yaml", cfg.Provider)
		}
		config := openai.DefaultConfig(cfg.APIKey)
		if cfg.Provider == "groq" {
			config.BaseURL = "https://api.groq.com/openai/v1"
		}
		openaiClient := openai.NewClientWithConfig(config)
		return &client{cfg: cfg, openaiClient: openaiClient}, nil

	default:
		return nil, fmt.Errorf("unknown AI provider '%s'", cfg.Provider)
	}
}

// AnalyzeVulnerability sends the vulnerability details to the configured LLM and returns its analysis.
func (c *client) AnalyzeVulnerability(ctx context.Context, vuln scanner.VulnerabilityResult) (string, error) {
	// The new prompt instructs the AI to return a readable, Markdown-formatted response
	// and to auto-detect the language for the code example.
	prompt := fmt.Sprintf(`
You are a professional penetration tester providing a summary for a developer.
Analyze the following security vulnerability and respond with a concise, actionable summary formatted in Markdown.

Use the following structure:
**Root Cause:** [Your analysis of the root cause]
**Recommendation:** [Your specific, actionable recommendation]
**Code Example (if relevant):**
`+"```"+`[language]
[Your code example for the fix]
`+"```"+`

Instructions for the Code Example:
- Infer the programming language from the context (e.g., URL extension).
- Replace '[language]' with the correct Markdown language specifier (e.g., php, python, javascript).

Vulnerability Details:
- Type: %s
- URL: %s
- Parameter: %s
- Payload: %s
- Details: %s
- Severity: %s
`,
		vuln.VulnerabilityType,
		vuln.URL,
		vuln.Parameter,
		vuln.Payload,
		vuln.Details,
		vuln.Severity,
	)

	switch c.cfg.Provider {
	case "gemini":
		if c.geminiClient == nil {
			return "", fmt.Errorf("Gemini client is not initialized")
		}
		resp, err := c.geminiClient.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			return "", fmt.Errorf("failed to generate content from Gemini: %w", err)
		}
		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("received an empty response from Gemini")
		}
		analysisResult, ok := resp.Candidates[0].Content.Parts[0].(genai.Text)
		if !ok {
			return "", fmt.Errorf("unexpected response format from Gemini")
		}
		return string(analysisResult), nil

	case "openai", "groq":
		if c.openaiClient == nil {
			return "", fmt.Errorf("%s client is not initialized", c.cfg.Provider)
		}
		resp, err := c.openaiClient.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model: c.cfg.Model,
				Messages: []openai.ChatCompletionMessage{
					{
						Role:    openai.ChatMessageRoleUser,
						Content: prompt,
					},
				},
			},
		)
		if err != nil {
			return "", fmt.Errorf("failed to generate content from %s: %w", c.cfg.Provider, err)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("received an empty response from %s", c.cfg.Provider)
		}
		return resp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("unhandled AI provider in AnalyzeVulnerability: %s", c.cfg.Provider)
}
