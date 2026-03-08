package ai

import (
	"Dursgo/internal/config"
	"Dursgo/internal/scanner"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	openaiClient *openai.Client // Used for OpenAI, Groq, and OpenRouter
	httpClient   *http.Client   // Used for Anthropic (native API)
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

	case "openai", "groq", "openrouter":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("%s API key is not configured in config.yaml", cfg.Provider)
		}
		oaiConfig := openai.DefaultConfig(cfg.APIKey)
		switch cfg.Provider {
		case "groq":
			oaiConfig.BaseURL = "https://api.groq.com/openai/v1"
		case "openrouter":
			oaiConfig.BaseURL = "https://openrouter.ai/api/v1"
		}
		openaiClient := openai.NewClientWithConfig(oaiConfig)
		return &client{cfg: cfg, openaiClient: openaiClient}, nil

	case "anthropic":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("Anthropic API key is not configured in config.yaml")
		}
		return &client{cfg: cfg, httpClient: &http.Client{}}, nil

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

	case "openai", "groq", "openrouter":
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

	case "anthropic":
		return c.analyzeWithAnthropic(ctx, prompt)
	}

	return "", fmt.Errorf("unhandled AI provider in AnalyzeVulnerability: %s", c.cfg.Provider)
}

// analyzeWithAnthropic calls the Anthropic Messages API natively.
func (c *client) analyzeWithAnthropic(ctx context.Context, prompt string) (string, error) {
	if c.httpClient == nil {
		return "", fmt.Errorf("Anthropic HTTP client is not initialized")
	}

	// Build request body according to Anthropic Messages API spec.
	reqBody := map[string]interface{}{
		"model":      c.cfg.Model,
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create Anthropic request: %w", err)
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Anthropic response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Anthropic API returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	// Parse Anthropic response format.
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse Anthropic response: %w", err)
	}
	if len(parsed.Content) == 0 {
		return "", fmt.Errorf("received an empty response from Anthropic")
	}
	return parsed.Content[0].Text, nil
}
