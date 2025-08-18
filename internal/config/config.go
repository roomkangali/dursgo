package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// OutputConfig holds configuration settings related to output and logging.
type OutputConfig struct {
	Format     string `yaml:"format"`      // Output format (e.g., "text", "json").
	OutputFile string `yaml:"output_file"` // Path to save the output file.
	Verbose    bool   `yaml:"verbose"`     // Enable verbose logging.
}

// Config is the main struct to hold all configuration data from the YAML file.
type Config struct {
	Target      string   `yaml:"target"`          // Target URL for scanning.
	Concurrency int      `yaml:"concurrency"`     // Number of concurrent workers.
	MaxRetries  int      `yaml:"max_retries"`     // Maximum number of retries for HTTP requests.
	Delay       int      `yaml:"delay"`           // Delay between requests in milliseconds.
	MaxDepth    int      `yaml:"max_depth"`       // Maximum crawling depth.
	Scanners    string   `yaml:"scanners_to_run"` // Comma-separated list of scanners to run.
	OAST        bool     `yaml:"oast"`            // Enable Out-of-Band Application Security Testing.
	RenderJS    bool     `yaml:"render_js"`       // Enable JavaScript rendering via headless browser.
	SeedURLs    []string `yaml:"seed_urls"`       // Additional URLs to start crawling from.

	// UserAgent field allows specifying a custom User-Agent header.
	UserAgent string `yaml:"user_agent"`

	// Output configuration settings.
	Output OutputConfig `yaml:"output"`

	// Authentication configuration settings.
	Authentication struct {
		Enabled           bool   `yaml:"enabled"`             // Enable authentication.
		LoginURL          string `yaml:"login_url"`           // URL for dynamic login.
		LoginMethod       string `yaml:"login_method"`        // HTTP method for login (e.g., POST).
		LoginData         string `yaml:"login_data"`          // POST data for login form.
		LoginCheckKeyword string `yaml:"login_check_keyword"` // Keyword to verify successful login.

		// Cookie field for static cookie-based authentication.
		Cookie string `yaml:"cookie"`
		// Headers map for static header-based authentication (e.g., Authorization tokens).
		Headers map[string]string `yaml:"headers"`
		// ScanIDOR is the authenticated user's ID for IDOR scanning.
		ScanIDOR int `yaml:"scan_idor"`

		// Fields for backward compatibility with old config format.
		Type       string `yaml:"type,omitempty"`       // Old authentication type (e.g., "header").
		HeaderName string `yaml:"header_name,omitempty"` // Old header name.
		Value      string `yaml:"value,omitempty"`      // Old header value.
	} `yaml:"authentication"`
}

// LoadConfig reads the configuration from a YAML file and returns a Config struct.
// It sets default values if the file does not exist or is empty.
func LoadConfig(filePath string) (*Config, error) {
	// Set default configuration values.
	config := &Config{
		Output: OutputConfig{
			Format:  "text",
			Verbose: false,
		},
	}

	// Read the YAML file.
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		// If the file does not exist, return default config without error.
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, err // Return error for other file reading issues.
	}

	// Unmarshal YAML data into the Config struct.
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err // Return error if YAML unmarshaling fails.
	}

	return config, nil // Return the loaded configuration.
}
