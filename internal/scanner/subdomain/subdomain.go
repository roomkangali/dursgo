package subdomain

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"golang.org/x/net/publicsuffix"
)

// SubdomainScanner implements the Scanner interface for discovering active subdomains.
type SubdomainScanner struct {
	mu           sync.Mutex
	hostsScanned map[string]bool
}

// NewSubdomainScanner creates a new instance of SubdomainScanner.
func NewSubdomainScanner() *SubdomainScanner {
	return &SubdomainScanner{
		hostsScanned: make(map[string]bool),
	}
}

// Name returns the scanner's name.
func (s *SubdomainScanner) Name() string {
	return "Subdomain Scanner"
}

// Scan discovers and validates subdomains for the given target.
func (s *SubdomainScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("could not parse URL: %v", err)
	}

	// Extract the registrable domain (e.g., example.com from sub.example.com)
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Host)
	if err != nil {
		return nil, fmt.Errorf("could not determine base domain for %s: %v", parsedURL.Host, err)
	}

	// --- Prevent Rescanning ---
	s.mu.Lock()
	if s.hostsScanned[baseDomain] {
		s.mu.Unlock()
		return nil, nil // This base domain has already been scanned in this session.
	}
	s.hostsScanned[baseDomain] = true
	s.mu.Unlock()
	// --- End Prevention ---

	log.Info("Starting subdomain scan for base domain: %s", baseDomain)
	foundSubdomains := make(map[string]bool)

	// --- 1. Passive Discovery (using Subfinder library) ---
	log.Debug("SubdomainScanner: Starting passive discovery via Subfinder for %s", baseDomain)
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true, // Suppress subfinder's own output
		// ProviderConfig: "provider-config.yaml", // Future improvement: allow user to configure API keys
	}

	subfinderRunner, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Warn("SubdomainScanner: Failed to create subfinder runner: %v", err)
	} else {
		output := &bytes.Buffer{}
		// Correctly call the function and handle its return values
		_, err = subfinderRunner.EnumerateSingleDomainWithCtx(context.Background(), baseDomain, []io.Writer{output})
		if err != nil {
			log.Warn("SubdomainScanner: Subfinder enumeration failed: %v", err)
		} else {
			subdomains := strings.Split(output.String(), "\n")
			for _, sub := range subdomains {
				cleanSub := strings.TrimSpace(sub)
				if cleanSub != "" {
					foundSubdomains[cleanSub] = true
				}
			}
		}
	}
	log.Info("SubdomainScanner: Passive discovery found %d potential subdomains.", len(foundSubdomains))

	// --- 2. Active Discovery (Brute-force) ---
	log.Debug("SubdomainScanner: Starting active discovery (brute-force) for %s", baseDomain)
	for _, word := range payloads.SubdomainWordlist {
		subdomain := fmt.Sprintf("%s.%s", word, baseDomain)
		foundSubdomains[subdomain] = true
	}
	log.Info("SubdomainScanner: Total unique potential subdomains to validate: %d", len(foundSubdomains))

	// --- 3. Wildcard Detection ---
	wildcardDetected := false
	var wildcardBodyHash string
	// Generate a highly unlikely subdomain for wildcard testing
	wildcardTestDomain := fmt.Sprintf("thisshouldnotexist-%d.%s", time.Now().UnixNano(), baseDomain)
	wildcardResp, err := client.Get("http://" + wildcardTestDomain)
	if err == nil && wildcardResp != nil {
		if wildcardResp.Body != nil {
			defer wildcardResp.Body.Close()
			bodyBytes, _ := io.ReadAll(wildcardResp.Body)
			// Only consider it a wildcard if there's content
			if len(bodyBytes) > 0 {
				wildcardDetected = true
				hash := sha256.Sum256(bodyBytes)
				wildcardBodyHash = hex.EncodeToString(hash[:])
				log.Info("SubdomainScanner: Wildcard DNS detected for *.%s. Baselining response.", baseDomain)
			}
		}
	}

	// --- 4. Validation ---
	var wg sync.WaitGroup
	var findingsMu sync.Mutex
	jobs := make(chan string, len(foundSubdomains))

	numWorkers := opts.Concurrency
	if numWorkers == 0 {
		numWorkers = 10
	}
	if numWorkers > 100 {
		numWorkers = 100 // Cap workers for subdomain validation
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				var activeURL string
				var statusCode int

				protocols := []string{"https"}
				if parsedURL.Scheme == "http" {
					protocols = []string{"http", "https"}
				}

				for _, proto := range protocols {
					targetURL := fmt.Sprintf("%s://%s", proto, subdomain)
					// Use a temporary client with a shorter timeout for validation
					tempClient := httpclient.NewClient(log, httpclient.ClientOptions{Timeout: 10 * time.Second, UserAgent: os.Getenv("USER_AGENT")})
					resp, err := tempClient.Get(targetURL)

					if err == nil && resp != nil {
						if resp.Body != nil {
							defer resp.Body.Close()
							if wildcardDetected {
								bodyBytes, _ := io.ReadAll(resp.Body)
								hash := sha256.Sum256(bodyBytes)
								currentHash := hex.EncodeToString(hash[:])
								if currentHash == wildcardBodyHash {
									continue
								}
							}
						}
						activeURL = targetURL
						statusCode = resp.StatusCode
						break
					}
				}

				if activeURL != "" {
					log.Success("SubdomainScanner: Found active subdomain: %s (Status: %d)", activeURL, statusCode)
					findingsMu.Lock()
					findings = append(findings, scanner.VulnerabilityResult{
						VulnerabilityType: "Active Subdomain Discovered",
						URL:               activeURL,
						Details:           fmt.Sprintf("Subdomain '%s' is active and responded with status code %d.", subdomain, statusCode),
						Severity:          "Info",
						ScannerName:       "subdomain",
					})
					findingsMu.Unlock()
				}
			}
		}()
	}

	for sub := range foundSubdomains {
		jobs <- sub
	}
	close(jobs)
	wg.Wait()

	return findings, nil
}
