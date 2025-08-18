package bola

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// numericIDRegex is a regex to find numeric IDs at the end of a URL path (last numeric segment).
var numericIDRegex = regexp.MustCompile(`/([0-9]+)(?:$|[/?#])`)

// publicAPIPrefixes are common public paths that should be enumerable without authorization (skipped).
var publicAPIPrefixes = []string{
	"/wp-json/", "/api/", "/feeds", "/rss", "/atom", "/sitemap", "/openapi", "/.well-known/",
}

// sensitiveResourceKeywords are resource keywords that are typically sensitive/user-scoped.
var sensitiveResourceKeywords = []string{
	"user", "account", "profile", "member", "admin", "customer", "order", "cart", "token", "session", "credentials",
}

// BOLAScanner implements the Scanner interface for Broken Object Level Authorization.
// It identifies BOLA vulnerabilities by attempting to access objects with modified IDs.
type BOLAScanner struct {
	mu          sync.Mutex
	testedPaths map[string]bool
}

// NewBOLAScanner creates a new instance.
func NewBOLAScanner() *BOLAScanner {
	return &BOLAScanner{
		testedPaths: make(map[string]bool),
	}
}

// Name returns the scanner's name.
func (s *BOLAScanner) Name() string {
	return "Broken Object Level Authorization (BOLA) Scanner"
}

// Scan performs the new, more flexible BOLA scan logic.
// This function identifies potential BOLA vulnerabilities by manipulating numeric IDs
// in URL paths and observing the application's response. It skips public API paths
// and non-sensitive resources to focus on relevant targets.
func (s *BOLAScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	// --- IMPROVEMENT 1: Extract Path and run more flexible Regex ---
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, nil
	}
	// Use full URL (path + query) for regex to handle /1?token=...
	// Regex modified to look for numbers before end of string OR before a question mark.
	matches := numericIDRegex.FindStringSubmatch(req.URL)
	if len(matches) < 2 {
		return nil, nil
	}

	originalIDStr := matches[1]
	originalID, _ := strconv.Atoi(originalIDStr)

	// --- IMPROVEMENT 2: Remove all overly strict UserID checks ---
	// The scanner will now test any ID it finds.

	// Use generic path without ID for testing and deduplication
	// This will replace "/1" from the path, even if there's a query string.
	pathOnly := parsedURL.Path
	genericPath := strings.TrimSuffix(pathOnly, "/"+originalIDStr)

	// --- IMPROVEMENT 3: Skip if path is public API or not sensitive ---
	for _, pub := range publicAPIPrefixes {
		if strings.Contains(strings.ToLower(genericPath), pub) {
			return nil, nil // Do not flag public enumerations
		}
	}
	if !isSensitiveResource(genericPath) {
		return nil, nil // Not indicated as a sensitive per-user object
	}

	s.mu.Lock()
	if s.testedPaths[genericPath] {
		s.mu.Unlock()
		return nil, nil
	}
	s.testedPaths[genericPath] = true
	s.mu.Unlock()

	log.Debug("BOLA: Testing endpoint: %s (Baseline ID: %d)", genericPath, originalID)

	// Get baseline with the original URL provided by the crawler.
	baselineBody, err := sendRequestAndGetBody(req.URL, client)
	if err != nil || containsNegativeKeyword(baselineBody) {
		log.Debug("BOLA: Could not get a valid baseline response for ID %d.", originalID)
		return nil, nil
	}

	// Test several neighboring IDs (±1) and one small random ID.
	randIDs := []int{originalID + 1, originalID - 1, 2}
	idsToTest := make([]int, 0, len(randIDs))
	for _, id := range randIDs {
		if id > 0 {
			idsToTest = append(idsToTest, id)
		}
	}

	for _, testID := range idsToTest {
		if testID <= 0 || testID == originalID {
			continue
		}

		// Reconstruct the test URL by replacing the ID in the path.
		testPath := genericPath + "/" + strconv.Itoa(testID)
		testURL := parsedURL.Scheme + "://" + parsedURL.Host + testPath

		log.Debug("BOLA: Testing with URL: %s", testURL)
		testBody, err := sendRequestAndGetBody(testURL, client)
		if err != nil {
			continue
		}

		if !containsNegativeKeyword(testBody) && testBody != baselineBody {
			details := fmt.Sprintf("Successfully accessed a different object by changing the path parameter from '%d' to '%d'.", originalID, testID)

			return []scanner.VulnerabilityResult{{
				VulnerabilityType: "Broken Object Level Authorization (BOLA)",
				URL:               testURL,
				Parameter:         fmt.Sprintf("Path Parameter (Original ID: %d)", originalID),
				Payload:           strconv.Itoa(testID),
				Location:          "path",
				Details:           details,
				Severity:          "High",
				Evidence:          fmt.Sprintf("Accessed object ID %d after originally accessing %d", testID, originalID),
				Remediation:       "Implement proper authorization checks to ensure users can only access resources they own. Verify ownership of the resource ID in the URL path against the session User ID.",
				ScannerName:       s.Name(),
			}}, nil
		}
	}

	return nil, nil
}

// --- Helper Functions ---
// containsNegativeKeyword checks if the response body contains any negative keywords.
// These keywords typically indicate an error or an unauthorized access attempt.
func containsNegativeKeyword(b string) bool {
	l := strings.ToLower(b)
	for _, k := range payloads.IDORNegativeKeywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// isSensitiveResource checks if the given path is considered a sensitive resource.
// It compares the path against a list of predefined sensitive resource keywords.
func isSensitiveResource(p string) bool {
	lower := strings.ToLower(p)
	for _, kw := range sensitiveResourceKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// sendRequest sends an HTTP GET request to the target URL.
// It's a helper function to encapsulate the HTTP request creation and execution.
func sendRequest(client *httpclient.Client, targetURL string) (*http.Response, error) {
	httpReq, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(httpReq)
}

// sendRequestAndGetBody sends an HTTP GET request and returns the response body as a string.
// It handles error checking for the request and response, and reads the entire response body.
func sendRequestAndGetBody(targetURL string, client *httpclient.Client) (string, error) {
	resp, err := sendRequest(client, targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}
