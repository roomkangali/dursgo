package lfi

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agext/levenshtein"
)

// LFIScanner implements the Scanner interface for Local File Inclusion.
type LFIScanner struct{}

// NewLFIScanner creates a new instance of LFIScanner.
func NewLFIScanner() *LFIScanner {
	return &LFIScanner{}
}

// Name returns the name of the scanner.
func (s *LFIScanner) Name() string {
	return "Advanced Local File Inclusion Scanner"
}

// Scan performs a scan for Local File Inclusion (LFI) vulnerabilities.
// It identifies potential LFI parameters and tests them with various path traversal payloads.
func (s *LFIScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	rand.Seed(time.Now().UnixNano())

	if req.Method != "GET" {
		return nil, nil
	}

ParamLoop:
	for _, paramName := range req.ParamNames {
		if !isPotentialLFIParam(paramName) {
			continue
		}

		log.Debug("LFI: Testing parameter '%s' in %s", paramName, req.URL)

		// Send a baseline request once per parameter
		baselineValue := fmt.Sprintf("dursgoprobing%d", rand.Intn(1e9))
		baselineResp, err := sendLFIRequest(req, client, paramName, baselineValue)
		if err != nil {
			continue
		}
		defer baselineResp.Body.Close()
		baselineBodyBytes, _ := io.ReadAll(baselineResp.Body)
		baselineBody := string(baselineBodyBytes)

		for _, lfiPayload := range payloads.LFIPathTraversalPayloads {
			vuln, found := s.executeTest(req, client, log, paramName, lfiPayload, baselineBody)
			if found {
				findings = append(findings, vuln)
				continue ParamLoop // Found, continue to the next parameter
			}
		}
	}
	return findings, nil
}

// executeTest performs a single LFI test with a given payload.
// It uses a three-step detection logic:
// 1. The response must be different from the baseline.
// 2. The response must contain a keyword indicating a successful LFI.
// 3. The keyword must not be a reflection of the payload itself.
func (s *LFIScanner) executeTest(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName, lfiPayload, baselineBody string) (scanner.VulnerabilityResult, bool) {
	testResp, err := sendLFIRequest(req, client, paramName, lfiPayload)
	if err != nil {
		return scanner.VulnerabilityResult{}, false
	}
	defer testResp.Body.Close()

	if testResp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(testResp.Body)
		body := string(bodyBytes)

		// Three-Step Detection Logic
		// 1. Response must be different from the baseline
		if !isDifferentResponse(baselineBody, body) {
			return scanner.VulnerabilityResult{}, false
		}

		for _, keyword := range payloads.LFIKeywords {
			// 2. Response must contain a keyword
			if strings.Contains(body, keyword) {
				// 3. Keyword must not be a reflection of the payload
				if !strings.Contains(lfiPayload, keyword) {
					log.Success("LFI: Found keyword '%s' for payload '%s' in param '%s'", keyword, lfiPayload, paramName)
					parsedURL, _ := url.Parse(req.URL)
					query := parsedURL.Query()
					query.Set(paramName, lfiPayload)
					parsedURL.RawQuery = query.Encode()
					testURL := parsedURL.String()

					details := fmt.Sprintf("LFI payload '%s' returned known file content matching keyword: '%s'", lfiPayload, keyword)
					vuln := scanner.VulnerabilityResult{
						VulnerabilityType: "Local File Inclusion/Path Traversal",
						URL:               testURL,
						Parameter:         paramName,
						Payload:           lfiPayload,
						Location:          "query",
						Details:           details,
						Severity:          "High",
						Evidence:          keyword,
						Remediation:       "Validate and sanitize all user input. Implement an allow-list of files that can be included and disallow path traversal characters.",
						ScannerName:       s.Name(),
					}
					return vuln, true
				}
			}
		}
	}
	return scanner.VulnerabilityResult{}, false
}

// sendLFIRequest sends an HTTP GET request with the LFI payload.
func sendLFIRequest(req crawler.ParameterizedRequest, client *httpclient.Client, paramName, value string) (*http.Response, error) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}
	query := parsedURL.Query()
	query.Set(paramName, value)
	parsedURL.RawQuery = query.Encode()
	testURL := parsedURL.String()

	return client.Get(testURL)
}

// isPotentialLFIParam checks if a parameter name is commonly associated with LFI vulnerabilities.
func isPotentialLFIParam(p string) bool {
	l := strings.ToLower(p)
	return strings.Contains(l, "file") || l == "filename" || strings.Contains(l, "page") ||
		strings.Contains(l, "path") || strings.Contains(l, "include") ||
		strings.Contains(l, "doc") || strings.Contains(l, "document") ||
		strings.Contains(l, "dir") || strings.Contains(l, "view") ||
		strings.Contains(l, "template") || strings.Contains(l, "name") ||
		strings.Contains(l, "country") // Added for lab
}

// isDifferentResponse checks if two responses are sufficiently different using Levenshtein distance.
func isDifferentResponse(original, modified string) bool {
	distance := levenshtein.Distance(original, modified, nil)
	maxLen := len(original)
	if len(modified) > maxLen {
		maxLen = len(modified)
	}
	if maxLen == 0 {
		return false
	}
	similarity := 1.0 - (float64(distance) / float64(maxLen))
	return similarity < 0.95
}
