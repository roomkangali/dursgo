package exposed

import (
	"github.com/roomkangali/dursgo/internal/crawler"
	"github.com/roomkangali/dursgo/internal/httpclient"
	"github.com/roomkangali/dursgo/internal/logger"
	"github.com/roomkangali/dursgo/internal/payloads"
	"github.com/roomkangali/dursgo/internal/scanner"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ExposedScanner implements the Scanner interface for detecting exposed files and directory listings.
type ExposedScanner struct {
	mu          sync.Mutex
	dirsScanned map[string]bool // Changed from hostsScanned to scan per-directory
}

// NewExposedScanner creates a new instance of ExposedScanner.
func NewExposedScanner() *ExposedScanner {
	return &ExposedScanner{dirsScanned: make(map[string]bool)}
}

// Name returns the scanner's name.
func (s *ExposedScanner) Name() string {
	return "Directory Listing / Exposed Files Scanner"
}

// Scan performs a scan for exposed files and directory listings.
// It now scans on a per-directory basis and includes baseline content checking to reduce false positives.
func (s *ExposedScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}

	// Determine the base directory for the scan. If the path has an extension, use its parent directory.
	baseDir := parsedURL.Path
	if !strings.HasSuffix(baseDir, "/") {
		lastSlash := strings.LastIndex(baseDir, "/")
		if lastSlash != -1 {
			baseDir = baseDir[:lastSlash+1]
		} else {
			baseDir = "/" // Fallback to root if no slash is found
		}
	}
	dirScanKey := parsedURL.Scheme + "://" + parsedURL.Host + baseDir

	s.mu.Lock()
	if s.dirsScanned[dirScanKey] {
		s.mu.Unlock()
		return nil, nil // Skip if this directory has already been scanned.
	}
	s.dirsScanned[dirScanKey] = true
	s.mu.Unlock()

	log.Info("Running Smart Exposed Items scan for directory: %s", dirScanKey)

	// --- False Positive Reduction: Baseline Check ---
	// Fetch a known non-existent file to get the "not found" response body.
	// This helps filter out servers that return 200 OK for 404 pages.
	baseURL, _ := url.Parse(dirScanKey)
	nonExistentURL := baseURL.ResolveReference(&url.URL{Path: "dursgo-not-found-test-12345.html"})
	respNotFound, errNotFound := client.Get(nonExistentURL.String())
	var notFoundBody string
	if errNotFound == nil && respNotFound.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(respNotFound.Body)
		notFoundBody = string(bodyBytes)
		respNotFound.Body.Close()
		log.Debug("ExposedScanner: Baselined 'not found' response for %s (body length: %d)", dirScanKey, len(notFoundBody))
	} else if respNotFound != nil && respNotFound.Body != nil {
		respNotFound.Body.Close()
	}
	// --- End Baseline Check ---

	pathsToTest := make(map[string]bool)

	// 1. Add all generic paths
	for _, path := range payloads.ExposedGenericPaths {
		pathsToTest[path] = true
	}

	// 2. Add specific paths based on fingerprint results
	if opts.Fingerprint != nil {
		for tech, paths := range payloads.TechSpecificPaths {
			for detectedTech := range opts.Fingerprint {
				if strings.Contains(strings.ToLower(detectedTech), tech) {
					log.Debug("ExposedScanner: Technology '%s' detected, adding %d specific paths to check.", tech, len(paths))
					for _, path := range paths {
						pathsToTest[path] = true
					}
					break
				}
			}
		}
	}

	for path := range pathsToTest {
		// Correctly join the base directory URL with the payload path.
		baseURL, _ := url.Parse(dirScanKey)
		payloadPath, _ := url.Parse(path)
		testURL := baseURL.ResolveReference(payloadPath)
		testURLStr := testURL.String()

		log.Debug("ExposedScanner: Testing path: %s", testURLStr)
		resp, err := client.Get(testURLStr)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			responseBody := string(bodyBytes)
			resp.Body.Close() // Close body immediately after reading

			// False Positive Check: Only report if the content is different from the "not found" baseline.
			if notFoundBody != "" && responseBody == notFoundBody {
				log.Debug("ExposedScanner: Skipping %s, content matches 'not found' baseline.", testURLStr)
				continue
			}

			isListing := false
			if strings.HasSuffix(path, "/") {
				for _, keyword := range payloads.DirListingKeywords {
					if strings.Contains(responseBody, keyword) {
						isListing = true
						break
					}
				}
			}

			if isListing {
				details := fmt.Sprintf("Directory %s is accessible and shows a file listing.", testURLStr)
				findings = append(findings, scanner.VulnerabilityResult{
					VulnerabilityType: "Directory Listing",
					URL:               testURLStr,
					Details:           details,
					Severity:          "Low",
					Evidence:          "Common directory listing keywords found in response body.",
					Remediation:       "Disable directory listing on the server or configure access controls properly.",
					ScannerName:       "exposed",
				})
			} else {
				details := fmt.Sprintf("Sensitive file/path %s is publicly accessible (Status: 200).", testURLStr)
				findings = append(findings, scanner.VulnerabilityResult{
					VulnerabilityType: "Exposed Sensitive File",
					URL:               testURLStr,
					Details:           details,
					Severity:          "Low",
					Evidence:          "Resource responded with 200 OK and content was served.",
					Remediation:       "Restrict public access to sensitive files and validate file exposure using access control.",
					ScannerName:       "exposed",
				})
			}
		} else if resp.Body != nil {
			resp.Body.Close()
		}
	}

	return findings, nil
}
