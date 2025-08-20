package securityheaders

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// SecurityHeadersScanner implements the Scanner interface for checking security headers.
type SecurityHeadersScanner struct {
	mu           sync.Mutex
	hostsScanned map[string]bool
}

// NewSecurityHeadersScanner creates a new instance of SecurityHeadersScanner.
func NewSecurityHeadersScanner() *SecurityHeadersScanner {
	return &SecurityHeadersScanner{hostsScanned: make(map[string]bool)}
}

// Name returns the scanner's name.
func (s *SecurityHeadersScanner) Name() string {
	return "Security Headers Scanner"
}

// isWordPressSite checks if the response indicates a WordPress site.
// It checks for common WordPress headers and body content.
func isWordPressSite(resp *http.Response) bool {
	// Check generator header
	if generator := resp.Header.Get("X-Generator"); generator != "" && strings.Contains(strings.ToLower(generator), "wordpress") {
		return true
	}

	// Check X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" && strings.Contains(strings.ToLower(poweredBy), "wordpress") {
		return true
	}

	// Check meta generator in body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// Reset body for further reading
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	
	bodyStr := strings.ToLower(string(bodyBytes))
	
	// Check for several WordPress indicators
	wordPressIndicators := []string{
		"generator name=\"wordpress\"",
		"wp-content",
		"wp-includes",
		"wp-json",
		"wp-admin",
		"wp-embed",
	}
	
	for _, indicator := range wordPressIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}
	
	return false
}

// isHTMLResponse checks if the response is likely HTML content
func isHTMLResponse(resp *http.Response, log *logger.Logger) bool {
	// Check Content-Type header first
	contentType := resp.Header.Get("Content-Type")
	path := strings.ToLower(resp.Request.URL.Path)
	
	// Debug log
	log.Debug("Checking if HTML - Path: %s, Content-Type: %s", path, contentType)

	// Always check HTML content directly first
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset body for actual reading
	
	// Check for common HTML indicators in the first few KB
	bodyStart := strings.ToLower(string(bodyBytes[:min(4096, len(bodyBytes))]))
	_ = strings.Contains(bodyStart, "<!doctype html>") || 
			  strings.Contains(bodyStart, "<html") ||
			  strings.Contains(bodyStart, "<head>") ||
			  strings.Contains(bodyStart, "<body>")

	// Check for common WordPress paths or if it's a WordPress site
	if path == "/" || strings.HasSuffix(path, ".php") || strings.Contains(path, "wp-") || isWordPressSite(resp) {
		log.Debug("WordPress path or site detected: %s", path)
		return true
	}

	// If no content type, check URL extension
	if contentType == "" {
		u, err := url.Parse(resp.Request.URL.String())
		if err != nil {
			log.Error("Error parsing URL: %v", err)
			return false
		}
		ext := ""
		if dot := strings.LastIndex(u.Path, "."); dot != -1 && dot < len(u.Path)-1 {
			ext = strings.ToLower(u.Path[dot+1:])
		}
		// Common web extensions
		htmlExtensions := map[string]bool{
			"": true, "html": true, "htm": true, "php": true, 
			"aspx": true, "jsp": true, "do": true, "action": true,
		}
		if htmlExtensions[ext] {
			log.Debug("HTML extension detected: %s", ext)
			return true
		}
		// If no extension, assume it's HTML for the root or common paths
		isRootPath := ext == "" && (u.Path == "" || u.Path == "/" || !strings.Contains(u.Path, "."))
		if isRootPath {
			log.Debug("Root path detected: %s", u.Path)
		}
		return isRootPath
	}

	// Handle Cloudflare and other content types
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "x-httpd-php") || 
	   strings.Contains(contentType, "x-httpd-fastphp") ||
	   strings.Contains(contentType, "text/html") ||
	   strings.Contains(contentType, "xhtml+xml") {
		log.Debug("HTML content type detected: %s", contentType)
		return true
	}

	// If we get here, try to parse the media type
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Error("Error parsing media type: %v", err)
		// Be permissive if we can't parse the content type
		return true
	}

	// Common HTML content types
	htmlTypes := map[string]bool{
		"text/html":               true,
		"application/xhtml+xml":   true,
		"application/x-httpd-php": true,
	}

	isHTML := htmlTypes[mediaType]
	log.Debug("Media type check - Type: %s, IsHTML: %v", mediaType, isHTML)
	return isHTML
}

// Scan performs a security headers scan on the given request's host.
// It checks for the presence and configuration of various security headers,
// considering the context of the response (e.g., HTML, sensitive content).
func (s *SecurityHeadersScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult

	parsedURL, _ := url.Parse(req.URL)
	hostKey := parsedURL.Scheme + "://" + parsedURL.Host

	s.mu.Lock()
	if s.hostsScanned[hostKey] {
		s.mu.Unlock()
		return nil, nil
	}
	s.hostsScanned[hostKey] = true
	s.mu.Unlock()

	log.Debug("Running Security Headers check on: %s", req.URL)

	resp, err := client.Get(req.URL)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, nil
	}
	defer resp.Body.Close()

	// Only analyze successful responses (2xx status codes).
	// This prevents false positives on 404 pages or server errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Debug("Skipping security headers check for non-successful status code %d on %s", resp.StatusCode, req.URL)
		return nil, nil
	}

	// Reset response body for further processing
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Check if this is an HTML response
	isHTML := isHTMLResponse(resp, log)
	isSensitive := isSensitiveContent(resp)

	// Get all response headers in lowercase for case-insensitive checks
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = v[0] // Take the first value if multiple
	}

	for _, headerCheck := range payloads.SecurityHeaderChecks {
		headerName := strings.ToLower(headerCheck.Name)
		headerValue, headerExists := headers[headerName]

		// Special handling for CSP: accept 'report-only' header as present.
		if headerName == "content-security-policy" {
			if _, reportOnlyExists := headers["content-security-policy-report-only"]; reportOnlyExists {
				headerExists = true
			}
		}

		// Skip if header is only for HTTPS and we're not on HTTPS
		if headerCheck.CheckOnHTTPSOnly && parsedURL.Scheme != "https" {
			continue
		}

		// Context-aware checks for specific headers
		switch headerName {
		case "content-security-policy":
			// Skip CSP for non-HTML content
			if !isHTML {
				continue
			}
		case "x-frame-options":
			// Skip if CSP with frame-ancestors is present (modern approach)
			if csp, hasCSP := headers["content-security-policy"]; hasCSP && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
				continue
			}
		case "cache-control":
			// Only require Cache-Control for sensitive content
			if !isSensitive {
				continue
			}
		}

		if !headerExists {
			findings = append(findings, scanner.VulnerabilityResult{
				VulnerabilityType: "Missing Security Header",
				URL:               req.URL,
				Details: fmt.Sprintf(
					"Header '%s' not found. %s",
					headerCheck.Name, headerCheck.Description,
				),
				Payload:     headerCheck.Remediation,
				Severity:    headerCheck.Severity,
				Evidence:    fmt.Sprintf("Header '%s' is missing in response headers.", headerCheck.Name),
				Remediation: headerCheck.Remediation,
				ScannerName: "securityheaders",
			})
		} else if headerCheck.RecommendedValue != "" && !strings.Contains(strings.ToLower(headerValue), strings.ToLower(headerCheck.RecommendedValue)) {
			// For misconfigured headers, only report if the value is clearly insecure
			if isInsecureHeaderValue(headerName, headerValue) {
				findings = append(findings, scanner.VulnerabilityResult{
					VulnerabilityType: "Misconfigured Security Header",
					URL:               req.URL,
					Details: fmt.Sprintf(
						"Header '%s' found with potentially insecure value '%s'. %s",
						headerCheck.Name, headerValue, headerCheck.Description,
					),
					Payload:     headerCheck.Remediation,
					Severity:    headerCheck.Severity,
					Evidence:    fmt.Sprintf("Found header '%s: %s', which may be misconfigured.", headerCheck.Name, headerValue),
					Remediation: headerCheck.Remediation,
					ScannerName: "securityheaders",
				})
			}
		}
	}

	return findings, nil
}

// isSensitiveContent checks if the response appears to contain sensitive content.
// It checks for common sensitive paths and error response codes.
func isSensitiveContent(resp *http.Response) bool {
	// Check common sensitive paths
	sensitivePaths := []string{
		"/login", 
		"/admin", 
		"/dashboard",
		"/account",
		"/settings",
		"/profile",
	}

	path := strings.ToLower(resp.Request.URL.Path)
	for _, p := range sensitivePaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	// Check response code
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return true
	}

	return false
}

// isInsecureHeaderValue checks if a header value is considered insecure.
// It contains logic to identify common misconfigurations for various security headers.
func isInsecureHeaderValue(headerName, value string) bool {
	switch strings.ToLower(headerName) {
	case "x-frame-options":
		return value == "" || !strings.EqualFold(value, "DENY") && !strings.EqualFold(value, "SAMEORIGIN")
	case "x-content-type-options":
		return !strings.EqualFold(value, "nosniff")
	case "x-xss-protection":
		// "0" is a valid way to disable the header, especially with a strong CSP.
		// "1; mode=block" is the strongest setting. Other values are less secure.
		val := strings.ToLower(value)
		if val == "0" || strings.Contains(val, "1; mode=block") {
			return false
		}
		return true
	case "strict-transport-security":
		return value == "" || !strings.Contains(strings.ToLower(value), "max-age=")
	case "content-security-policy":
		// Check for obviously insecure CSP
		value = strings.ToLower(value)
		if strings.Contains(value, "unsafe-inline") || 
		   strings.Contains(value, "unsafe-eval") ||
		   strings.Contains(value, "*.") ||
		   strings.Contains(value, "http:") ||
		   strings.Contains(value, "https://*") {
			return true
		}
	}
	return false
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
