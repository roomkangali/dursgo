package ssrf

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
	"strings"
)

// SSRFScanner implements the Scanner interface for Server-Side Request Forgery.
type SSRFScanner struct{}

// NewSSRFScanner creates a new instance of SSRFScanner.
func NewSSRFScanner() *SSRFScanner {
	return &SSRFScanner{}
}

// Name returns the scanner's name.
func (s *SSRFScanner) Name() string {
	return "Server-Side Request Forgery (SSRF) Scanner"
}

// Scan performs a scan for Server-Side Request Forgery (SSRF) vulnerabilities.
// It iterates through parameters in GET and POST requests, injecting SSRF payloads
// and checking for keywords in the response that indicate a successful SSRF attack.
func (s *SSRFScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	log.Debug("Starting SSRF scan for %s %s...", req.Method, req.URL)

	if contains(req.ParamLocations, "query") || contains(req.ParamLocations, "body") {
		for _, paramName := range req.ParamNames {
			for _, ssrfPayload := range payloads.SSRFPayloads {
				testURL, reqBody, httpMethod := buildRequest(req, paramName, ssrfPayload)

				httpRequest, reqErr := http.NewRequest(httpMethod, testURL, reqBody)
				if reqErr != nil {
					continue
				}
				if httpMethod == "POST" {
					httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if strings.Contains(ssrfPayload, "metadata.google.internal") {
					httpRequest.Header.Set("Metadata-Flavor", "Google")
				}

				originalCheckRedirectFunc := client.TemporarilyDisableRedirects()
				resp, err := client.Do(httpRequest)
				client.RestoreRedirects(originalCheckRedirectFunc)

				if resp != nil {
					defer resp.Body.Close()
				}
				if err != nil {
					if resp == nil {
						continue
					}
				}
				if resp == nil {
					continue
				}

				bodyBytes, _ := io.ReadAll(resp.Body)
				responseBody := string(bodyBytes)

				for _, keyword := range payloads.SSRFResponseKeywords {
					if strings.Contains(strings.ToLower(responseBody), strings.ToLower(keyword)) {
						details := fmt.Sprintf("Response from target URL (%s, Status: %d) contained keyword '%s' when testing SSRF payload '%s'.",
							resp.Request.URL.String(), resp.StatusCode, keyword, ssrfPayload)
						findings = append(findings, scanner.VulnerabilityResult{
							VulnerabilityType: "Server-Side Request Forgery (SSRF)",
							URL:               testURL,
							Parameter:         paramName,
							Payload:           ssrfPayload,
							Location:          "body", // optional: can be replaced with getParamLocation(req) for more accuracy
							Details:           details,
							Severity:          "high",
							Evidence:          ssrfPayload,
							Remediation:       "Whitelist allowed URLs, avoid user-controlled input in server-side requests, and implement SSRF protection libraries or firewalls.",
							ScannerName:       "ssrf",
						})

						goto nextSSRFParam
					}
				}
			}
		nextSSRFParam:
		}
	}
	return findings, nil
}

// buildRequest constructs an HTTP request with the SSRF payload.
// It handles both GET and POST requests, injecting the payload into the appropriate parameter.
func buildRequest(req crawler.ParameterizedRequest, paramName, payload string) (string, io.Reader, string) {
	if req.Method == "GET" {
		// --- FIX STARTS HERE ---
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			// If the original URL from the crawler is broken, return an empty string.
			// This will cause http.NewRequest to fail safely in the Scan function, and this test will be skipped.
			return "", nil, "GET"
		}
		// --- END FIX ---

		queryParams := parsedURL.Query()
		queryParams.Set(paramName, payload)
		parsedURL.RawQuery = queryParams.Encode()
		return parsedURL.String(), nil, "GET"
	}

	// The POST part does not have a URL parsing risk, so no changes are needed.
	formData, _ := url.ParseQuery(req.FormPostData)
	formData.Set(paramName, payload)
	return req.URL, strings.NewReader(formData.Encode()), "POST"
}

// contains checks if a string is present in a slice of strings.
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
