package openredirect

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
)

// OpenRedirectScanner implements the Scanner interface for Open Redirect vulnerabilities.
type OpenRedirectScanner struct{}

// NewOpenRedirectScanner creates a new instance of OpenRedirectScanner.
func NewOpenRedirectScanner() *OpenRedirectScanner {
	return &OpenRedirectScanner{}
}

// Name returns the scanner's name.
func (s *OpenRedirectScanner) Name() string {
	return "Open Redirect Scanner"
}

// Scan performs a scan for Open Redirect vulnerabilities.
// It injects various redirect payloads into parameters and checks if the server
// responds with a redirect to an external domain.
func (s *OpenRedirectScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	log.Debug("Starting Open Redirect scan for %s %s...", req.Method, req.URL)

	originalRequestParsedURL, errParseOrig := url.Parse(req.URL)
	if errParseOrig != nil {
		return nil, errParseOrig
	}
	originalHost := originalRequestParsedURL.Host

	// --- Path-Based Open Redirect Scan ---
	for _, orPayload := range payloads.OpenRedirectPayloads {
		// We only test for payloads that start with // or \\, as these can manipulate the host
		if strings.HasPrefix(orPayload, "//") || strings.HasPrefix(orPayload, "\\\\") {
			parsedURL, err := url.Parse(req.URL)
			if err != nil {
				continue // Skip malformed URLs from crawler
			}

			// Construct test URL by combining scheme, host, and payload.
			// e.g., https://example.com + //evil.com -> https://example.com//evil.com
			// This specifically tests for path-based redirects at the root.
			testURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, orPayload)

			httpRequest, reqErr := http.NewRequest("GET", testURL, nil)
			if reqErr != nil {
				continue
			}

			originalCheckRedirectFunc := client.TemporarilyDisableRedirects()
			resp, err := client.Do(httpRequest)
			client.RestoreRedirects(originalCheckRedirectFunc)

			if resp != nil {
				defer resp.Body.Close()
			}

			if err != nil {
				if urlErr, ok := err.(*url.Error); !ok || urlErr.Err != http.ErrUseLastResponse {
					continue // Skip non-redirect errors
				}
			}
			if resp == nil {
				continue
			}

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				locationHeader := resp.Header.Get("Location")
				if locationHeader != "" {
					redirectURL, parseErr := originalRequestParsedURL.Parse(locationHeader)
					if parseErr == nil {
						// For path-based, the payload itself is the redirect target.
						// We need to parse the payload to get its host.
						payloadTargetURL, payloadParseErr := url.Parse(orPayload)
						if payloadParseErr != nil {
							// Handle cases like "\\evil.com" which might not parse as a valid URL
							// by trying to parse them as if they were protocol-relative.
							if strings.HasPrefix(orPayload, "\\\\") {
								payloadTargetURL, _ = url.Parse("http:" + strings.Replace(orPayload, "\\", "/", -1))
							} else {
								continue
							}
						}

						if redirectURL.Host != "" && payloadTargetURL != nil && payloadTargetURL.Host != "" &&
							strings.Contains(strings.ToLower(redirectURL.Host), strings.ToLower(payloadTargetURL.Host)) &&
							strings.ToLower(redirectURL.Host) != strings.ToLower(originalHost) {

							details := fmt.Sprintf("Path-based redirect to external URL '%s' (Host: %s) which matches payload host '%s'. Original host: '%s'. Status: %d.",
								locationHeader, redirectURL.Host, payloadTargetURL.Host, originalHost, resp.StatusCode)

							findings = append(findings, scanner.VulnerabilityResult{
								VulnerabilityType: "Open Redirect (Path-based)",
								URL:               testURL,
								Parameter:         "N/A (Path Manipulation)",
								Payload:           orPayload,
								Location:          "path",
								Details:           details,
								Severity:          "medium",
								Evidence:          locationHeader,
								Remediation:       "Avoid using user input in redirect destinations. Use allow-lists or enforce strict validation. Sanitize URL paths.",
								ScannerName:       "openredirect",
							})
						}
					}
				}
			}
		}
	}
	// --- End of Path-Based Scan ---

	if contains(req.ParamLocations, "query") || contains(req.ParamLocations, "body") {
		for _, paramName := range req.ParamNames {
			for _, orPayload := range payloads.OpenRedirectPayloads {
				testURL, reqBody, httpMethod := buildRequest(req, paramName, orPayload)

				httpRequest, reqErr := http.NewRequest(httpMethod, testURL, reqBody)
				if reqErr != nil {
					continue
				}
				if httpMethod == "POST" {
					httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}

				originalCheckRedirectFunc := client.TemporarilyDisableRedirects()
				resp, err := client.Do(httpRequest)
				client.RestoreRedirects(originalCheckRedirectFunc)

				if resp != nil {
					defer resp.Body.Close()
				}

				// Handle redirect suppression gracefully
				if err != nil {
					if resp == nil {
						continue
					}
					isErrUseLastResponse := false
					if urlErr, ok := err.(*url.Error); ok {
						if urlErr.Err == http.ErrUseLastResponse {
							isErrUseLastResponse = true
						}
					}
					if !isErrUseLastResponse {
						continue
					}
				}
				if resp == nil {
					continue
				}

				if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
					locationHeader := resp.Header.Get("Location")
					if locationHeader != "" {
						currentTestedURL, _ := url.Parse(testURL)
						redirectURL, parseErr := currentTestedURL.Parse(locationHeader)
						if parseErr == nil {
							payloadTargetURL, payloadParseErr := url.Parse(orPayload)
							if redirectURL.Host != "" && payloadParseErr == nil && payloadTargetURL.Host != "" &&
								strings.Contains(strings.ToLower(redirectURL.Host), strings.ToLower(payloadTargetURL.Host)) &&
								strings.ToLower(redirectURL.Host) != strings.ToLower(originalHost) {

								details := fmt.Sprintf("Redirected to external URL '%s' (Host: %s) which matches payload host '%s'. Original host: '%s'. Status: %d.",
									locationHeader, redirectURL.Host, payloadTargetURL.Host, originalHost, resp.StatusCode)

								locationType := "query"
								if httpMethod == "POST" {
									locationType = "body"
								}

								findings = append(findings, scanner.VulnerabilityResult{
									VulnerabilityType: "Open Redirect",
									URL:               req.URL,
									Parameter:         paramName,
									Payload:           orPayload,
									Location:          locationType,
									Details:           details,
									Severity:          "medium",
									Evidence:          locationHeader,
									Remediation:       "Avoid using user input in redirect destinations. Use allow-lists or enforce strict validation.",
									ScannerName:       "openredirect",
								})
								goto nextORParam
							}
						}
					}
				}
			}
		nextORParam:
		}
	}
	return findings, nil
}

// buildRequest constructs an HTTP request with the open redirect payload.
// It handles both GET and POST requests, injecting the payload into the appropriate parameter.
func buildRequest(req crawler.ParameterizedRequest, paramName, payload string) (string, io.Reader, string) {
	if req.Method == "GET" {
		// --- FIX STARTS HERE ---
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			// If the original URL from the crawler is broken, return an empty string.
			// This will cause http.NewRequest to fail safely in the Scan function,
			// and this test will be skipped.
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
