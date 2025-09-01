package idor

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
	"strconv"
	"strings"
)

// IDORScanner implements the Scanner interface for Insecure Direct Object Reference (IDOR).
type IDORScanner struct{}

// NewIDORScanner creates a new instance of IDORScanner.
func NewIDORScanner() *IDORScanner {
	return &IDORScanner{}
}

// Name returns the scanner's name.
func (s *IDORScanner) Name() string {
	return "Insecure Direct Object Reference (IDOR) Scanner"
}

// isUserResourcePath checks if a URL path likely points to a user-specific resource.
func isUserResourcePath(path string) bool {
	userKeywords := []string{"user", "profile", "account", "member", "customer"}
	lowerPath := strings.ToLower(path)
	for _, keyword := range userKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}
	return false
}

// testPathForIDOR tests for IDOR vulnerabilities by manipulating numeric IDs in URL paths.
func (s *IDORScanner) testPathForIDOR(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) []scanner.VulnerabilityResult {
	var findings []scanner.VulnerabilityResult
	parsedURL, err := url.Parse(req.URL)
	if err != nil || !isUserResourcePath(parsedURL.Path) {
		return nil
	}

	pathSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	for i, segment := range pathSegments {
		originalID, err := strconv.Atoi(segment)
		if err != nil {
			continue // Not a numeric segment.
		}

		log.Debug("IDOR (Path): Found numeric segment '%d' in path %s. Testing...", originalID, parsedURL.Path)

		const invalidID = 999999
		invalidPathSegments := make([]string, len(pathSegments))
		copy(invalidPathSegments, pathSegments)
		invalidPathSegments[i] = strconv.Itoa(invalidID)
		invalidURL := *parsedURL
		invalidURL.Path = "/" + strings.Join(invalidPathSegments, "/")

		_, baselineErrorBody, errBase := sendRequest(req.Method, &invalidURL, nil, client, log)
		if errBase != nil {
			continue
		}

		idsToTest := []int{1, 2, 3}
		for _, testID := range idsToTest {
			if opts.UserID != 0 && (testID == opts.UserID || testID == originalID) {
				continue
			}

			testPathSegments := make([]string, len(pathSegments))
			copy(testPathSegments, pathSegments)
			testPathSegments[i] = strconv.Itoa(testID)
			testURL := *parsedURL
			testURL.Path = "/" + strings.Join(testPathSegments, "/")

			statusCodeTest, responseBodyTest, errTest := sendRequest(req.Method, &testURL, nil, client, log)

			if errTest == nil && statusCodeTest == http.StatusOK && responseBodyTest != baselineErrorBody {
				var details string
				if opts.UserID != 0 {
					details = fmt.Sprintf("As authenticated user %d, accessed user-resource '%s'. The response was valid and different from the error page baseline, indicating access to another user's data.", opts.UserID, testURL.String())
				} else {
					details = fmt.Sprintf("As an unauthenticated user, accessed user-resource '%s'. The response was valid and different from the error page baseline, indicating access to sensitive data.", testURL.String())
				}
				findings = append(findings, scanner.VulnerabilityResult{
					VulnerabilityType: "Insecure Direct Object Reference (IDOR)",
					URL:               testURL.String(),
					Parameter:         fmt.Sprintf("URL Path Segment #%d", i+1),
					Payload:           strconv.Itoa(testID),
					Location:          "path",
					Details:           details,
					Severity:          "High",
					Evidence:          "Response for a valid ID was different from the response for a known-invalid ID.",
					Remediation:       "Ensure that server-side authorization checks verify that the logged-in user has permission to access the requested resource ID.",
					ScannerName:       s.Name(),
				})
				return findings
			}
		}
	}
	return findings
}

// testParamsForIDOR tests for IDOR vulnerabilities in URL and body parameters.
func (s *IDORScanner) testParamsForIDOR(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) []scanner.VulnerabilityResult {
	var findings []scanner.VulnerabilityResult
	originalParams, err := getOriginalParams(req)
	if err != nil {
		return nil
	}

	for _, paramName := range req.ParamNames {
		if !isCommonIDParam(paramName) {
			continue
		}

		originalValueStr := originalParams.Get(paramName)
		originalID, err := strconv.Atoi(originalValueStr)
		if err != nil {
			originalID = 0
		}

		log.Debug("IDOR (Param): Found potential IDOR parameter '%s'. Testing...", paramName)

		const invalidID = 999999
		invalidParams := copyParams(originalParams)
		invalidParams.Set(paramName, strconv.Itoa(invalidID))
		parsedURL, _ := url.Parse(req.URL)
		_, baselineErrorBody, errBase := sendRequest(req.Method, parsedURL, invalidParams, client, log)
		if errBase != nil {
			continue
		}

		idsToTest := []int{1, 2, 3}
		for _, testID := range idsToTest {
			if opts.UserID != 0 && (testID == opts.UserID || testID == originalID) {
				continue
			}

			testParams := copyParams(originalParams)
			testParams.Set(paramName, strconv.Itoa(testID))
			statusCodeTest, responseBodyTest, errTest := sendRequest(req.Method, parsedURL, testParams, client, log)

			if errTest == nil && statusCodeTest == http.StatusOK && responseBodyTest != baselineErrorBody {
				// Final False Positive Check: Ensure the response doesn't contain common error messages.
				isFalsePositive := false
				for _, keyword := range payloads.IDORNegativeKeywords {
					if strings.Contains(strings.ToLower(responseBodyTest), keyword) {
						log.Debug("IDOR (Param): Skipping potential false positive for '%s=%d' due to negative keyword: %s", paramName, testID, keyword)
						isFalsePositive = true
						break
					}
				}
				if isFalsePositive {
					continue
				}

				var details string
				if opts.UserID != 0 {
					details = fmt.Sprintf("As authenticated user %d, accessed a resource via parameter '%s=%d'. The response was valid and different from the error page baseline, indicating access to another user's data.", opts.UserID, paramName, testID)
				} else {
					details = fmt.Sprintf("As an unauthenticated user, accessed a resource via parameter '%s=%d'. The response was valid and different from the error page baseline, indicating access to sensitive data.", paramName, testID)
				}

				findings = append(findings, scanner.VulnerabilityResult{
					VulnerabilityType: "Insecure Direct Object Reference (IDOR)",
					URL:               req.URL,
					Parameter:         paramName,
					Payload:           strconv.Itoa(testID),
					Location:          getParamLocation(req),
					Details:           details,
					Severity:          "High",
					Evidence:          "Response for a valid ID was different from the response for a known-invalid ID.",
					Remediation:       "Ensure that server-side authorization checks verify that the logged-in user has permission to access the requested resource ID.",
					ScannerName:       s.Name(),
				})
				return findings
			}
		}
	}
	return findings
}

// Scan performs the IDOR scan.
func (s *IDORScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	log.Debug("Starting IDOR scan for %s %s...", req.Method, req.URL)

	pathFindings := s.testPathForIDOR(req, client, log, opts)
	findings = append(findings, pathFindings...)

	paramFindings := s.testParamsForIDOR(req, client, log, opts)
	findings = append(findings, paramFindings...)

	return findings, nil
}

// ---- Helper Functions ----
func isCommonIDParam(p string) bool {
	for _, name := range payloads.CommonIDParameterNames {
		if strings.ToLower(p) == name {
			return true
		}
	}
	return false
}

func getOriginalParams(req crawler.ParameterizedRequest) (url.Values, error) {
	if req.Method == "GET" {
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			return nil, err
		}
		return parsedURL.Query(), nil
	}
	return url.ParseQuery(req.FormPostData)
}

func copyParams(original url.Values) url.Values {
	newParams := url.Values{}
	for k, v := range original {
		newParams[k] = v
	}
	return newParams
}

func sendRequest(method string, baseURL *url.URL, params url.Values, client *httpclient.Client, log *logger.Logger) (int, string, error) {
	var targetURL string
	var reqBody io.Reader
	if method == "GET" {
		freshURL := *baseURL
		if params != nil {
			freshURL.RawQuery = params.Encode()
		}
		targetURL = freshURL.String()
	} else {
		targetURL = baseURL.String()
		if params != nil {
			reqBody = strings.NewReader(params.Encode())
		}
	}
	return fetchAndRead(client, method, targetURL, reqBody, log)
}

func getParamLocation(req crawler.ParameterizedRequest) string {
	return strings.Join(req.ParamLocations, ",")
}

func fetchAndRead(client *httpclient.Client, method, targetURL string, reqBody io.Reader, log *logger.Logger) (int, string, error) {
	httpRequest, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		return 0, "", err
	}
	if method == "POST" {
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(httpRequest)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return 0, "", err
	}
	defer resp.Body.Close()
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, "", readErr
	}
	return resp.StatusCode, string(bodyBytes), nil
}
