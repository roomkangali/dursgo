package sqli

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
	"strings"
	"time"

	"github.com/agext/levenshtein"
)

// ignoredParams is a list of parameters to be ignored during scanning to reduce false positives.
var ignoredParams = map[string]bool{
	"_csrf_token": true,
	"csrf_token":  true,
	"csrf":        true,
	"token":       true,
	"_token":      true,
}

// specialPaths is a list of paths that often cause false positives and will be ignored.
var specialPaths = []string{
	"/comment",
	"/login",
	"/register",
}

// SQLiScanner implements the Scanner interface for SQL Injection.
// It performs various types of SQL injection tests, including error-based, time-based, and boolean-based.
type SQLiScanner struct{}

// NewSQLiScanner creates a new instance of SQLiScanner.
func NewSQLiScanner() *SQLiScanner {
	return &SQLiScanner{}
}

// Name returns the name of the scanner.
func (s *SQLiScanner) Name() string {
	return "Advanced SQL Injection Scanner"
}

// Scan performs the SQL Injection scan.
// It orchestrates various SQL injection tests, including error-based, time-based, and boolean-based,
// while ignoring common non-vulnerable parameters and paths to reduce false positives.
func (s *SQLiScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult

	if req.Method != "GET" && req.Method != "POST" {
		return nil, nil
	}

	for _, path := range specialPaths {
		if strings.Contains(req.URL, path) {
			return nil, nil // Ignore special paths
		}
	}

ParamLoop:
	for _, paramName := range req.ParamNames {
		if _, ignored := ignoredParams[strings.ToLower(paramName)]; ignored {
			continue // Ignore special parameters
		}

		log.Debug("SQLi: Testing parameter '%s' in %s", paramName, req.URL)

		// 1. Error-Based (Most Reliable)
		errorVuln, foundErrorBased := s.testErrorBased(req, client, log, paramName)
		if foundErrorBased {
			findings = append(findings, errorVuln)
			continue ParamLoop
		}

		// 2. Time-Based (Reliable for Blind)
		timeVuln, foundTimeBased := s.testTimeBased(req, client, log, paramName)
		if foundTimeBased {
			findings = append(findings, timeVuln)
			continue ParamLoop
		}

		// 3. Boolean-Based (For Faster Blind)
		booleanVuln, foundBooleanBased := s.testBooleanBased(req, client, log, paramName)
		if foundBooleanBased {
			findings = append(findings, booleanVuln)
			continue ParamLoop
		}
	}

	return findings, nil
}

// testErrorBased performs an error-based SQL injection test.
// It injects various SQL payloads and checks for database error messages in the response.
func (s *SQLiScanner) testErrorBased(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName string) (scanner.VulnerabilityResult, bool) {
	for _, payload := range payloads.SQLiPayloads {
		testParams, err := getOriginalParams(req)
		if err != nil {
			continue
		}
		originalValue := testParams.Get(paramName)
		testParams.Set(paramName, originalValue+payload)

		_, body, err := sendRequest(req, client, log, testParams)
		if err != nil {
			continue
		}

		for _, pattern := range payloads.SQLiErrorPatterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(body) {
				log.Success("SQLi (Error-Based): Found pattern '%s' for param '%s'", pattern, paramName)
				testURL, _, _ := buildRequestComponents(req, testParams)
				vuln := scanner.VulnerabilityResult{
					VulnerabilityType: "SQL Injection (Error-Based)",
					URL:               testURL,
					Parameter:         paramName,
					Payload:           payload,
					Details:           "A database error message was detected in the response, indicating a potential SQL injection vulnerability.",
					Severity:          "High",
					Evidence:          re.FindString(body),
					Location:          getParamLocation(req),
					Remediation:       "Use parameterized queries (prepared statements).",
					ScannerName:       s.Name(),
				}
				return vuln, true
			}
		}
	}
	return scanner.VulnerabilityResult{}, false
}

// testTimeBased performs a time-based blind SQL injection test.
// It injects time-delay payloads and measures the response time to detect vulnerabilities.
func (s *SQLiScanner) testTimeBased(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName string) (scanner.VulnerabilityResult, bool) {
	baselineDuration, err := measureRequestDuration(req, client, log, nil) // Baseline without any params
	if err != nil {
		return scanner.VulnerabilityResult{}, false
	}

	for _, payload := range payloads.TimeBasedSQLiTests {
		testParams, err := getOriginalParams(req)
		if err != nil {
			continue
		}
		originalValue := testParams.Get(paramName)
		payloadStr := strings.Replace(payload.PayloadTemplate, "{DELAY}", "5", -1)
		testParams.Set(paramName, originalValue+payloadStr)

		testDuration, err := measureRequestDuration(req, client, log, testParams)
		if err != nil {
			continue
		}

		// If test time > baseline + 4 seconds (allowing 1 second tolerance)
		if testDuration > baselineDuration+(4*time.Second) {
			log.Success("SQLi (Time-Based): Detected significant delay for param '%s'", paramName)
			testURL, _, _ := buildRequestComponents(req, testParams)
			vuln := scanner.VulnerabilityResult{
				VulnerabilityType: "SQL Injection (Time-Based)",
				URL:               testURL,
				Parameter:         paramName,
				Payload:           payloadStr,
				Details:           fmt.Sprintf("A time delay of %.2f seconds was detected (baseline: %.2f seconds).", testDuration.Seconds(), baselineDuration.Seconds()),
				Severity:          "High",
				Evidence:          fmt.Sprintf("Response time: %s", testDuration),
				Location:          getParamLocation(req),
				Remediation:       "Use parameterized queries (prepared statements).",
				ScannerName:       s.Name(),
			}
			return vuln, true
		}
	}
	return scanner.VulnerabilityResult{}, false
}

// testBooleanBased performs a boolean-based blind SQL injection test.
// It injects true and false conditions and compares the responses to detect differences.
func (s *SQLiScanner) testBooleanBased(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName string) (scanner.VulnerabilityResult, bool) {
	originalParams, err := getOriginalParams(req)
	if err != nil {
		return scanner.VulnerabilityResult{}, false
	}
	_, originalBody, err := sendRequest(req, client, log, originalParams)
	if err != nil {
		return scanner.VulnerabilityResult{}, false
	}

	for _, test := range payloads.BooleanSQLiTests {
		// True
		trueParams := copyParams(originalParams)
		trueParams.Set(paramName, trueParams.Get(paramName)+test.TruePayload)
		_, trueBody, err := sendRequest(req, client, log, trueParams)
		if err != nil {
			continue
		}

		// False
		falseParams := copyParams(originalParams)
		falseParams.Set(paramName, falseParams.Get(paramName)+test.FalsePayload)
		_, falseBody, err := sendRequest(req, client, log, falseParams)
		if err != nil {
			continue
		}

		if !isDifferentResponse(originalBody, trueBody) && isDifferentResponse(originalBody, falseBody) {
			log.Success("SQLi (Boolean-Based): Detected differential response for param '%s'", paramName)
			testURL, _, _ := buildRequestComponents(req, trueParams)
			vuln := scanner.VulnerabilityResult{
				VulnerabilityType: "SQL Injection (Boolean-Based)",
				URL:               testURL,
				Parameter:         paramName,
				Payload:           test.TruePayload,
				Details:           "The application's response was different when a logically false SQL condition was injected compared to a true one.",
				Severity:          "High",
				Evidence:          "Response for TRUE condition was similar to original, while response for FALSE was different.",
				Location:          getParamLocation(req),
				Remediation:       "Use parameterized queries (prepared statements).",
				ScannerName:       s.Name(),
			}
			return vuln, true
		}
	}
	return scanner.VulnerabilityResult{}, false
}

// --- Helper Functions ---

// getOriginalParams extracts original parameters from the request based on its method.
func getOriginalParams(req crawler.ParameterizedRequest) (url.Values, error) {
	if req.Method == "GET" {
		u, err := url.Parse(req.URL)
		if err != nil {
			return nil, err
		}
		return u.Query(), nil
	}
	return url.ParseQuery(req.FormPostData)
}

// copyParams creates a deep copy of url.Values.
func copyParams(original url.Values) url.Values {
	newParams := url.Values{}
	for k, v := range original {
		newParams[k] = v
	}
	return newParams
}

// buildRequestComponents constructs the URL and request body for a test request.
func buildRequestComponents(req crawler.ParameterizedRequest, params url.Values) (string, io.Reader, error) {
	if req.Method == "GET" {
		u, err := url.Parse(req.URL)
		if err != nil {
			return "", nil, err
		}
		u.RawQuery = params.Encode()
		return u.String(), nil, nil
	}
	return req.URL, strings.NewReader(params.Encode()), nil
}

// sendRequest sends an HTTP request and returns the status code, body, and any error.
func sendRequest(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, params url.Values) (int, string, error) {
	testURL, reqBody, err := buildRequestComponents(req, params)
	if err != nil {
		return 0, "", err
	}

	httpReq, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		return 0, "", err
	}
	if req.Method == "POST" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(bodyBytes), nil
}

// measureRequestDuration measures the duration of an HTTP request.
func measureRequestDuration(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, params url.Values) (time.Duration, error) {
	if params == nil {
		var err error
		params, err = getOriginalParams(req)
		if err != nil {
			return 0, err
		}
	}
	testURL, reqBody, err := buildRequestComponents(req, params)
	if err != nil {
		return 0, err
	}

	httpReq, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		return 0, err
	}
	if req.Method == "POST" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return time.Since(startTime), nil
}

// getParamLocation returns the location of the parameter (query or body).
func getParamLocation(req crawler.ParameterizedRequest) string {
	if req.Method == "GET" {
		return "query"
	}
	return "body"
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
