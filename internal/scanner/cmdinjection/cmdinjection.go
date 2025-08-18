package cmdinjection

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
)

// CommandInjectionScanner implements the Scanner interface for Command Injection.
type CommandInjectionScanner struct{}

// NewCommandInjectionScanner creates a new instance of CommandInjectionScanner.
func NewCommandInjectionScanner() *CommandInjectionScanner {
	return &CommandInjectionScanner{}
}

// Name returns the scanner's name.
func (s *CommandInjectionScanner) Name() string {
	return "Context-Aware Command Injection Scanner"
}

// Scan performs a command injection scan on the given parameterized request.
// It prioritizes output-based detection, then falls back to time-based, and finally OAST-based detection.
func (s *CommandInjectionScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	rand.Seed(time.Now().UnixNano())

	for _, paramName := range req.ParamNames {
		originalParams, err := getOriginalParams(req)
		if err != nil {
			continue
		}
		originalValue := originalParams.Get(paramName)
		var vulnerabilityFoundForParam bool

		// --- Phase 1: Prioritize Output-Based Detection ---
		for _, testCase := range payloads.CommandInjectionTests {
			if testCase.Type != "output-based" {
				continue
			}
			found, vuln := s.executeTest(req, client, log, paramName, originalValue, originalParams, testCase)
			if found {
				findings = append(findings, vuln)
				vulnerabilityFoundForParam = true
				break // Found the best evidence, stop output-based tests for this param
			}
		}
		if vulnerabilityFoundForParam {
			continue // Move to the next parameter
		}

		// --- Phase 2: Fallback to Time-Based Detection ---
		for _, testCase := range payloads.CommandInjectionTests {
			if testCase.Type != "time-based" {
				continue
			}
			found, vuln := s.executeTest(req, client, log, paramName, originalValue, originalParams, testCase)
			if found {
				findings = append(findings, vuln)
				vulnerabilityFoundForParam = true
				break // Found time-based, good enough, stop time-based tests for this param
			}
		}
		if vulnerabilityFoundForParam {
			continue // Move to the next parameter
		}

		// --- Phase 3: Always run OAST if enabled, as it's a separate detection method ---
		if opts.OASTDomain != "" {
			s.testOASTBased(req, client, opts, paramName, "")
		}
	}
	return findings, nil
}

// executeTest is a new helper function to run a single test case and check for vulnerabilities.
// It constructs and sends requests with various payloads and checks for signs of command injection.
func (s *CommandInjectionScanner) executeTest(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName, originalValue string, originalParams url.Values, testCase payloads.CommandInjectionTest) (bool, scanner.VulnerabilityResult) {
	for _, separator := range testCase.Separators {
		// Smart Injection Strategy: Try appending and replacing with '1'
		injectionBases := []string{originalValue, "1"}
		for _, base := range injectionBases {
			payload := strings.Replace(testCase.PayloadToInject, "{SLEEP_TIME}", fmt.Sprintf("%d", testCase.SleepSeconds), -1)
			payload = strings.Replace(payload, "{SLEEP_TIME_PLUS_ONE}", fmt.Sprintf("%d", testCase.SleepSeconds+1), -1)
			maliciousValue := base + separator + payload

			switch testCase.Type {
			case "output-based":
				testURL, reqBody := buildRequest(req, originalParams, paramName, maliciousValue)
				responseBody, err := sendRequestAndGetBody(client, req.Method, testURL, reqBody, log)
				if err != nil {
					continue
				}
				if testCase.DetectionRegex != nil && testCase.DetectionRegex.MatchString(responseBody) {
					return true, scanner.VulnerabilityResult{
						VulnerabilityType: "Command Injection (Output-Based)",
						URL:               testURL,
						Parameter:         paramName,
						Payload:           separator + payload,
						Location:          getParamLocation(req),
						Details:           fmt.Sprintf("Command output detected for OS '%s'.", testCase.OS),
						Evidence:          testCase.DetectionRegex.FindString(responseBody),
						Severity:          "high",
						Remediation:       "Do not use user input directly in command execution. Use safe APIs and strict validation.",
						ScannerName:       s.Name(),
					}
				}
			case "time-based":
				baselineDuration := measureRequestDuration(req, client, originalParams)
				if baselineDuration < 0 {
					continue
				}
				testParams := copyParams(originalParams)
				testParams.Set(paramName, maliciousValue)
				testDuration := measureRequestDuration(req, client, testParams)
				delayThreshold := time.Duration(testCase.SleepSeconds-1) * time.Second

				if testDuration > (baselineDuration + delayThreshold) {
					testURL, _ := buildRequest(req, originalParams, paramName, maliciousValue)
					return true, scanner.VulnerabilityResult{
						VulnerabilityType: "Blind Command Injection (Time-Based)",
						URL:               testURL,
						Parameter:         paramName,
						Payload:           separator + payload,
						Location:          getParamLocation(req),
						Severity:          "high",
						Details:           fmt.Sprintf("OS detected as '%s'. Request delayed by ~%d seconds.", testCase.OS, testCase.SleepSeconds),
						Remediation:       "Use allowlists or proper input validation. Avoid using input directly in shell commands.",
						ScannerName:       s.Name(),
					}
				}
			}
		}
	}
	return false, scanner.VulnerabilityResult{}
}

// testOASTBased performs OAST-based command injection tests.
// It generates unique OAST payloads and stores correlation data for out-of-band detection.
func (s *CommandInjectionScanner) testOASTBased(req crawler.ParameterizedRequest, client *httpclient.Client, opts scanner.ScannerOptions, paramName, detectedOS string) {
	originalParams, _ := getOriginalParams(req)

	for _, testCase := range payloads.OASTCommandInjectionTests {
		if testCase.OS != "any" && testCase.OS != "" && testCase.OS != detectedOS {
			continue
		}
		for _, separator := range []string{";", "&&", "|", "`", "\n"} {
			correlationID := fmt.Sprintf("cmd-%s-%d", paramName, rand.Intn(1e9))
			oastPayloadDomain := fmt.Sprintf("%s.%s", correlationID, opts.OASTDomain)
			payloadToInject := strings.Replace(testCase.PayloadTemplate, "DURSGO_OAST_DOMAIN", oastPayloadDomain, -1)
			// For blind injection, we don't prepend the original value as it can break the command.
			maliciousValue := separator + " " + payloadToInject

			opts.OASTCorrelationMap.Store(correlationID, scanner.VulnerabilityResult{
				VulnerabilityType: fmt.Sprintf("Blind Command Injection (OAST: %s)", testCase.Description),
				URL:               req.URL,
				Parameter:         paramName,
				Payload:           separator + " " + payloadToInject,
				Location:          getParamLocation(req),
				Severity:          "high",
				Evidence:          fmt.Sprintf("Payload sent to %s", oastPayloadDomain),
				Remediation:       "Avoid using untrusted input in OS commands. Use whitelisting and secure APIs.",
				ScannerName:       s.Name(),
			})

			testURL, reqBody := buildRequest(req, originalParams, paramName, maliciousValue)
			// Send the request synchronously to ensure it completes before the scan finishes.
			sendAndForget(client, req.Method, testURL, reqBody)
		}
	}
}

// ---- Helper Functions (Improved for Stability) ----

// getOriginalParams extracts original parameters from the request based on its method.
func getOriginalParams(req crawler.ParameterizedRequest) (url.Values, error) {
	if req.Method == "GET" {
		p, e := url.Parse(req.URL)
		if e != nil {
			return nil, e
		}
		return p.Query(), nil
	}
	return url.ParseQuery(req.FormPostData)
}

// buildRequest builds an HTTP request with the injected payload.
// This is a key improvement function.
func buildRequest(req crawler.ParameterizedRequest, oP url.Values, pti, vti string) (string, io.Reader) {
	testParams := url.Values{}
	for k, v := range oP {
		testParams[k] = v
	}

	// Context-Aware Fix: When testing a parameter (pti), check if other parameters
	// look like they expect a URL. If so, and their current value is invalid,
	// provide a valid placeholder URL to satisfy server-side validation logic
	// that might otherwise block the execution path to our target parameter.
	for key := range testParams {
		if key == pti {
			continue // Skip the parameter we are currently testing
		}

		// Heuristic to identify URL-like parameters
		lowerKey := strings.ToLower(key)
		isURLParam := strings.Contains(lowerKey, "url") ||
			strings.Contains(lowerKey, "uri") ||
			strings.Contains(lowerKey, "site") ||
			strings.Contains(lowerKey, "dest") || // destination
			strings.Contains(lowerKey, "redirect")

		if isURLParam {
			currentValue := testParams.Get(key)
			// Check if the value is a structurally valid absolute URL.
			if u, err := url.ParseRequestURI(currentValue); err != nil || !u.IsAbs() {
				testParams.Set(key, "http://example.com/dursgo-placeholder")
			}
		}
	}

	testParams.Set(pti, vti) // Set the actual payload for the parameter under test

	if req.Method == "GET" {
		baseURL, err := url.Parse(req.URL)
		if err != nil {
			return "", nil // Return empty string if URL is invalid
		}
		baseURL.RawQuery = testParams.Encode()
		return baseURL.String(), nil
	}
	return req.URL, strings.NewReader(testParams.Encode())
}

// getParamLocation returns a comma-separated string of parameter locations.
func getParamLocation(req crawler.ParameterizedRequest) string {
	return strings.Join(req.ParamLocations, ",")
}

// sendRequest sends an HTTP request and returns the response.
// Added error checking for extra security.
func sendRequest(c *httpclient.Client, m, t string, b io.Reader) (*http.Response, error) {
	h, e := http.NewRequest(m, t, b)
	if e != nil {
		return nil, e
	}
	if m == "POST" {
		h.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return c.Do(h)
}

// sendAndForget sends an HTTP request and waits for it to complete.
func sendAndForget(c *httpclient.Client, m, t string, b io.Reader) {
	h, e := http.NewRequest(m, t, b)
	if e == nil { // Only proceed if the request was successfully created
		if m == "POST" {
			h.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, _ := c.Do(h)
		if resp != nil && resp.Body != nil {
			// We don't need to read the body, but we must close it.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}

// sendRequestAndGetBody sends an HTTP request and returns the response body as a string.
func sendRequestAndGetBody(c *httpclient.Client, m, t string, b io.Reader, l *logger.Logger) (string, error) {
	r, e := sendRequest(c, m, t, b)
	if e != nil {
		return "", e
	}
	defer r.Body.Close()
	by, re := io.ReadAll(r.Body)
	if re != nil {
		return "", re
	}
	if r.StatusCode >= 400 {
		return string(by), fmt.Errorf("error status code: %d", r.StatusCode)
	}
	return string(by), nil
}

// measureRequestDuration measures the duration of an HTTP request.
func measureRequestDuration(req crawler.ParameterizedRequest, client *httpclient.Client, params url.Values) time.Duration {
	var testURL string
	var reqBody io.Reader

	if req.Method == "GET" {
		u, err := url.Parse(req.URL)
		if err != nil {
			return -1
		} // Error checking
		u.RawQuery = params.Encode()
		testURL = u.String()
		reqBody = nil
	} else {
		testURL = req.URL
		reqBody = strings.NewReader(params.Encode())
	}

	startTime := time.Now()
	httpRequest, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		return -1 // Error checking
	}
	if req.Method == "POST" {
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	res, err := client.Do(httpRequest)
	if err != nil {
		if res != nil {
			res.Body.Close()
		}
		return -1
	}
	if res.Body != nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
	return time.Since(startTime)
}

// copyParams creates a deep copy of url.Values.
func copyParams(original url.Values) url.Values {
	nP := url.Values{}
	for k, v := range original {
		nP[k] = v
	}
	return nP
}
