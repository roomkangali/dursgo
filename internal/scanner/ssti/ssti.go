package ssti

import (
	"github.com/roomkangali/dursgo/internal/crawler"
	"github.com/roomkangali/dursgo/internal/httpclient"
	"github.com/roomkangali/dursgo/internal/logger"
	"github.com/roomkangali/dursgo/internal/payloads"
	"github.com/roomkangali/dursgo/internal/scanner"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSTIScanner implements the Scanner interface for Server-Side Template Injection.
type SSTIScanner struct{}

// NewSSTIScanner creates a new instance.
func NewSSTIScanner() *SSTIScanner {
	return &SSTIScanner{}
}

// Name returns the scanner's name.
func (s *SSTIScanner) Name() string {
	return "Server-Side Template Injection (SSTI) Scanner"
}

// Scan performs the SSTI scan by injecting payloads and analyzing responses.
func (s *SSTIScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	// Seed the random number generator for unique baseline values.
	rand.Seed(time.Now().UnixNano())

	log.Debug("Starting SSTI scan for %s %s...", req.Method, req.URL)

	// Iterate through each parameter found in the request.
	for _, paramName := range req.ParamNames {
		vulnerabilityFoundForParam := false // Flag to stop testing a parameter once a vulnerability is found.

		// Generate a unique baseline value for comparison.
		baselineValue := fmt.Sprintf("dursgoprobe%d", rand.Intn(1e9))
		baselineResp, err := sendSSTIRequest(req, client, paramName, baselineValue)
		if err != nil {
			log.Debug("SSTI: Baseline request failed for param '%s': %v", paramName, err)
			continue // Cannot proceed without a valid baseline.
		}
		defer baselineResp.Body.Close() // Ensure response body is closed.
		baselineBodyBytes, _ := io.ReadAll(baselineResp.Body)
		baselineBody := string(baselineBodyBytes)

		// Iterate through each SSTI test case (payload template).
		for _, testCase := range payloads.SSTIPayloads {
			if vulnerabilityFoundForParam {
				break // Stop if a vulnerability has already been found for this parameter.
			}

			// Generate a unique payload and its expected output for the current test case.
			payload, expectedOutput := payloads.GenerateSSTIPayload(testCase)

			testResp, err := sendSSTIRequest(req, client, paramName, payload)
			if err != nil {
				log.Debug("SSTI: Test request failed for param '%s' with payload '%s': %v", paramName, payload, err)
				continue
			}
			defer testResp.Body.Close() // Ensure response body is closed.
			testBodyBytes, _ := io.ReadAll(testResp.Body)
			testBody := string(testBodyBytes)

			// --- Detection Logic ---
			// 1. Reflection-Based Detection (High Confidence):
			//    - Expected output is found in the test response.
			//    - Expected output is NOT found in the baseline response (prevents false positives from static content).
			//    - HTTP status code is OK (200).
			isReflected := strings.Contains(testBody, expectedOutput) && !strings.Contains(baselineBody, expectedOutput)
			if isReflected && testResp.StatusCode == http.StatusOK {
				vulnerabilityFoundForParam = true
				findings = append(findings, s.createVulnerability(req, testCase, paramName, payload,
					fmt.Sprintf("Template expression '%s' was evaluated to '%s'.", payload, expectedOutput)))
				continue
			}

			// 2. Error-Based Detection (Medium-High Confidence):
			//    - Baseline request was successful (HTTP 200 OK).
			//    - Test request resulted in an Internal Server Error (HTTP 500).
			//    This indicates the server attempted to process the template but failed.
			isErrorBased := baselineResp.StatusCode == http.StatusOK && testResp.StatusCode == http.StatusInternalServerError
			if isErrorBased {
				vulnerabilityFoundForParam = true
				findings = append(findings, s.createVulnerability(req, testCase, paramName, payload,
					fmt.Sprintf("Payload '%s' caused a 500 Internal Server Error, while a baseline request was successful. This strongly indicates the server tried to process the template.", payload)))
				continue
			}
		}
	}
	return findings, nil
}

// createVulnerability constructs a scanner.VulnerabilityResult based on the detected SSTI.
func (s *SSTIScanner) createVulnerability(req crawler.ParameterizedRequest, testCase payloads.SSTIPayloadTest, paramName, payload, details string) scanner.VulnerabilityResult {
	// Build the vulnerable URL using the original request and the successful payload.
	vulnerableURL, _, _, _ := buildRequestComponents(req, paramName, payload)
	return scanner.VulnerabilityResult{
		VulnerabilityType: "Server-Side Template Injection (SSTI)",
		URL:               vulnerableURL,
		Parameter:         paramName,
		Payload:           payload,
		Location:          getParamLocation(req),
		Details:           details,
		Severity:          "High",
		Evidence:          fmt.Sprintf("Engine: %s, Expected Output: %s", testCase.EngineName, testCase.ExpectedPattern),
		Remediation:       "Avoid using user-supplied input in template structures. Use sandboxed template engines and explicitly pass variables.",
		ScannerName:       s.Name(),
	}
}

// --- Helper Functions ---

func sendSSTIRequest(req crawler.ParameterizedRequest, client *httpclient.Client, paramName, value string) (*http.Response, error) {
	testURL, reqBody, contentType, err := buildRequestComponents(req, paramName, value)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		return nil, err
	}
	if req.Method == "POST" && contentType != "" {
		httpRequest.Header.Set("Content-Type", contentType)
	}
	return client.Do(httpRequest)
}

func buildRequestComponents(req crawler.ParameterizedRequest, paramName, value string) (string, io.Reader, string, error) {
	if req.Method == "GET" {
		p, err := url.Parse(req.URL)
		if err != nil {
			return "", nil, "", err
		}
		q := p.Query()
		q.Set(paramName, value)
		p.RawQuery = q.Encode()
		return p.String(), nil, "", nil
	}

	trimmedData := strings.TrimSpace(req.FormPostData)
	if strings.HasPrefix(trimmedData, "{") && strings.HasSuffix(trimmedData, "}") {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(req.FormPostData), &jsonData); err == nil {
			jsonData[paramName] = value
			newBody, err := json.Marshal(jsonData)
			if err != nil {
				return "", nil, "", err
			}
			return req.URL, bytes.NewReader(newBody), "application/json", nil
		}
	}
	return buildFormRequest(req, paramName, value)
}

func buildFormRequest(req crawler.ParameterizedRequest, paramName, value string) (string, io.Reader, string, error) {
	params, err := url.ParseQuery(req.FormPostData)
	if err != nil {
		return "", nil, "", err
	}
	params.Set(paramName, value)
	params.Set("submit", "Submit")
	return req.URL, strings.NewReader(params.Encode()), "application/x-www-form-urlencoded", nil
}

func getParamLocation(req crawler.ParameterizedRequest) string {
	if req.Method == "GET" {
		return "query"
	}
	return "body"
}
