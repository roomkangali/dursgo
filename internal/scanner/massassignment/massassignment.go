package massassignment

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// MassAssignmentScanner implements the Scanner interface for Mass Assignment vulnerabilities.
type MassAssignmentScanner struct {
	mu         sync.Mutex
	testedURLs map[string]bool
}

// NewMassAssignmentScanner creates a new instance of MassAssignmentScanner.
func NewMassAssignmentScanner() *MassAssignmentScanner {
	return &MassAssignmentScanner{
		testedURLs: make(map[string]bool),
	}
}

// Name returns the scanner's name.
func (s *MassAssignmentScanner) Name() string {
	return "Mass Assignment Scanner"
}

// isPotentialTarget is a heuristic to identify potentially vulnerable endpoints.
// It checks if the URL path contains keywords commonly associated with user profiles,
// account settings, and other data modification endpoints.
func isPotentialTarget(targetURL string, log *logger.Logger) bool {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Debug("MassAssignment: Failed to parse URL '%s' in isPotentialTarget.", targetURL)
		return false
	}
	path := strings.ToLower(parsedURL.Path)

	keywords := []string{
		"profile", "user", "account", "setting", "update", "edit",
		"api", "me", "save", "store", "create", "assignment",
	}

	for _, kw := range keywords {
		if strings.Contains(path, kw) {
			return true
		}
	}
	return false
}

// Scan performs the Mass Assignment scan.
// It identifies potential target endpoints and attempts to modify restricted fields
// by sending crafted JSON payloads. It then verifies if the changes were successful.
func (s *MassAssignmentScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if !isPotentialTarget(req.URL, log) {
		return nil, nil
	}

	s.mu.Lock()
	if s.testedURLs[req.URL] {
		s.mu.Unlock()
		return nil, nil
	}
	s.testedURLs[req.URL] = true
	s.mu.Unlock()

	log.Debug("MassAssignment: Found potential target: %s. Starting test...", req.URL)

	for _, httpMethod := range []string{"POST", "PUT"} {
		for _, testCase := range payloads.MassAssignmentPayloads {
			payloadBody := map[string]interface{}{
				testCase.Key: testCase.Value,
			}
			jsonPayload, err := json.Marshal(payloadBody)
			if err != nil {
				continue
			}

			injectReq, _ := http.NewRequest(httpMethod, req.URL, bytes.NewBuffer(jsonPayload))
			injectReq.Header.Set("Content-Type", "application/json")

			log.Debug("MassAssignment: Sending %s to %s with payload: %s", httpMethod, req.URL, string(jsonPayload))
			injectResp, err := client.Do(injectReq)
			if err != nil {
				if injectResp != nil && injectResp.Body != nil {
					injectResp.Body.Close()
				}
				continue
			}
			injectResp.Body.Close()

			time.Sleep(250 * time.Millisecond)

			verifyReq, _ := http.NewRequest("GET", req.URL, nil)
			verifyResp, err := client.Do(verifyReq)
			if err != nil {
				if verifyResp != nil && verifyResp.Body != nil {
					verifyResp.Body.Close()
				}
				continue
			}

			var result map[string]interface{}
			err = json.NewDecoder(verifyResp.Body).Decode(&result)
			verifyResp.Body.Close()
			if err != nil {
				continue
			}

			if val, ok := result[testCase.Key]; ok {
				vulnerable := false
				switch testCase.CheckType {
				case "bool_true":
					if bVal, ok := val.(bool); ok && bVal {
						vulnerable = true
					}
				case "string_match":
					if sVal, ok := val.(string); ok && sVal == testCase.Value.(string) {
						vulnerable = true
					}
				case "int_match":
					if fVal, ok := val.(float64); ok && int(fVal) == testCase.Value.(int) {
						vulnerable = true
					}
				}

				if vulnerable {
					details := fmt.Sprintf("Successfully injected and modified the restricted field '%s' to value '%v' via a %s request.", testCase.Key, testCase.Value, httpMethod)
					log.Success("Mass Assignment found at %s!", req.URL)

					return []scanner.VulnerabilityResult{{
						VulnerabilityType: "Mass Assignment",
						URL:               req.URL,
						Payload:           string(jsonPayload),
						Location:          "JSON Body",
						Details:           details,
						ScannerName:       s.Name(),
						Severity:          "High",
						Evidence:          fmt.Sprintf("Key '%s' changed to '%v' and reflected in GET response", testCase.Key, testCase.Value),
						Remediation:       "Implement whitelisting for mass assignable fields or use explicit field binding. Avoid binding user input directly to model objects.",
					}}, nil
				}
			}
		}
	}

	return nil, nil
}
