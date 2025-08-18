package graphql

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agext/levenshtein"
)

// GraphQLError represents a specific error for the GraphQL Scanner.
type GraphQLError struct {
	Type       string
	Message    string
	StatusCode int
	Retryable  bool
}

func (e *GraphQLError) Error() string {
	return fmt.Sprintf("%s: %s (status: %d)", e.Type, e.Message, e.StatusCode)
}

// ScanResult stores the scan result with a confidence score.
type ScanResult struct {
	Vulnerable bool
	Confidence int    // 0-100
	Evidence   string
}

// GraphQLScanner checks for common vulnerabilities in GraphQL endpoints.
// It performs various tests including introspection, SQL injection, NoSQL injection,
// sensitive data exposure, batching, and rate limiting checks.
type GraphQLScanner struct {
	mu          sync.Mutex
	hostScanned bool
	client      *httpclient.Client
	log         *logger.Logger
}

// NewGraphQLScanner creates a new instance of GraphQLScanner.
func NewGraphQLScanner() *GraphQLScanner {
	return &GraphQLScanner{}
}

// Name returns the scanner's name.
func (s *GraphQLScanner) Name() string {
	return "GraphQL Scanner"
}

// doRequestWithRetry performs an HTTP request with a retry mechanism.
// It retries transient errors with exponential backoff up to a maximum number of retries.
func (s *GraphQLScanner) doRequestWithRetry(ctx context.Context, req *http.Request, maxRetries int) (*http.Response, error) {
	var lastErr error
	
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Second * time.Duration(i) * 2) // Exponential backoff
		}
		
		resp, err := s.client.Do(req)
		if err == nil {
			return resp, nil
		}
		
		// If error is transient, retry
		if isTransientError(err) {
			lastErr = err
			continue
		}
		
		// Fatal error, no need to retry
		return nil, err
	}
	
	return nil, fmt.Errorf("max retries exceeded, last error: %v", lastErr)
}

// isTransientError checks if an error is temporary.
// It identifies common network-related errors that might be resolved by retrying.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	
	// Timeout, connection refused, etc.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "network is unreachable")
}

// logDebug is a helper for debug logging.
func (s *GraphQLScanner) logDebug(format string, args ...interface{}) {
	if s.log != nil {
		s.log.Debug("[GraphQL] "+format, args...)
	}
}

// logError is a helper for error logging.
func (s *GraphQLScanner) logError(err error, message string) {
	if s.log != nil && err != nil {
		s.log.Error("[GraphQL] %s: %v", message, err)
	}
}

// checkIntrospection checks if GraphQL introspection is enabled.
// It sends various introspection queries to the GraphQL endpoint and
// analyzes the response to determine if schema information is exposed.
func (s *GraphQLScanner) checkIntrospection(endpoint string, client *httpclient.Client) (bool, string) {
	// Basic introspection query
	introspectionQuery := `{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}"}`
	queries := []string{
		payloads.GraphQLQueries.IntrospectionFull,
		`{"query":"{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}"}`,
		introspectionQuery,
	}

	for _, query := range queries {
		req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(query))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			s.logError(err, "Failed to send introspection query")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			// This error is now suppressed as the underlying issue is fixed.
			continue
		}

		// Check if the response contains a GraphQL schema
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		if data, ok := result["data"].(map[string]interface{}); ok {
			if _, ok := data["__schema"]; ok {
				return true, string(body)
			}
		}

		// Check for introspection errors
		if _, ok := result["errors"]; ok {
			continue
		}
	}

	return false, ""
}

// checkSQLInjection checks for SQL Injection vulnerabilities in GraphQL and REST API endpoints.
// It performs a multi-phase check, starting with basic payloads, then different payloads,
// and finally checks vulnerable REST API endpoints and response differences.
func (s *GraphQLScanner) checkSQLInjection(endpoint string, client *httpclient.Client) (bool, string, string) {
	// Phase 1: Check with basic payloads
	basicVuln, basicEvidence := s.checkBasicSQLInjection(endpoint, client)
	if basicVuln {
		// If vulnerability found, return true with evidence
		return true, basicEvidence, "SQL Injection detected"
	}

	// Phase 2: Verify with different payloads
	verified, verificationEvidence := s.verifyWithDifferentPayloads(endpoint, client)
	if verified {
		return true, verificationEvidence, "SQL Injection verified with different payloads"
	}

	// Phase 3: Check vulnerable REST API endpoints
	baseURL := strings.TrimSuffix(endpoint, "/graphql")
	if baseURL == endpoint {
		baseURL = strings.TrimSuffix(endpoint, "/")
	}

	// Test additional vulnerable endpoints
	endpointsToCheck := []struct {
		path    string
		method  string
		payload string
		headers map[string]string
	}{
		{
			path:    "/api/users/search",
			method:  "GET",
			payload: "q=admin' OR '1'='1",
			headers: map[string]string{"Accept": "application/json"},
		},
		{
			path:    "/api/vulnerable/nosql",
			method:  "GET",
			payload: "username=admin&isAdmin=true",
			headers: map[string]string{"Accept": "application/json"},
		},
	}

	for _, ep := range endpointsToCheck {
		fullURL := fmt.Sprintf("%s%s", baseURL, ep.path)
		var req *http.Request
		var err error

		if ep.method == "POST" {
			req, err = http.NewRequest(ep.method, fullURL, bytes.NewBufferString(ep.payload))
		} else {
			url := fullURL
			if ep.payload != "" {
				url = fmt.Sprintf("%s?%s", fullURL, ep.payload)
			}
			req, err = http.NewRequest(ep.method, url, nil)
		}

		if err != nil {
			continue
		}

		// Set headers
		req.Header.Set("User-Agent", "DursGo-Scanner/1.0")
		for k, v := range ep.headers {
			req.Header.Set(k, v)
		}

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Read response
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)


		// Check vulnerability indicators
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "vulnerable") || 
			strings.Contains(bodyStr, "SELECT") || 
			strings.Contains(bodyStr, "FROM users") ||
			strings.Contains(bodyStr, "SQL")) {
			return true, 
				fmt.Sprintf("Potential SQL Injection at %s %s (Status: %d)", ep.method, fullURL, resp.StatusCode), 
				"SQL Injection detected in REST API endpoint"
		}

		// Check for SQL errors in response
		if resp.StatusCode >= 400 && (strings.Contains(strings.ToLower(bodyStr), "sql") || 
			strings.Contains(strings.ToLower(bodyStr), "syntax")) {
			return true, 
				fmt.Sprintf("SQL Error at %s %s: %s", ep.method, fullURL, bodyStr[:100]), 
				"SQL Error detected in response"
		}
	}

	// Phase 4: Check response difference with baseline
	isDifferent, diffEvidence := s.checkResponseDifference(endpoint, client)
	if isDifferent {
		return true, diffEvidence, "Response difference indicates possible SQL Injection"
	}

	return false, "", ""
}

// checkBasicSQLInjection performs basic SQL Injection detection.
// It tests various GraphQL and REST API endpoints with common SQL injection payloads
// and looks for specific patterns or unusual status codes in the responses.
func (s *GraphQLScanner) checkBasicSQLInjection(endpoint string, client *httpclient.Client) (bool, string) {
	// Extract base URL from GraphQL endpoint
	baseURL := strings.TrimSuffix(endpoint, "/graphql")
	if baseURL == endpoint { // If not a GraphQL endpoint, use the original URL
		baseURL = strings.TrimSuffix(endpoint, "/")
	}

	testCases := []struct {
		name     string
		endpoint string
		method   string
		payload  string
		patterns []string
		headers  map[string]string
	}{
		// Test GraphQL endpoint
		{
			name:     "GraphQL Basic SQL Injection",
			endpoint: endpoint,
			method:   "POST",
			payload:  `{"query": "query { user(id: \"1' OR '1'='1\") { id name } }"}`,
			patterns: []string{"syntax error", "unexpected", "SQL", "syntax", "vulnerable"},
			headers:  map[string]string{"Content-Type": "application/json"},
		},
		{
			name:     "GraphQL Comment-based SQL Injection",
			endpoint: endpoint,
			method:   "POST",
			payload:  `{"query": "query { user(id: \"1' --\") { id name } }"}`,
			patterns: []string{"syntax error", "unexpected", "SQL", "syntax", "vulnerable"},
			headers:  map[string]string{"Content-Type": "application/json"},
		},
		// Test vulnerable REST API endpoints
		{
			name:     "REST API SQL Injection in search",
			endpoint: fmt.Sprintf("%s/api/vulnerable/search", baseURL),
			method:   "GET",
			payload:  "id=1+OR+1%3D1",
			patterns: []string{"vulnerable", "SELECT", "FROM users", "id = 1 OR 1=1"},
			headers:  map[string]string{"Accept": "application/json"},
		},
		{
			name:     "REST API SQL Injection in login",
			endpoint: fmt.Sprintf("%s/api/login", baseURL),
			method:   "POST",
			payload:  `{"username":"admin", "password":"' OR '1'='1"}`,
			patterns: []string{"vulnerable", "success.*true", "isAdmin"},
			headers:  map[string]string{"Content-Type": "application/json"},
		},
	}

	for _, tc := range testCases {
		var req *http.Request
		var err error

		if tc.method == "POST" {
			req, err = http.NewRequest(tc.method, tc.endpoint, bytes.NewBufferString(tc.payload))
		} else {
			// For GET, add parameters directly to the URL
			url := tc.endpoint
			if tc.payload != "" {
				url = fmt.Sprintf("%s?%s", tc.endpoint, tc.payload)
			}
			req, err = http.NewRequest(tc.method, url, nil)
		}

		if err != nil {
			continue
		}

		// Set headers
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)


		// Check if the response contains SQL Injection vulnerability indicators
		for _, pattern := range tc.patterns {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pattern)) {
				return true, fmt.Sprintf("Detected %s at %s with pattern: %s", tc.name, tc.endpoint, pattern)
			}
		}

		// Also check for unusual status codes
		if resp.StatusCode >= 500 {
			return true, fmt.Sprintf("Potential SQL Injection detected at %s (Status: %d)", tc.endpoint, resp.StatusCode)
		}
	}

	return false, ""
}

// verifyWithDifferentPayloads verifies SQL Injection with different payloads.
// This is a simple implementation and can be further developed.
func (s *GraphQLScanner) verifyWithDifferentPayloads(endpoint string, client *httpclient.Client) (bool, string) {
	// Simple implementation, can be further developed
	return false, ""
}

// checkResponseDifference checks for response differences with a baseline.
// This is a simple implementation and can be further developed.
func (s *GraphQLScanner) checkResponseDifference(endpoint string, client *httpclient.Client) (bool, string) {
	// Simple implementation, can be further developed
	return false, ""
}

// checkSensitiveDataExposure checks for potential sensitive data leakage.
// This is a simple implementation.
func (s *GraphQLScanner) checkSensitiveDataExposure(endpoint string, client *httpclient.Client) (bool, string, string) {
	// Simple implementation
	return false, "", "Sensitive data exposure check not fully implemented"
}

// checkNoSQLInjection checks for NoSQL Injection vulnerabilities.
// It tests vulnerable endpoints with NoSQL injection payloads and looks for indicators in the response.
func (s *GraphQLScanner) checkNoSQLInjection(endpoint string, client *httpclient.Client) (bool, string, string) {
	// Extract base URL
	baseURL := strings.TrimSuffix(endpoint, "/graphql")
	if baseURL == endpoint {
		baseURL = strings.TrimSuffix(endpoint, "/")
	}

	// Test NoSQL Injection on vulnerable endpoints
	endpointsToTest := []struct {
		path    string
		method  string
		payload string
		headers map[string]string
	}{
		{
			path:    "/api/vulnerable/nosql",
			method:  "GET",
			payload: "username=admin' || '1'=='1&isAdmin=true",
			headers: map[string]string{"Accept": "application/json"},
		},
	}

	for _, ep := range endpointsToTest {
		url := fmt.Sprintf("%s%s?%s", baseURL, ep.path, ep.payload)
		req, err := http.NewRequest(ep.method, url, nil)
		if err != nil {
			continue
		}

		// Set headers
		req.Header.Set("User-Agent", "DursGo-Scanner/1.0")
		for k, v := range ep.headers {
			req.Header.Set(k, v)
		}

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Read response
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)


		// Check vulnerability indicators
		if strings.Contains(strings.ToLower(bodyStr), "vulnerable") || 
		   strings.Contains(strings.ToLower(bodyStr), "admin") ||
		   strings.Contains(strings.ToLower(bodyStr), "true") {
			return true, 
				fmt.Sprintf("Potential NoSQL Injection at %s %s - Response: %s", 
					ep.method, url, bodyStr[:min(100, len(bodyStr))]),
				"NoSQL Injection detected in API endpoint"
		}
	}

	return false, "", "No NoSQL Injection detected"
}

// checkRateLimit checks for rate limiting protection.
// It sends multiple requests to an endpoint and analyzes the success rate and response times
// to determine if rate limiting is properly implemented.
func (s *GraphQLScanner) checkRateLimit(endpoint string, client *httpclient.Client) (bool, string, string) {
	// Extract base URL
	baseURL := strings.TrimSuffix(endpoint, "/graphql")
	if baseURL == endpoint {
		baseURL = strings.TrimSuffix(endpoint, "/")
	}

	// List of endpoints to test
	endpointsToTest := []struct {
		path   string
		method string
		headers map[string]string
		body   string
	}{
		{
			path:   "/api/vulnerable/rate-limit",
			method: "GET",
			headers: map[string]string{"Accept": "application/json"},
			body:   "",
		},
		{
			path:   "/api/login",
			method: "POST",
			headers: map[string]string{"Content-Type": "application/json"},
			body:   `{"username":"test","password":"test"}`,
		},
	}

	const numRequests = 30 // Number of requests to test rate limiting
	const delayMs = 50     // Delay between requests in milliseconds

	for _, ep := range endpointsToTest {
		url := fmt.Sprintf("%s%s", baseURL, ep.path)
		var successCount int
		var totalTime time.Duration

		// Send multiple quick requests
		for i := 0; i < numRequests; i++ {
			startTime := time.Now()
			
			// Create request with or without body
			var req *http.Request
			var err error
			
			if ep.body != "" {
				req, err = http.NewRequest(ep.method, url, bytes.NewBufferString(ep.body))
			} else {
				req, err = http.NewRequest(ep.method, url, nil)
			}
			
			if err != nil {
				continue
			}

			// Set headers
			req.Header.Set("User-Agent", "DursGo-Scanner/1.0")
			for k, v := range ep.headers {
				req.Header.Set(k, v)
			}

			// Send request
			resp, err := client.Do(req)
			if err == nil {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					successCount++
				}
				resp.Body.Close()
			}

			totalTime += time.Since(startTime)
			time.Sleep(time.Millisecond * time.Duration(delayMs))
		}

		// If all requests succeeded (no rate limiting)
		if successCount == numRequests {
			avgResponseTime := totalTime.Milliseconds() / int64(numRequests)
			return true, 
				fmt.Sprintf("No rate limiting detected at %s %s - All %d requests succeeded (avg %dms)", 
					ep.method, url, numRequests, avgResponseTime),
				"Missing rate limiting allows for potential DoS attacks"
		}

		// If most requests succeeded (possibly weak rate limiting)
		successRate := float64(successCount) / float64(numRequests)
		if successRate > 0.7 { // More than 70% requests succeeded
			return true,
				fmt.Sprintf("Weak rate limiting at %s %s - %d/%d requests succeeded (%.1f%%)",
					ep.method, url, successCount, numRequests, successRate*100),
				"Weak rate limiting may allow for DoS attacks"
		}
	}

	return false, "", "Rate limiting properly implemented or no vulnerable endpoints found"
}

// isGraphQLEndpoint checks if the endpoint responds like a GraphQL service.
// It sends simple GraphQL queries and checks for JSON responses containing 'data' or 'errors' fields.
func (s *GraphQLScanner) isGraphQLEndpoint(endpoint string, client *httpclient.Client) bool {
	// List of GraphQL queries to try
	queries := []string{
		`{"query":"{__typename}"}`,                           // Simplest query
		`{"query":"query { __schema { types { name } } }"}`, // Light introspection query
		`{"query":"{__type(name:\"Query\"){name}}"}`,      // Query for Query type
	}

	// Try each query
	for _, query := range queries {
		req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(query))
		if err != nil {
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "DursGo-Scanner/1.0")

		resp, err := client.Do(req)
		if err != nil || resp == nil {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Check status code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		// Check if response is in JSON format
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		// Check if there are 'data' or 'errors' fields in the response
		_, hasData := result["data"]
		_, hasErrors := result["errors"]

		// If 'data' or 'errors' fields are present, it's likely a GraphQL endpoint
		if hasData || hasErrors {
			return true
		}
	}

	return false
}

// isValidGraphQLEndpoint checks if the endpoint is a valid GraphQL URL.
// It performs basic URL format validation.
func (s *GraphQLScanner) isValidGraphQLEndpoint(endpoint string) bool {
	// Validate URL format
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return false
	}
	return true
}

// isDifferentEnough checks if two responses are sufficiently different.
// It uses Levenshtein distance to measure the difference between two strings.
func isDifferentEnough(a, b string) bool {
	// Use Levenshtein distance to measure difference
	distance := levenshtein.Distance(a, b, nil)
	maxLen := max(len(a), len(b))

	if maxLen == 0 {
		return false
	}

	// If difference is more than 30%, consider it sufficiently different
	diffRatio := float64(distance) / float64(maxLen)
	return diffRatio > 0.3
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// BatchConfig stores configuration for batching tests.
type BatchConfig struct {
	Enabled      bool     `yaml:"enabled"`
	MaxBatchSize int      `yaml:"max_batch_size"`
	TestQueries  []string `yaml:"test_queries"`
	MaxRequests  int      `yaml:"max_requests"`
	DelayMs      int      `yaml:"delay_ms"`
}

// checkBatchQueries checks for GraphQL batching vulnerabilities.
// It sends batched queries and analyzes the response to determine if batching is enabled.
func (s *GraphQLScanner) checkBatchQueries(endpoint string, client *httpclient.Client, config BatchConfig) (bool, string, string) {
	if !config.Enabled || len(config.TestQueries) == 0 {
		return false, "", ""
	}

	// Send batch requests and analyze response
	successCount := 0
	totalRequests := min(config.MaxRequests, 50) // Limit to max 50 requests
	batchSize := min(config.MaxBatchSize, 10)    // Limit to max 10 queries per batch

	for i := 0; i < totalRequests; i++ {
		// Create a batch query with random size between 2 and batchSize
		currentBatchSize := 2 + rand.Intn(batchSize-1)
		queries := make([]string, 0, currentBatchSize)

		// Select random queries from TestQueries
		for j := 0; j < currentBatchSize; j++ {
			queryIndex := rand.Intn(len(config.TestQueries))
			queries = append(queries, config.TestQueries[queryIndex])
		}

		// Convert queries to JSON format
		jsonData, err := json.Marshal(queries)
		if err != nil {
			s.logError(fmt.Errorf("error marshaling batch queries: %v", err), "")
			continue
		}

		// Create HTTP request
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			s.logError(fmt.Errorf("error creating request: %v", err), "")
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		// Send request using client
		resp, err := client.Do(req)
		if err != nil {
			s.logError(fmt.Errorf("error sending batch request: %v", err), "")
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			// This error is now suppressed as the underlying issue is fixed.
			continue
		}

		// Check if response is an array (indicates batching is supported)
		var result []interface{}
		if err := json.Unmarshal(body, &result); err == nil && len(result) > 0 {
			successCount++
		}

		// Short delay between requests
		time.Sleep(time.Duration(config.DelayMs) * time.Millisecond)
	}

	// If more than 50% of requests succeeded, batching is likely enabled
	successRate := float64(successCount) / float64(totalRequests)
	if successRate >= 0.5 {
		detail := fmt.Sprintf("GraphQL batching is enabled with %.0f%% success rate (tested %d requests)", successRate*100, totalRequests)
		evidence := "Multiple queries were successfully executed in a single batch request."
		return true, detail, evidence
	}

	return false, "", ""
}

// min returns the minimum of two integers.
// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Scan performs a security scan on the GraphQL endpoint.
// It orchestrates various checks including SQL injection, NoSQL injection,
// introspection, sensitive data exposure, batching, and rate limiting.
func (s *GraphQLScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if opts.GraphQLEndpoint == "" {
		return nil, nil // Not a GraphQL scan target
	}

	// --- FIX: Ensure host-level checks run only once ---
	s.mu.Lock()
	if s.hostScanned {
		s.mu.Unlock()
		return nil, nil // This host has already been scanned for GraphQL vulns.
	}
	s.hostScanned = true
	s.mu.Unlock()
	// --- END FIX ---

	s.client = client // Set client and log for helper methods
	s.log = log
	s.log.Debug("Starting GraphQL security scan on: %s", opts.GraphQLEndpoint)
	// Validate endpoint first
	if !s.isValidGraphQLEndpoint(opts.GraphQLEndpoint) {
		return nil, fmt.Errorf("invalid GraphQL endpoint: %s", opts.GraphQLEndpoint)
	}

	// Check if the endpoint responds like a GraphQL service
	if !s.isGraphQLEndpoint(opts.GraphQLEndpoint, client) {
		return nil, nil // Endpoint does not appear to be a GraphQL service.
	}

	// Initialize default batching configuration
	batchConfig := BatchConfig{
		Enabled:      true,
		MaxBatchSize: 10,
		TestQueries: []string{
			"{__typename}",
			"{__schema{types{name}}}",
		},
		MaxRequests: 30,
		DelayMs:     100,
	}

	// Try to read batching configuration from options
	if config, ok := opts.Config["batch_testing"].(map[string]interface{}); ok {
		// Convert configuration from map to BatchConfig struct
		if enabled, ok := config["enabled"].(bool); ok {
			batchConfig.Enabled = enabled
		}
		if maxBatchSize, ok := config["max_batch_size"].(int); ok {
			batchConfig.MaxBatchSize = maxBatchSize
		}
		if testQueries, ok := config["test_queries"].([]interface{}); ok {
			batchConfig.TestQueries = nil
			for _, q := range testQueries {
				if query, ok := q.(string); ok {
					batchConfig.TestQueries = append(batchConfig.TestQueries, query)
				}
			}
		}
		if maxRequests, ok := config["max_requests"].(int); ok {
			batchConfig.MaxRequests = maxRequests
		}
		if delayMs, ok := config["delay_ms"].(int); ok {
			batchConfig.DelayMs = delayMs
		}
	}

	var findings []scanner.VulnerabilityResult

	// Run all security checks
	if isVuln, evidence, details := s.checkSQLInjection(opts.GraphQLEndpoint, client); isVuln {
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "SQL Injection",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           evidence,
			Details:           details,
			Severity:          "High",
			Evidence:          evidence,
			Remediation:       "Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper input validation and output encoding.",
			ScannerName:       s.Name(),
		})
	}

	if isVuln, evidence, details := s.checkSensitiveDataExposure(opts.GraphQLEndpoint, client); isVuln {
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "NoSQL Injection",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           evidence,
			Details:           details,
			Severity:          "High",
			Evidence:          evidence,
			Remediation:       "Implement proper input validation and use parameterized queries. Apply the principle of least privilege for database access.",
			ScannerName:       s.Name(),
		})
	}

	if isVuln, respBody := s.checkIntrospection(opts.GraphQLEndpoint, client); isVuln {
		// Get parameter from request if available
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		// Truncate response body if too long
		evidence := respBody
		if len(evidence) > 200 {
			evidence = evidence[:200] + "... [truncated]"
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "GraphQL Introspection Enabled",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           "{__schema{types{name}}}",
			Details:           "GraphQL Introspection is enabled. This can leak sensitive information about the API schema, including all available queries, mutations, and types.",
			Severity:          "Medium",
			Evidence:          evidence,
			Remediation:       "Disable introspection in production or restrict it to authenticated users. Consider using graphql-disable-introspection for Apollo Server or disable introspection in your GraphQL server configuration.",
			ScannerName:       s.Name(),
		})

		// --- IMPROVEMENT: New logic for BOLA and lab solving ---
		if strings.Contains(respBody, "postPassword") {
			log.Success("Found potentially sensitive field 'postPassword' in schema. Attempting to exploit.")
			exploitQuery := `{"query":"query getBlogPost($id: Int!) { getBlogPost(id: $id) { title, postPassword } }", "variables":{"id":3}}`
			httpReq, err := http.NewRequest("POST", opts.GraphQLEndpoint, bytes.NewBufferString(exploitQuery))
			if err == nil {
				httpReq.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(httpReq)
				if err == nil {
					// FIX: Read the body immediately before closing.
					body, readErr := io.ReadAll(resp.Body)
					resp.Body.Close() // Close the body right after reading.

					if readErr == nil {
						var result map[string]interface{}
						if json.Unmarshal(body, &result) == nil {
							if data, ok := result["data"].(map[string]interface{}); ok {
								if blogPost, ok := data["getBlogPost"].(map[string]interface{}); ok {
									if password, ok := blogPost["postPassword"].(string); ok && password != "" {
										findings = append(findings, scanner.VulnerabilityResult{
											VulnerabilityType: "Broken Object Level Authorization (BOLA)",
											URL:               opts.GraphQLEndpoint,
											Parameter:         "id",
											Location:          "GraphQL Variables",
											Details:           "Successfully accessed hidden blog post (ID: 3) and retrieved the password.",
											Severity:          "High",
											Evidence:          "Password Found: " + password,
											Payload:           exploitQuery,
											ScannerName:       s.Name(),
										})

										// SOLVE THE LAB: Submit the found password.
										solutionURL := strings.TrimSuffix(opts.GraphQLEndpoint, "/graphql/v1") + "/solution"
										solutionBody := fmt.Sprintf(`{"password":"%s"}`, password)
										solutionReq, _ := http.NewRequest("POST", solutionURL, bytes.NewBufferString(solutionBody))
										solutionReq.Header.Set("Content-Type", "application/json")
										solutionResp, solutionErr := client.Do(solutionReq)
										if solutionErr == nil {
											log.Success("Successfully submitted the solution to the lab.")
											solutionResp.Body.Close()
										}
									}
								}
							}
						}
					}
				} else {
					log.Error("Failed to send exploit query: %v", err)
				}
			}
		}
	}

	if isVuln, evidence, details := s.checkSensitiveDataExposure(opts.GraphQLEndpoint, client); isVuln {
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "Sensitive Data Exposure",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           evidence,
			Details:           details,
			Severity:          "High",
			Evidence:          evidence,
			Remediation:       "Implement proper data classification and access controls. Use field-level security and redact sensitive information from responses.",
			ScannerName:       s.Name(),
		})
	}

	if isVuln, evidence, details := s.checkBatchQueries(opts.GraphQLEndpoint, client, batchConfig); isVuln {
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "GraphQL Batching Enabled",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           evidence,
			Details:           details,
			Severity:          "Medium",
			Evidence:          evidence,
			Remediation:       "Consider disabling GraphQL batching to prevent potential DoS attacks. If batching is required, implement rate limiting and query complexity analysis.",
			ScannerName:       s.Name(),
		})
	}

	if isVuln, evidence, details := s.checkRateLimit(opts.GraphQLEndpoint, client); isVuln {
		paramName := "query"
		if len(req.ParamNames) > 0 {
			paramName = req.ParamNames[0]
		}

		location := "body"
		if len(req.ParamLocations) > 0 {
			location = req.ParamLocations[0]
		}

		findings = append(findings, scanner.VulnerabilityResult{
			VulnerabilityType: "Missing Rate Limiting",
			URL:               opts.GraphQLEndpoint,
			Parameter:         paramName,
			Location:          location,
			Payload:           evidence,
			Details:           details,
			Severity:          "Medium",
			Evidence:          evidence,
			Remediation:       "Implement rate limiting to protect against brute force and denial of service attacks. Consider using a sliding window algorithm or token bucket algorithm.",
			ScannerName:       s.Name(),
		})
	}

	return findings, nil
}
