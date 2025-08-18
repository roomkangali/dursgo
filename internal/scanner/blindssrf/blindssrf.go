package blindssrf

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/scanner"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BlindSSRFScanner implements the Scanner interface for Blind SSRF.
type BlindSSRFScanner struct{}

// NewBlindSSRFScanner creates a new instance.
func NewBlindSSRFScanner() *BlindSSRFScanner {
	return &BlindSSRFScanner{}
}

// Name returns the scanner's name.
func (s *BlindSSRFScanner) Name() string {
	return "Blind SSRF Scanner (OAST)"
}

// isPotentialSSRFParam is a heuristic to check if a parameter name is common for SSRF.
func isPotentialSSRFParam(paramName string) bool {
	lowerParam := strings.ToLower(paramName)
	// "url" is a substring of "reportUrl", "image_url", etc.
	// "dest" is a substring of "destination".
	// "redirect" is a substring of "redirect_uri".
	commonNames := []string{"url", "uri", "dest", "redirect", "path", "site", "feed", "image"}
	for _, name := range commonNames {
		if strings.Contains(lowerParam, name) {
			return true
		}
	}
	return false
}

// commonSSRFHeaders lists common HTTP headers that are often vulnerable to SSRF.
var commonSSRFHeaders = []string{
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Real-IP",
	"Client-IP",
	"X-Client-IP",
	"X-Custom-IP-Authorization",
	"X-Originating-IP",
	"User-Agent",
}

// Scan injects OAST payloads for out-of-band detection.
func (s *BlindSSRFScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if opts.OASTDomain == "" || opts.OASTCorrelationMap == nil {
		return nil, nil
	}
	rand.Seed(time.Now().UnixNano())

	var wg sync.WaitGroup
	log.Debug("Starting Blind SSRF scan for %s %s...", req.Method, req.URL)

	// --- Test Parameters (Query and Body) ---
	for _, paramName := range req.ParamNames {
		if !isPotentialSSRFParam(paramName) {
			continue
		}
		for _, paramLoc := range req.ParamLocations {
			if !((req.Method == "GET" && paramLoc == "query") || (req.Method == "POST" && paramLoc == "body")) {
				continue
			}
			wg.Add(1)
			go s.testParameterInjection(&wg, req, client, log, opts, paramName, paramLoc)
		}
	}

	// --- Test Headers ---
	for _, headerName := range commonSSRFHeaders {
		wg.Add(1)
		go s.testHeaderInjection(&wg, req, client, log, opts, headerName)
	}

	wg.Wait()
	return nil, nil
}

// testParameterInjection handles the logic for testing a single parameter.
func (s *BlindSSRFScanner) testParameterInjection(wg *sync.WaitGroup, req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions, paramName, paramLoc string) {
	defer wg.Done()
	oastPayloads := generateOASTPayloads(opts.OASTDomain, fmt.Sprintf("ssrf-param-%s", paramName))

	for _, payload := range oastPayloads {
		potentialVuln := scanner.VulnerabilityResult{
			VulnerabilityType: "Blind SSRF (OAST)",
			URL:               req.URL,
			Parameter:         paramName,
			Payload:           payload,
			Location:          paramLoc,
			Details:           fmt.Sprintf("OAST interaction confirmed for payload injected into '%s' parameter.", paramName),
			Severity:          "High",
			Evidence:          fmt.Sprintf("Payload %s was sent to a suspected SSRF parameter and triggered an OAST interaction.", payload),
			Remediation:       "Validate and sanitize all user-controlled URLs. Block access to internal resources (e.g., AWS metadata, internal APIs). Use allowlists.",
			ScannerName:       s.Name(),
		}
		opts.OASTCorrelationMap.Store(extractCorrelationID(payload), potentialVuln)

		testURL, reqBody := buildRequestComponents(req, paramName, payload)
		httpRequest, _ := http.NewRequest(req.Method, testURL, reqBody)
		addCommonHeaders(httpRequest) // Make the request look legitimate
		if req.Method == "POST" {
			httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		log.Debug("BlindSSRF: Injecting OAST payload '%s' into param '%s'", payload, paramName)
		client.Do(httpRequest)
	}
}

// testHeaderInjection handles the logic for testing a single header.
func (s *BlindSSRFScanner) testHeaderInjection(wg *sync.WaitGroup, req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions, headerName string) {
	defer wg.Done()
	oastPayloads := generateOASTPayloads(opts.OASTDomain, fmt.Sprintf("ssrf-header-%s", strings.ToLower(headerName)))

	for _, payload := range oastPayloads {
		potentialVuln := scanner.VulnerabilityResult{
			VulnerabilityType: "Blind SSRF (OAST)",
			URL:               req.URL,
			Parameter:         headerName,
			Payload:           payload,
			Location:          "header",
			Details:           fmt.Sprintf("OAST interaction confirmed for payload injected into '%s' header.", headerName),
			Severity:          "High",
			Evidence:          fmt.Sprintf("Payload %s was sent to a suspected SSRF header and triggered an OAST interaction.", payload),
			Remediation:       "Validate and sanitize all user-controlled URLs. Block access to internal resources (e.g., AWS metadata, internal APIs). Use allowlists.",
			ScannerName:       s.Name(),
		}
		opts.OASTCorrelationMap.Store(extractCorrelationID(payload), potentialVuln)

		// Send a single, well-formed attack request.
		attackURL, attackBody := buildRequestComponents(req, "", "")
		attackReq, _ := http.NewRequest(req.Method, attackURL, attackBody)
		addCommonHeaders(attackReq) // Make the request look legitimate
		if req.Method == "POST" {
			attackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		attackReq.Header.Set(headerName, payload)

		log.Debug("BlindSSRF: Injecting OAST payload '%s' into header '%s'", payload, headerName)
		client.Do(attackReq)
		// A small delay is still useful to avoid overwhelming the server and the OAST service.
		time.Sleep(200 * time.Millisecond)
	}
}

// buildRequestComponents is a helper to build the request with the payload.
func buildRequestComponents(req crawler.ParameterizedRequest, paramToInject, valueToInject string) (string, io.Reader) {
	var originalParams url.Values
	if req.Method == "GET" {
		p, _ := url.Parse(req.URL)
		originalParams = p.Query()
	} else {
		originalParams, _ = url.ParseQuery(req.FormPostData)
	}

	testParams := url.Values{}
	for k, v := range originalParams {
		testParams[k] = v
	}

	if paramToInject != "" {
		testParams.Set(paramToInject, valueToInject)
	}

	if req.Method == "GET" {
		baseURL, _ := url.Parse(req.URL)
		baseURL.RawQuery = testParams.Encode()
		return baseURL.String(), nil
	}
	return req.URL, strings.NewReader(testParams.Encode())
}

// generateOASTPayloads creates a slice of various OAST payloads for a given base domain and prefix.
func generateOASTPayloads(oastDomain, prefix string) []string {
	correlationID := fmt.Sprintf("%s-%d", prefix, rand.Intn(1e9))
	fullOASTDomain := fmt.Sprintf("%s.%s", correlationID, oastDomain)

	payloads := []string{
		fmt.Sprintf("http://%s", fullOASTDomain),
		fmt.Sprintf("https://%s", fullOASTDomain),
		fmt.Sprintf("%s", fullOASTDomain),
		fmt.Sprintf("http://%s:80", fullOASTDomain),
		fmt.Sprintf("https://%s:443", fullOASTDomain),
		fmt.Sprintf("http://%s/path", fullOASTDomain),
		fmt.Sprintf("http://%s?q=test", fullOASTDomain),
	}
	return payloads
}

// extractCorrelationID extracts the correlation ID from an OAST payload URL.
func extractCorrelationID(payloadURL string) string {
	re := regexp.MustCompile(`(http[s]?://)?([^/]+)\.`)
	matches := re.FindStringSubmatch(payloadURL)
	if len(matches) > 2 {
		hostnameParts := strings.Split(matches[2], ".")
		if len(hostnameParts) > 0 {
			return hostnameParts[0]
		}
	}
	return ""
}

// addCommonHeaders adds a set of standard browser headers to a request to make it look legitimate.
func addCommonHeaders(req *http.Request) {
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Ch-Ua", `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
}
