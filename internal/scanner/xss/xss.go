package xss

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// --- Reflected XSS Scanner ---

type ReflectedXSSScanner struct{}

func NewReflectedXSSScanner() scanner.Scanner { return &ReflectedXSSScanner{} }

func (s *ReflectedXSSScanner) Name() string { return "xss-reflected" }

// verifyXSS checks for XSS vulnerabilities with improved false positive detection.
// It returns true if a vulnerability is found, along with the evidence.
func (s *ReflectedXSSScanner) verifyXSS(body []byte, detectionRegex *regexp.Regexp, payloadTemplate string) (bool, string) {
	rawBody := string(body)
	decodedBody := html.UnescapeString(rawBody)

	// Check if the payload pattern is found in the decoded response.
	if !detectionRegex.MatchString(decodedBody) {
		return false, "" // No match, no vulnerability.
	}

	// Match found. Now, check for signs of a false positive.
	// A false positive occurs if the payload is reflected but HTML-encoded by the server.
	isEncoded := (strings.Contains(payloadTemplate, "<") && strings.Contains(rawBody, "&lt;")) ||
		(strings.Contains(payloadTemplate, ">") && strings.Contains(rawBody, "&gt;")) ||
		(strings.Contains(payloadTemplate, "\"") && strings.Contains(rawBody, "&quot;")) ||
		(strings.Contains(payloadTemplate, "'") && (strings.Contains(rawBody, "&#39;") || strings.Contains(rawBody, "&#x27;")))

	// If the payload pattern does NOT match the raw body, and we detected encoding, it's a false positive.
	if !detectionRegex.MatchString(rawBody) && isEncoded {
		return false, "" // It's a false positive, ignore it.
	}

	// If we are here, it's either a raw reflection (true positive) or a complex case.
	// We consider it a valid finding.
	evidence := detectionRegex.FindString(decodedBody)
	return true, evidence
}

func (s *ReflectedXSSScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	rand.Seed(time.Now().UnixNano())

	log.Debug("[%s] Processing request: %s %s", s.Name(), req.Method, req.URL)

	for _, paramName := range req.ParamNames {
		for _, paramLoc := range req.ParamLocations {
			if !((req.Method == "GET" && paramLoc == "query") || (req.Method == "POST" && paramLoc == "form")) {
				continue
			}

			detectedContexts := detectReflectionContexts(req, paramName, client, log)
			if len(detectedContexts) == 0 {
				continue
			}

		PayloadLoop:
			for _, testCase := range payloads.XSSTests {
				if _, contextMatch := detectedContexts[testCase.Context]; !contextMatch {
					continue
				}

				uniqueMarker := fmt.Sprintf("%s%d", payloads.XSSMarker, rand.Intn(1e9))
				payload := strings.Replace(testCase.PayloadTemplate, "DURSGO_MARKER", uniqueMarker, -1)
				detectionRegexStr := strings.Replace(testCase.DetectionRegex, "DURSGO_MARKER", uniqueMarker, -1)
				detectionRegex, _ := regexp.Compile(detectionRegexStr)

				testURL, reqBody := buildRequestComponents(req, paramName, payload)
				httpRequest, _ := http.NewRequest(req.Method, testURL, reqBody)
				if req.Method == "POST" {
					httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}

				resp, err := client.Do(httpRequest)
				if err != nil {
					if resp != nil {
						resp.Body.Close()
					}
					continue
				}
				if resp.Body == nil {
					continue
				}

				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				// Pass the payload template to the verification function for more accurate checking.
				if found, evidence := s.verifyXSS(bodyBytes, detectionRegex, testCase.PayloadTemplate); found {
					contentType := resp.Header.Get("Content-Type")
					if !strings.Contains(strings.ToLower(contentType), "text/html") {
						continue
					}

					finalEvidence := evidence
					if finalEvidence == "" {
						finalEvidence = payload
					}

					details := fmt.Sprintf(
						"Injected payload was executed in a '%s' context. Description: %s",
						testCase.Context, testCase.Description,
					)

					vuln := scanner.VulnerabilityResult{
						VulnerabilityType: "Reflected XSS",
						URL:               testURL,
						Parameter:         paramName,
						Payload:           payload,
						Location:          paramLoc,
						Details:           details,
						Severity:          "high",
						Evidence:          finalEvidence,
						Remediation:       "Sanitize user input and implement proper output encoding based on context.",
						ScannerName:       s.Name(),
					}
					findings = append(findings, vuln)
					// [REVERT] Restore original logic to stop after the first valid finding for efficiency.
					break PayloadLoop
				}
			}
		}
	}
	return findings, nil
}

// --- Stored XSS Scanner ---

type StoredXSSScanner struct{}

func NewStoredXSSScanner() scanner.Scanner { return &StoredXSSScanner{} }

func (s *StoredXSSScanner) Name() string { return "xss-stored" }

func (s *StoredXSSScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if !(req.Method == "POST" && isStoredXSSForm(req)) {
		return nil, nil
	}

	// [PERBAIKAN] Coba logika baru yang lebih canggih terlebih dahulu.
	if req.SourceURL != "" {
		findings, err := s.scanWithSourceURL(req, client, log)
		// Jika ada temuan atau error (selain error "tidak ditemukan"), kembalikan.
		if err != nil || len(findings) > 0 {
			return findings, err
		}
	}
	
	// Jika logika baru tidak menemukan apa-apa, jalankan logika lama sebagai fallback.
	log.Debug("[%s] Falling back to legacy Stored XSS check for: %s", s.Name(), req.URL)
	return submitAndVerifyStoredXSS(req, client, log)
}

// [FUNGSI BARU] Logika baru yang menggunakan SourceURL
func (s *StoredXSSScanner) scanWithSourceURL(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger) ([]scanner.VulnerabilityResult, error) {
	verificationURL := req.SourceURL
	log.Debug("StoredXSS-Advanced: Verifying on SourceURL: %s", verificationURL)

	// 1. Dapatkan halaman sumber untuk CSRF
	resp, err := client.Get(verificationURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	pageBody, _ := io.ReadAll(resp.Body)

	csrfRegex := regexp.MustCompile(`name="csrf"[^>]*value="([^"]+)"`)
	csrfMatch := csrfRegex.FindStringSubmatch(string(pageBody))
	if len(csrfMatch) < 2 {
		log.Warn("StoredXSS-Advanced: Could not find CSRF token on page %s.", verificationURL)
		return nil, nil
	}
	csrfToken := csrfMatch[1]
	log.Debug("StoredXSS-Advanced: Found CSRF token: %s", csrfToken)

	// 2. Coba payload
	payload := "<script>alert(1)</script>"
	detectionRegex := regexp.MustCompile(regexp.QuoteMeta(payload))

	formData := buildCommentFormData(req, payload, csrfToken)

	// 3. Kirim komentar
	postReq, _ := http.NewRequest("POST", req.URL, strings.NewReader(formData.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Referer", verificationURL)
	
	submitResp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	submitResp.Body.Close()

	// 4. Verifikasi
	time.Sleep(2 * time.Second)
	verifyResp, err := client.Get(verificationURL)
	if err != nil {
		return nil, err
	}
	defer verifyResp.Body.Close()
	verifyBody, _ := io.ReadAll(verifyResp.Body)

	if detectionRegex.Match(verifyBody) {
		log.Success("Stored XSS detected on verification page!")
		return []scanner.VulnerabilityResult{{
			VulnerabilityType: "Stored XSS",
			URL:               verificationURL,
			Parameter:         "comment",
			Payload:           payload,
			Details:           "Stored XSS successfully executed on blog comment page.",
			Severity:          "High",
			ScannerName:       s.Name(),
		}}, nil
	}

	return nil, nil
}

// --- Helper Functions (Shared) ---

func isStoredXSSForm(req crawler.ParameterizedRequest) bool {
	storedEndpoints := []string{"comment", "message", "post", "review", "feedback"}
	for _, endpoint := range storedEndpoints {
		if strings.Contains(strings.ToLower(req.URL), endpoint) {
			return true
		}
	}
	storedParams := []string{"content", "message", "body", "text", "comment"}
	for _, param := range req.ParamNames {
		for _, storedParam := range storedParams {
			if strings.EqualFold(param, storedParam) {
				return true
			}
		}
	}
	return false
}

func submitAndVerifyStoredXSS(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult

	// Find the injectable parameter (e.g., 'comment' or 'content')
	var injectableParam string
	for _, pName := range req.ParamNames {
		if pName == "content" || pName == "comment" {
			injectableParam = pName
			break
		}
	}
	if injectableParam == "" {
		log.Debug("[%s] No injectable parameter (e.g., 'comment', 'content') found in form.", "xss-stored")
		return nil, nil // No point in continuing
	}

	productURL := getVerificationURL(req.URL)
	if productURL == req.URL {
		return nil, nil
	}

	log.Debug("Testing Stored XSS on %s, will verify at: %s", req.URL, productURL)

	// --- Preliminary Probe Check ---
	probeMarker := fmt.Sprintf("dursgoStoredProbe%d", rand.Intn(1e9))
	log.Debug("[%s] Injecting probe '%s' into parameter '%s'", "xss-stored", probeMarker, injectableParam)

	// Get original page to extract CSRF token and have a baseline
	originalProductPage, err := client.Get(productURL)
	if err != nil {
		return nil, nil
	}
	originalBody, _ := io.ReadAll(originalProductPage.Body)
	originalProductPage.Body.Close() // Close body immediately after reading

	// Build and send the probe request
	probeFormData := url.Values{}
	csrfRegex := regexp.MustCompile(`name="_csrf_token"[^>]*value="([^"]+)"`)
	csrfToken := ""
	if matches := csrfRegex.FindStringSubmatch(string(originalBody)); len(matches) > 1 {
		csrfToken = matches[1]
	}

	for _, param := range req.ParamNames {
		if (param == "_csrf_token" || param == "csrf_token") && csrfToken != "" {
			probeFormData.Set(param, csrfToken)
		} else if param == injectableParam {
			probeFormData.Set(param, probeMarker)
		} else if param == "rating" {
			probeFormData.Set(param, "5")
		} else if !strings.HasPrefix(param, "_") {
			probeFormData.Set(param, "test")
		}
	}

	probePostReq, _ := http.NewRequest("POST", req.URL, strings.NewReader(probeFormData.Encode()))
	probePostReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	probePostReq.Header.Set("Referer", req.URL)
	probeResp, err := client.Do(probePostReq)
	if err != nil {
		return nil, err
	}
	probeResp.Body.Close()

	time.Sleep(500 * time.Millisecond)

	// Verify if the probe is reflected
	verifyProbeResp, err := client.Get(productURL)
	if err != nil {
		return nil, err
	}
	verifyProbeBody, _ := io.ReadAll(verifyProbeResp.Body)
	verifyProbeResp.Body.Close()

	if !strings.Contains(string(verifyProbeBody), probeMarker) {
		log.Debug("[%s] Probe marker not found on verification page. Aborting Stored XSS payload testing for %s.", "xss-stored", injectableParam)
		return nil, nil // ABORT: Parameter is not reflective.
	}

	log.Debug("[%s] Probe marker FOUND. Proceeding with full XSS payload testing.", "xss-stored")

	// --- Full Payload Testing (only if probe was successful) ---
	for _, testCase := range payloads.XSSTests {
		uniqueMarker := fmt.Sprintf("%s%d", payloads.XSSMarker, rand.Intn(1e9))
		payload := strings.Replace(testCase.PayloadTemplate, "DURSGO_MARKER", uniqueMarker, -1)
		detectionRegexStr := strings.Replace(testCase.DetectionRegex, "DURSGO_MARKER", uniqueMarker, -1)
		detectionRegex, _ := regexp.Compile(detectionRegexStr)

		formData := url.Values{}
		for _, param := range req.ParamNames {
			if (param == "_csrf_token" || param == "csrf_token") && csrfToken != "" {
				formData.Set(param, csrfToken)
			} else if param == injectableParam {
				formData.Set(param, payload)
			} else if param == "rating" {
				formData.Set(param, "5")
			} else if !strings.HasPrefix(param, "_") {
				formData.Set(param, "test")
			}
		}

		postReq, _ := http.NewRequest("POST", req.URL, strings.NewReader(formData.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Referer", req.URL)

		resp, err := client.Do(postReq)
		if err != nil {
			continue
		}
		resp.Body.Close()

		time.Sleep(500 * time.Millisecond)

		verifyResp, err := client.Get(productURL)
		if err != nil {
			continue
		}
		newBody, _ := io.ReadAll(verifyResp.Body)
		verifyResp.Body.Close()

		if detectionRegex.Match(newBody) && !detectionRegex.Match(originalBody) {
			findings = append(findings, scanner.VulnerabilityResult{
				VulnerabilityType: "Stored XSS",
				URL:               productURL,
				Parameter:         injectableParam,
				Location:          "body",
				Payload:           payload,
				Details:           fmt.Sprintf("Stored XSS detected in comments at %s.", productURL),
				Severity:          "high",
				ScannerName:       "xss-stored",
			})
			return findings, nil // Found a vulnerability, exit immediately.
		}
	}

	return findings, nil
}

func getVerificationURL(formURL string) string {
	if strings.Contains(formURL, "/comment") {
		parts := strings.Split(formURL, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return formURL
}

func buildCommentFormData(req crawler.ParameterizedRequest, payload, csrfToken string) url.Values {
	formData := url.Values{}
	re := regexp.MustCompile(`postId=(\d+)`)
	match := re.FindStringSubmatch(req.SourceURL)
	postId := "1" 
	if len(match) > 1 {
		postId = match[1]
	}

	formData.Set("csrf", csrfToken)
	formData.Set("postId", postId)
	formData.Set("comment", payload)
	formData.Set("name", "DursgoUser")
	formData.Set("email", "test@roomkangali.com")
	formData.Set("website", "https://roomkangali.com")
	return formData
}

func detectReflectionContexts(req crawler.ParameterizedRequest, paramName string, client *httpclient.Client, log *logger.Logger) map[string]bool {
	probeMarker := fmt.Sprintf("dursgoprobe%d", rand.Intn(1e9))
	testURL, reqBody := buildRequestComponents(req, paramName, probeMarker)

	httpRequest, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		log.Debug("Error creating request for context detection: %v", err)
		return nil
	}

	
	if req.Method == "POST" {
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(httpRequest)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		log.Debug("Error during context detection request for param '%s': %v", paramName, err)
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug("Error reading response body for context detection: %v", err)
		return nil
	}
	responseBody := string(bodyBytes)

	contexts := make(map[string]bool)
	indices := []int{}
	for i := strings.Index(responseBody, probeMarker); i != -1; i = strings.Index(responseBody[i+1:], probeMarker) {
		if len(indices) > 10 {
			break
		}
		indices = append(indices, i)
	}

	if len(indices) == 0 {
		log.Debug("Parameter '%s' does not appear to be reflected.", paramName)
		return nil
	}

	log.Info("Parameter '%s' is reflected in %d locations. Analyzing contexts...", paramName, len(indices))

	for _, index := range indices {
		precedingText := safeSubstring(responseBody, index-15, index)
		followingText := safeSubstring(responseBody, index+len(probeMarker), index+len(probeMarker)+15)

		if strings.Contains(precedingText, "<script>") && strings.Contains(followingText, "</script>") {
			log.Debug("Context for '%s' at index %d: JS", paramName, index)
			contexts["JS"] = true
			continue
		}

		lastQuote := strings.LastIndexAny(precedingText, `"'`)
		if lastQuote != -1 {
			quoteChar := string(precedingText[lastQuote])
			if strings.HasPrefix(followingText, quoteChar) {
				log.Debug("Context for '%s' at index %d: Attribute", paramName, index)
				contexts["Attribute"] = true
				continue
			}
		}

		if strings.Contains(precedingText, "<") && strings.Contains(followingText, ">") {
			log.Debug("Context for '%s' at index %d: HTML (in-tag)", paramName, index)
			contexts["HTML"] = true
			continue
		}

		log.Debug("Context for '%s' at index %d: HTML (default)", paramName, index)
		contexts["HTML"] = true
	}

	return contexts
}

func buildRequestComponents(req crawler.ParameterizedRequest, paramToInject, valueToInject string) (string, io.Reader) {
	parsedURL, _ := url.Parse(req.URL)
	params := parsedURL.Query()
	var body io.Reader

	if req.Method == "POST" && req.FormPostData != "" {
		params, _ = url.ParseQuery(req.FormPostData)
	}

	params.Set(paramToInject, valueToInject)

	if req.Method == "POST" {
		bodyParams := url.Values{}
		urlParams := url.Values{}
		originalPostParams, _ := url.ParseQuery(req.FormPostData)

		for key := range params {
			if _, isBodyParam := originalPostParams[key]; isBodyParam || key == paramToInject {
				bodyParams.Set(key, params.Get(key))
			} else {
				urlParams.Set(key, params.Get(key))
			}
		}
		body = strings.NewReader(bodyParams.Encode())
		parsedURL.RawQuery = urlParams.Encode()
	} else {
		parsedURL.RawQuery = params.Encode()
	}

	return parsedURL.String(), body
}

func safeSubstring(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	if start > end {
		return ""
	}
	return s[start:end]
}
