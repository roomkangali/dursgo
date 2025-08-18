package cors

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// publicPathsCORS lists common public, stateless endpoints where CORS reflection is expected and benign.
var publicPathsCORS = []string{"/wp-json/", "/api/", "/feeds", "/rss", "/atom", "/sitemap", "/openapi", "/.well-known/"}

type CORSScanner struct {
	mu          sync.Mutex
	urlsScanned map[string]bool
}

func NewCORSScanner() *CORSScanner {
	return &CORSScanner{urlsScanned: make(map[string]bool)}
}

func (s *CORSScanner) Name() string {
	return "CORS Misconfiguration Scanner"
}

func (s *CORSScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	targetURL := req.URL

	s.mu.Lock()
	if s.urlsScanned[targetURL] {
		s.mu.Unlock()
		return nil, nil
	}
	s.urlsScanned[targetURL] = true
	s.mu.Unlock()

	log.Debug("Running CORS check on: %s", targetURL)

	for _, testCase := range payloads.CORSTests {
		httpRequest, _ := http.NewRequest("GET", targetURL, nil)
		httpRequest.Header.Set("Origin", testCase.OriginHeader)

		resp, err := client.Do(httpRequest)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue
		}
		defer resp.Body.Close()

		acaoHeader := resp.Header.Get("Access-Control-Allow-Origin")
		acacHeader := resp.Header.Get("Access-Control-Allow-Credentials")
		setCookie := resp.Header.Get("Set-Cookie") != ""
		hasRealCookie := httpRequest.Header.Get("Cookie") != ""
		authHeader := httpRequest.Header.Get("Authorization") != ""

		vulnerable := false
		details := ""
		severity := testCase.Severity

		// Flag vulnerability only when it actually poses a risk:
		// 1. Wildcard * **and** credentials allowed (ACAC:true)
		// 2. Reflected arbitrary origin **and** credentials allowed (ACAC:true)
		// 3. Origin "null" accepted (common browser quirk abuse)
		if acaoHeader == "*" && strings.EqualFold(acacHeader, "true") {
			vulnerable = true
			details = fmt.Sprintf("Server allows all origins ('Access-Control-Allow-Origin: *') **while also** allowing credentials. Severity: %s.", testCase.Severity)
		} else if strings.EqualFold(acaoHeader, testCase.OriginHeader) {
			if testCase.OriginHeader == "null" {
				vulnerable = true
				details = fmt.Sprintf("Server allows 'null' origin ('Access-Control-Allow-Origin: null'). Severity: %s.", testCase.Severity)
			} else if strings.EqualFold(acacHeader, "true") {
				// Only mark reflected origin as vulnerable when credentials are also allowed
				vulnerable = true
				details = fmt.Sprintf("Server reflects arbitrary Origin header ('Access-Control-Allow-Origin: %s') **and** allows credentials. Severity: %s.", acaoHeader, testCase.Severity)
			}
		}

		// --- Reduce false positives on public stateless endpoints ---
		if vulnerable {
			credsInvolved := setCookie || hasRealCookie || authHeader
			isPublic := false
			for _, p := range publicPathsCORS {
				if strings.Contains(targetURL, p) {
					isPublic = true
					break
				}
			}
			if isPublic && !credsInvolved {
				// benign scenario – skip reporting entirely
				vulnerable = false
			} else if !credsInvolved {
				// downgrade severity if no real credentials/ state
				severity = "Low"
			}
		}

		if vulnerable {
			if strings.EqualFold(acacHeader, "true") {
				details += " This is more severe because 'Access-Control-Allow-Credentials' is set to 'true'."
			}

			evidence := fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acaoHeader, acacHeader)
			remediation := "Do not reflect arbitrary Origin headers or use wildcards. Validate and explicitly whitelist trusted origins. Avoid using 'Access-Control-Allow-Credentials: true' with wildcards or dynamic origins."

			findings = append(findings, scanner.VulnerabilityResult{
				VulnerabilityType: "CORS Misconfiguration",
				URL:               targetURL,
				Payload:           fmt.Sprintf("Origin: %s", testCase.OriginHeader),
				Details:           details,
				Severity:          severity,
				Evidence:          evidence,
				Remediation:       remediation,
				ScannerName:       s.Name(),
			})
			return findings, nil
		}
	}
	return findings, nil
}
