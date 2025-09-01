package csrf

import (
	"github.com/roomkangali/dursgo/internal/crawler"
	"github.com/roomkangali/dursgo/internal/httpclient"
	"github.com/roomkangali/dursgo/internal/logger"
	"github.com/roomkangali/dursgo/internal/payloads"
	"github.com/roomkangali/dursgo/internal/scanner"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// CSRFScanner implements the Scanner interface for Cross-Site Request Forgery.
type CSRFScanner struct{}

// NewCSRFScanner creates a new instance of CSRFScanner.
func NewCSRFScanner() *CSRFScanner {
	return &CSRFScanner{}
}

// Name returns the scanner's name.
func (s *CSRFScanner) Name() string {
	return "Cross-Site Request Forgery (CSRF) Scanner"
}

// Scan performs a CSRF scan on the given parameterized request.
// It checks if a POST form is vulnerable to CSRF by testing for the absence
// or weak validation of CSRF tokens. It skips login/registration and file upload forms.
func (s *CSRFScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, _ scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if req.Method != "POST" || !contains(req.ParamLocations, "body") {
		return nil, nil
	}

	if isLoginForm(req) {
		log.Debug("CSRF: Skipping form at %s because it appears to be a login/registration form.", req.URL)
		return nil, nil
	}
	if isPotentialUploadForm(req) {
		log.Debug("CSRF: Skipping form at %s because it appears to be a file upload form.", req.URL)
		return nil, nil
	}

	log.Debug("Starting CSRF scan for POST form: %s", req.URL)

	originalFormData, _ := url.ParseQuery(req.FormPostData)
	csrfTokenField := ""
	for k := range originalFormData {
		if isCSRFTokenParam(k) {
			csrfTokenField = k
			break
		}
	}

	// --- LOGIC IMPROVEMENT ---
	// If the form does not have a token field at all, THIS IS A VULNERABILITY.
	if csrfTokenField == "" {
		log.Success("CSRF: Found a form at %s without any CSRF token.", req.URL)
		return []scanner.VulnerabilityResult{{
			VulnerabilityType: "Cross-Site Request Forgery (CSRF)",
			URL:               req.URL,
			Location:          "body",
			Details:           "The form does not contain any CSRF token, making it vulnerable to CSRF attacks.",
			Severity:          "High",
			Evidence:          "No CSRF token parameter found in the form.",
			Remediation:       "Implement CSRF protection using synchronizer tokens, SameSite cookies, or double submit tokens.",
			ScannerName:       "csrf",
		}}, nil
	}

	// If a token IS FOUND, proceed with testing for weak token validation.
	log.Debug("CSRF: Found potential token '%s'. Testing for weak validation.", csrfTokenField)

	// ---- Step 1: Get baseline response with original data (only to ensure the form can be processed normally) ----
	_, errBase := submitForm(req, client, log, originalFormData)
	if errBase != nil {
		return nil, nil
	}

	// ---- Step 2: Send request WITHOUT token ----
	manipNoToken := cloneValues(originalFormData)
	manipNoToken.Del(csrfTokenField)
	noTokenSnap, _ := submitForm(req, client, log, manipNoToken)
	if noTokenSnap.status == http.StatusOK || noTokenSnap.status == http.StatusFound {
		details := fmt.Sprintf("Request without CSRF token was accepted (status %d).", noTokenSnap.status)
		return []scanner.VulnerabilityResult{{
			VulnerabilityType: "Cross-Site Request Forgery (CSRF)",
			URL:               req.URL,
			Location:          "body",
			Details:           details,
			Severity:          "medium",
			Evidence:          "Token omitted and server response matched baseline.",
			Remediation:       "Implement CSRF protection using synchronizer tokens, SameSite cookies, or double submit tokens.",
			ScannerName:       "csrf",
		}}, nil
	}

	// ---- Step 3: Send request with a bad token ----
	badTokenValue := "dursgo_bad_csrf_token_test"
	manipBad := cloneValues(originalFormData)
	manipBad.Set(csrfTokenField, badTokenValue)
	badTokenSnap, _ := submitForm(req, client, log, manipBad)
	if badTokenSnap.status == http.StatusOK || badTokenSnap.status == http.StatusFound {
		details := fmt.Sprintf("Request with invalid CSRF token was accepted (status %d).", badTokenSnap.status)
		return []scanner.VulnerabilityResult{{
			VulnerabilityType: "Cross-Site Request Forgery (CSRF)",
			URL:               req.URL,
			Location:          "body",
			Details:           details,
			Severity:          "medium",
			Evidence:          "Invalid token accepted.",
			Remediation:       "Implement CSRF protection using synchronizer tokens, SameSite cookies, or double submit tokens.",
			ScannerName:       "csrf",
		}}, nil
	}

	log.Debug("CSRF: Baseline differed from manipulated requests. Form appears protected.")
	return nil, nil
}

// ---- Helper functions ----
// respSnapshot captures key aspects of an HTTP response for comparison.
type respSnapshot struct {
	status   int
	bodyHash string
	location string
}

// hashBody generates a SHA256 hash of the response body.
func hashBody(b string) string {
	h := sha256.Sum256([]byte(b))
	return fmt.Sprintf("%x", h[:])
}

// statusAndLocationMatch checks if the status code and location header of two snapshots match.
func statusAndLocationMatch(a, b respSnapshot) bool {
	return a.status == b.status && a.location == b.location
}

// snapshotsEqual checks if two response snapshots are identical (status, body hash, and location).
func snapshotsEqual(a, b respSnapshot) bool {
	return a.status == b.status && a.location == b.location
}

// cloneValues creates a deep copy of url.Values.
func cloneValues(v url.Values) url.Values {
	c := url.Values{}
	for k, vals := range v {
		for _, val := range vals {
			c.Add(k, val)
		}
	}
	return c
}

// submitForm sends a POST request with the given data and returns a response snapshot.
// It temporarily disables redirects to capture the immediate response status and location.
func submitForm(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, data url.Values) (respSnapshot, error) {
	httpReq, _ := http.NewRequest("POST", req.URL, strings.NewReader(data.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	originalCheckRedirect := client.TemporarilyDisableRedirects()
	defer client.RestoreRedirects(originalCheckRedirect)

	resp, err := client.Do(httpReq)
	if err != nil && !strings.Contains(err.Error(), "use last response") {
		if resp != nil {
			resp.Body.Close()
		}
		return respSnapshot{}, err
	}
	if resp == nil {
		return respSnapshot{}, fmt.Errorf("nil resp")
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	locationHeader := resp.Header.Get("Location")

	return respSnapshot{
		status:   resp.StatusCode,
		bodyHash: hashBody(bodyString),
		location: locationHeader,
	}, nil
}

// getValidTokenFromPage fetches a page and attempts to extract a valid CSRF token from its HTML.
func getValidTokenFromPage(sourceURL string, client *httpclient.Client, log *logger.Logger) string {
	if sourceURL == "" {
		return ""
	}
	log.Debug("CSRF: Fetching source page %s to get a valid token", sourceURL)
	resp, err := client.Get(sourceURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	doc, err := html.Parse(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return ""
	}

	var tokenValue string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			isTokenField := false
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
					if isCSRFTokenParam(name) {
						isTokenField = true
					}
				}
				if a.Key == "value" {
					value = a.Val
				}
			}
			if isTokenField && value != "" {
				log.Debug("CSRF: Found valid token field '%s' with value '%s...'", name, value[:min(10, len(value))])
				tokenValue = value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return tokenValue
}

// guessSourcePage attempts to guess the source page URL for a given action URL.
func guessSourcePage(actionURL string) string {
	u, err := url.Parse(actionURL)
	if err != nil {
		return ""
	}

	pathParts := strings.Split(u.Path, "/")
	if len(pathParts) > 1 {
		dirPath := strings.Join(pathParts[:len(pathParts)-1], "/")
		if strings.Contains(dirPath, "csrf") {
			u.Path = dirPath + "/csrf_test_home.php"
			return u.String()
		}
	}
	return ""
}

// isLoginForm checks if the request appears to be for a login or registration form.
func isLoginForm(req crawler.ParameterizedRequest) bool {
	lowerPath := strings.ToLower(req.Path)
	if strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "signin") || strings.Contains(lowerPath, "auth") {
		return true
	}
	for _, p := range req.ParamNames {
		lowerP := strings.ToLower(p)
		if lowerP == "password" || lowerP == "pass" || lowerP == "user_pass" {
			return true
		}
	}
	return false
}

// isPotentialUploadForm checks if the request appears to be for a file upload form.
func isPotentialUploadForm(req crawler.ParameterizedRequest) bool {
	for _, paramName := range req.ParamNames {
		lowerParam := strings.ToLower(paramName)
		if lowerParam == "file" || lowerParam == "ufile" || lowerParam == "upload" {
			return true
		}
	}
	return false
}

// isCSRFTokenParam checks if a parameter name is likely a CSRF token field.
func isCSRFTokenParam(p string) bool {
	l := strings.ToLower(p)
	for _, n := range payloads.CommonCSRFTokenNames {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

// responseIndicatesTokenFailure checks if the response body contains keywords indicating CSRF token validation failure.
func responseIndicatesTokenFailure(b string) bool {
	l := strings.ToLower(b)
	for _, k := range payloads.CSRFTokenValidationFailedKeywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
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

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
