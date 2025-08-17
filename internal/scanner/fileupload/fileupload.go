package fileupload

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"bytes"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// FileUploadScanner implements the Scanner interface for Unrestricted File Upload vulnerabilities.
type FileUploadScanner struct{}

// NewFileUploadScanner creates a new instance of FileUploadScanner.
func NewFileUploadScanner() *FileUploadScanner {
	return &FileUploadScanner{}
}

// Name returns the scanner's name.
func (s *FileUploadScanner) Name() string {
	return "Unrestricted File Upload Scanner"
}

// Scan performs a scan for unrestricted file upload vulnerabilities.
// It attempts to upload malicious files and verifies if they are accessible and executable.
func (s *FileUploadScanner) Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	var findings []scanner.VulnerabilityResult
	if req.Method != "POST" {
		return nil, nil
	}

	if strings.Contains(req.URL, "delete.php") {
		return nil, nil
	}

	var fileParamName string
	for _, pName := range req.ParamNames {
		if isPotentialUploadParam(pName) {
			fileParamName = pName
			break
		}
	}
	if fileParamName == "" {
		return nil, nil
	}

	log.Debug("Fileupload: Starting scan on form at %s...", req.URL)

	// --- Generic Upload Test ---
	shellFilename := fmt.Sprintf("dursgo_shell_%d.php", time.Now().UnixNano())
	shellContent := "<?php echo 'DURSGO_UPLOAD_CONFIRMED'; ?>"
	if found, vuln := s.testUpload(req, client, log, opts, fileParamName, shellFilename, []byte(shellContent), "image/jpeg", "DURSGO_UPLOAD_CONFIRMED"); found {
		findings = append(findings, vuln)
		return findings, nil
	}

	// --- Payload-Based Tests (Magic Header, etc.) ---
	for _, testCase := range payloads.FileUploadTests {
		marker := fmt.Sprintf("dursgo_marker_%d", time.Now().UnixNano())
		contentWithMarker := bytes.Replace(testCase.Content, []byte("dursgo_magic_header"), []byte(marker), -1)
		contentWithMarker = bytes.Replace(contentWithMarker, []byte("dursgo_secret"), []byte(marker), -1)

		if found, vuln := s.testUpload(req, client, log, opts, fileParamName, testCase.FileName, contentWithMarker, testCase.ContentType, marker); found {
			findings = append(findings, vuln)
			return findings, nil
		}
	}

	return findings, nil
}

// testUpload performs a file upload test and verifies its success.
// It attempts to upload a file with given content and type, then checks for its accessibility and a marker.
func (s *FileUploadScanner) testUpload(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions, paramName, fileName string, fileContent []byte, contentType, marker string) (bool, scanner.VulnerabilityResult) {
	uploadResp, err := s.performUploadRequest(req, client, log, paramName, fileName, fileContent, contentType)
	if err != nil {
		log.Debug("Fileupload: Upload request for '%s' failed: %v", fileName, err)
		return false, scanner.VulnerabilityResult{}
	}
	defer uploadResp.Body.Close()
	bodyBytes, _ := io.ReadAll(uploadResp.Body)
	bodyString := string(bodyBytes)

	if uploadResp.StatusCode != http.StatusOK {
		log.Debug("Fileupload: Upload request for '%s' returned non-200 status: %d. Response body: %s", fileName, uploadResp.StatusCode, bodyString)
		return false, scanner.VulnerabilityResult{}
	}
	// Even with 200 OK, some apps return an error message in the body.
	log.Debug("Fileupload: Received 200 OK for '%s' upload. Response body: %s", fileName, bodyString)

	// --- New Logic: Check for file path in response body ---
	re := regexp.MustCompile(`File path:\s*([^\s<]+)`)
	matches := re.FindStringSubmatch(bodyString)

	if len(matches) > 1 {
		foundPath := matches[1]
		log.Debug("Fileupload: Extracted file path from response body: %s", foundPath)

		baseUploadURL, err := url.Parse(req.URL)
		if err == nil {
			// Resolve the relative path against the request URL's path
			u, err := baseUploadURL.Parse(foundPath)
			if err == nil {
				potentialURL := u.String()
				// Check this URL immediately, no need for extra sleep
				if s.checkURL(client, potentialURL, marker, log) {
					vuln := scanner.VulnerabilityResult{
						VulnerabilityType: "Unrestricted File Upload (RCE)",
						URL:               req.URL,
						Parameter:         paramName,
						Payload:           fileName,
						Location:          "body (multipart/form-data)",
						Details:           fmt.Sprintf("Successfully uploaded a malicious file '%s' and confirmed its execution at %s. Path was found directly in the server response.", fileName, potentialURL),
						Severity:          "Critical",
						Evidence:          marker,
						Remediation:       "Validate file types on the server-side using file content and extensions. Store uploaded files in a non-web-accessible directory.",
						ScannerName:       s.Name(),
					}
					return true, vuln
				}
			}
		}
	}
	// --- End of New Logic ---

	log.Debug("Fileupload: Path not in response body. Falling back to standard verification for '%s'...", fileName)

	// Add a short delay to give the server time to process the file
	time.Sleep(5 * time.Second)

	verifiedURL := s.verifyUpload(req, client, log, opts, fileName, marker)
	if verifiedURL != "" {
		vuln := scanner.VulnerabilityResult{
			VulnerabilityType: "Unrestricted File Upload (RCE)",
			URL:               req.URL,
			Parameter:         paramName,
			Payload:           fileName,
			Location:          "body (multipart/form-data)",
			Details:           fmt.Sprintf("Successfully uploaded a malicious file '%s' and confirmed its execution at %s", fileName, verifiedURL),
			Severity:          "Critical",
			Evidence:          marker,
			Remediation:       "Validate file types on the server-side using file content and extensions. Store uploaded files in a non-web-accessible directory.",
			ScannerName:       s.Name(),
		}
		return true, vuln
	}

	return false, scanner.VulnerabilityResult{}
}

// performUploadRequest constructs and sends a multipart/form-data upload request.
// It includes the specified file content and other original form parameters.
func (s *FileUploadScanner) performUploadRequest(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, paramName, fileName string, fileContent []byte, contentType string) (*http.Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, paramName, fileName))
	h.Set("Content-Type", contentType)
	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, err
	}
	_, err = part.Write(fileContent)
	if err != nil {
		return nil, err
	}

	originalFormData, _ := url.ParseQuery(req.FormPostData)
	for key, values := range originalFormData {
		if key != paramName {
			for _, value := range values {
				writer.WriteField(key, value)
			}
		}
	}

	// Explicitly add common submit parameters, as many applications check for them.
	writer.WriteField("submit", "Upload")
	writer.Close()

	uploadReq, _ := http.NewRequest("POST", req.URL, body)
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())

	return client.Do(uploadReq)
}

// verifyUpload attempts to verify the successful upload and execution of a file.
// It first tries to find a link to the uploaded file in the rendered HTML (if headless browser is enabled),
// then falls back to guessing common upload paths.
func (s *FileUploadScanner) verifyUpload(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions, fileName, marker string) string {
	baseUploadURL, err := url.Parse(req.URL)
	if err != nil {
		return ""
	}

	if opts.Renderer != nil {
		verificationPageURL := req.SourceURL
		if verificationPageURL == "" {
			verificationPageURL = req.URL
		}

		log.Debug("Fileupload: Using headless browser to find link on verification page: %s", verificationPageURL)
		renderedHTML, err := opts.Renderer.GetRenderedHTML(verificationPageURL, 15*time.Second)
		if err != nil {
			log.Warn("Fileupload: Failed to get rendered HTML: %v", err)
		} else {
			re := regexp.MustCompile(`(href|src)\s*=\s*['"]([^'"]*` + regexp.QuoteMeta(fileName) + `[^'"]*)['"]`)
			matches := re.FindStringSubmatch(renderedHTML)
			if len(matches) > 2 {
				foundPath := strings.TrimSpace(html.UnescapeString(matches[2]))
				log.Success("Fileupload: Found link to uploaded file in RENDERED DOM: %s", foundPath)
				
				u, err := baseUploadURL.Parse(foundPath)
				if err == nil {
					potentialURL := u.String()
					if s.checkURL(client, potentialURL, marker, log) {
						return potentialURL
					}
				}
			}
		}
	}

	log.Debug("Fileupload: Could not verify via rendered DOM. Falling back to path guessing.")
	cleanPath := baseUploadURL.Path
	if !strings.HasSuffix(cleanPath, "/") {
		lastSlash := strings.LastIndex(cleanPath, "/")
		if lastSlash != -1 {
			cleanPath = cleanPath[:lastSlash+1]
		}
	}

	possiblePaths := []string{
		cleanPath + "uploads/" + fileName,
		cleanPath + fileName,
		cleanPath + "../uploads/" + fileName,
		cleanPath + "../../uploads/" + fileName,
		"/uploads/" + fileName,
		"/files/" + fileName,
		"/media/" + fileName,
		"/assets/uploads/" + fileName,
		"/" + fileName,
	}

	for _, path := range possiblePaths {
		potentialURL := baseUploadURL.Scheme + "://" + baseUploadURL.Host + path
		if s.checkURL(client, potentialURL, marker, log) {
			return potentialURL
		}
	}

	return ""
}

// checkURL verifies if the uploaded file is accessible and contains the expected marker.
func (s *FileUploadScanner) checkURL(client *httpclient.Client, url, marker string, log *logger.Logger) bool {
	log.Debug("Fileupload: Verifying at URL: %s", url)
	verifyResp, err := client.Get(url)
	if err != nil {
		return false
	}

	// Check if status code is 2xx (success)
	if verifyResp.StatusCode < 200 || verifyResp.StatusCode > 299 {
		verifyResp.Body.Close()
		return false
	}
	defer verifyResp.Body.Close()

	verifyBody, _ := io.ReadAll(verifyResp.Body)
	if strings.Contains(string(verifyBody), marker) {
		log.Success("Fileupload: Verification successful at %s", url)
		return true
	}
	return false
}

// isPotentialUploadParam checks if a parameter name is commonly associated with file uploads.
func isPotentialUploadParam(p string) bool {
	lowerParam := strings.ToLower(p)
	commonNames := []string{"file", "ufile", "upload", "filetoupload", "image", "picture", "avatar", "input_image", "image_file"}
	for _, name := range commonNames {
		if strings.Contains(lowerParam, name) {
			return true
		}
	}
	return false
}
