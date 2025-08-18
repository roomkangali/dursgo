package scanner

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Manager orchestrates the execution of multiple scanners.
// It manages a collection of registered scanners and runs them against a set of requests.
type Manager struct {
	scanners   []Scanner
	httpClient *httpclient.Client
	logger     *logger.Logger
	options    ScannerOptions
}

// NewManager creates a new scanner manager.
func NewManager(client *httpclient.Client, log *logger.Logger, opts ScannerOptions) *Manager {
	return &Manager{
		httpClient: client,
		logger:     log,
		options:    opts,
		scanners:   make([]Scanner, 0),
	}
}

// RegisterScanner adds a scanner to the manager.
func (m *Manager) RegisterScanner(s Scanner) {
	m.scanners = append(m.scanners, s)
	m.logger.Debug("ScannerManager: Registered scanner: %s", s.Name())
}

// RunScans executes all registered scanners against a list of requests.
// It implements a smart targeting logic to optimize scanning by identifying
// representative parameters based on reflection signatures.
func (m *Manager) RunScans(requests []crawler.ParameterizedRequest) []VulnerabilityResult {
	if len(m.scanners) == 0 || len(requests) == 0 {
		return nil
	}

	m.logger.Info("ScannerManager: Starting vulnerability scanning on %d requests...", len(requests))
	var allFindings []VulnerabilityResult
	var findingsMu sync.Mutex

	// --- SMART TARGETING LOGIC (Temporarily Disabled for Debugging) ---
	// The original logic is preserved below but commented out.
	/*
		optimizedRequests := make(map[string]crawler.ParameterizedRequest)

		for _, req := range requests {
			// Only optimize if there are more than 2 parameters.
			if len(req.ParamNames) <= 2 {
				optimizedRequests[req.Method+req.URL] = req
				continue
			}

			m.logger.Debug("SmartTargeting: Analyzing %d parameters for %s %s", len(req.ParamNames), req.Method, req.URL)

			reflectionSignatures := make(map[string]string)
			var representativeParams []string
			rand.Seed(time.Now().UnixNano()) // Initialize random seed
			probeMarker := fmt.Sprintf("dursgoprobe%d", rand.Intn(1e9))

			for _, paramName := range req.ParamNames {
				signature := m.getReflectionSignature(req, paramName, probeMarker)

				if _, exists := reflectionSignatures[signature]; !exists {
					reflectionSignatures[signature] = paramName
					representativeParams = append(representativeParams, paramName)
					m.logger.Debug("SmartTargeting: Parameter '%s' is a new representative for signature: %s", paramName, signature)
				} else {
					m.logger.Debug("SmartTargeting: Parameter '%s' has a duplicate signature. Skipping full scan.", paramName)
				}
			}

			optimizedReq := req
			optimizedReq.ParamNames = representativeParams
			optimizedRequests[req.Method+req.URL] = optimizedReq
			m.logger.Info("SmartTargeting: Optimized %s %s from %d to %d parameters.", req.Method, req.URL, len(req.ParamNames), len(representativeParams))
		}

		finalRequests := make([]crawler.ParameterizedRequest, 0, len(optimizedRequests))
		for _, req := range optimizedRequests {
			finalRequests = append(finalRequests, req)
		}
	*/
	finalRequests := requests // Bypass optimization
	// --- END SMART TARGETING LOGIC ---

	jobs := make(chan crawler.ParameterizedRequest, len(finalRequests))
	var wg sync.WaitGroup
	numWorkers := m.options.Concurrency
	if numWorkers > len(finalRequests) {
		numWorkers = len(finalRequests)
	}
	if numWorkers == 0 && len(finalRequests) > 0 {
		numWorkers = 1
	}

	m.logger.Debug("ScannerManager: Initializing %d worker(s) for optimized scanning.", numWorkers)

	// --- Start Spinner ---
	done := make(chan bool)
	go func() {
		spinner := []string{"/", "-", "\\", "|"}
		i := 0
		for {
			select {
			case <-done:
				fmt.Print("\r") // Clear the spinner line
				return
			default:
				fmt.Printf("\rScanning... %s ", spinner[i])
				i = (i + 1) % len(spinner)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	// --- End Spinner ---

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range jobs {
				for _, s := range m.scanners {
					findings, err := s.Scan(req, m.httpClient, m.logger, m.options)
					if err != nil {
						m.logger.Error("Scanner %s failed for %s: %v", s.Name(), req.URL, err)
						continue
					}
					if len(findings) > 0 {
						findingsMu.Lock()
						allFindings = append(allFindings, findings...)
						findingsMu.Unlock()
					}
				}
			}
		}()
	}

	for _, req := range finalRequests {
		jobs <- req
	}
	close(jobs)
	wg.Wait()

	done <- true // Stop the spinner
	// --- End Spinner Stop ---

	m.logger.Info("ScannerManager: All scanning workers finished. Found %d total potential vulnerabilities.", len(allFindings))
	return allFindings
}

// getReflectionSignature is a new helper function to create a "fingerprint".
// It sends a probe value in a parameter and analyzes how it's reflected in the response
// to create a unique signature for reflection behavior.
func (m *Manager) getReflectionSignature(req crawler.ParameterizedRequest, paramName, probeValue string) string {
	var testURL string
	var reqBody io.Reader

	originalParams, _ := url.ParseQuery(req.FormPostData)
	if req.Method == "GET" {
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			m.logger.Debug("SmartTargeting: Failed to parse URL %s for probe. Skipping.", req.URL)
			return "error_parsing_url"
		}
		queryParams := parsedURL.Query()
		queryParams.Set(paramName, probeValue)
		parsedURL.RawQuery = queryParams.Encode()
		testURL = parsedURL.String()
	} else { // POST
		testURL = req.URL
		formData := url.Values{}
		for k, v := range originalParams {
			formData[k] = v
		}
		formData.Set(paramName, probeValue)
		reqBody = strings.NewReader(formData.Encode())
	}

	// --- KEY FIX: Adding missing error handling ---
	httpRequest, err := http.NewRequest(req.Method, testURL, reqBody)
	if err != nil {
		m.logger.Debug("SmartTargeting: Could not create probe request for %s: %v", testURL, err)
		return "error_creating_request" // Return a unique error fingerprint
	}

	if req.Method == "POST" {
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := m.httpClient.Do(httpRequest)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return "error_fetching"
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	responseBody := string(bodyBytes)

	// Create a fingerprint based on how the probeValue is reflected.
	reflectionCount := strings.Count(responseBody, probeValue)
	isEncoded := strings.Contains(responseBody, url.QueryEscape(probeValue)) && !strings.Contains(responseBody, probeValue)

	return fmt.Sprintf("count:%d-encoded:%t", reflectionCount, isEncoded)
}

// GetRegisteredScanners returns a slice of registered scanners.
func (m *Manager) GetRegisteredScanners() []Scanner {
	return m.scanners
}
