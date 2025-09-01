package domxss

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"Dursgo/internal/scanner"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// DOMXSSScanner implements the Scanner interface for DOM-Based XSS.
type DOMXSSScanner struct{}

// NewDOMXSSScanner creates a new instance of DOMXSSScanner.
func NewDOMXSSScanner() *DOMXSSScanner { return &DOMXSSScanner{} }

// Name returns the scanner's name.
func (s *DOMXSSScanner) Name() string { return "Intelligent DOM-Based XSS Scanner" }

// confirmExecutionViaJSProtocol handles payloads using the 'javascript:' protocol.
// It navigates to the clean URL, then directly evaluates the JS code from the payload,
// which is more reliable than assigning to window.location.href and avoids syntax errors.
func confirmExecutionViaJSProtocol(ctx context.Context, targetURL, payload, marker string, log *logger.Logger) bool {
	markerSelector := "#" + marker
	// Strip the "javascript:" prefix to get the raw code to execute.
	jsCode := strings.TrimPrefix(payload, "javascript:")

	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var success bool
	err := chromedp.Run(runCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(1*time.Second),  // Allow page to settle
		chromedp.Evaluate(jsCode, nil), // Directly execute the JS code
		chromedp.ActionFunc(func(ctx context.Context) error {
			waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
			defer waitCancel()
			if err := chromedp.Run(waitCtx, chromedp.WaitVisible(markerSelector, chromedp.ByID)); err == nil {
				success = true
			}
			return nil
		}),
	)

	if err != nil {
		log.Debug("DOMXSS Exploit (JS Proto): Error during execution: %v", err)
		return false
	}

	if success {
		log.Success("DOMXSS Exploit (JS Proto): Element with marker '%s' found in DOM!", marker)
		return true
	}

	log.Debug("DOMXSS Exploit (JS Proto): Element with marker '%s' not found.", marker)
	return false
}

// confirmExecution checks if a DOM XSS payload successfully executed by looking for a marker element.
// This function navigates to a URL with the payload in the fragment and waits for a specific
// HTML element (marker) to appear in the DOM, indicating successful execution.
func confirmExecution(ctx context.Context, targetURL, payload, marker string, log *logger.Logger) bool {
	exploitURL := targetURL + "#" + payload
	markerSelector := "#" + marker

	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	err := chromedp.Run(runCtx,
		chromedp.Navigate(exploitURL),
		chromedp.WaitVisible(markerSelector, chromedp.ByID),
	)

	if err == nil {
		log.Success("DOMXSS Exploit: Element with marker '%s' found in DOM!", marker)
		return true
	}

	log.Debug("DOMXSS Exploit: Element with marker '%s' not found. Error: %v", marker, err)
	return false
}

// isReflectedInDOM checks if a probe string is reflected in the DOM.
// This function navigates to a URL with a probe in the fragment and evaluates
// JavaScript to determine if the probe string is present in the document's innerHTML.
func isReflectedInDOM(ctx context.Context, targetURL, probe string, log *logger.Logger) bool {
	var isFound bool
	probeURL := targetURL + "#" + probe
	checkScript := fmt.Sprintf(`document.body.innerHTML.includes('%s')`, probe)

	// Set a timeout for this probe task.
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	err := chromedp.Run(probeCtx,
		chromedp.Navigate(probeURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(checkScript, &isFound),
	)

	if err != nil {
		log.Warn("DOMXSS Probe: Failed during reflection check: %v", err)
		return false
	}

	if isFound {
		log.Debug("DOMXSS Probe: Reflection detected for probe '%s' at %s", probe, targetURL)
	}
	return isFound
}

// testFragmentDOMXSS contains the existing fragment-based scanning logic.
// It first probes for reflection in the URL fragment and then attempts to
// inject DOM XSS payloads if reflection is confirmed.
func (s *DOMXSSScanner) testFragmentDOMXSS(allocatorContext context.Context, req crawler.ParameterizedRequest, log *logger.Logger) []scanner.VulnerabilityResult {
	log.Debug("DOMXSS (Fragment): Starting probe-then-attack scan on: %s", req.URL)

	// Phase 1: Probe
	probeCtx, cancelProbe := chromedp.NewContext(allocatorContext)
	defer cancelProbe()
	probe := fmt.Sprintf("DursgoProbe%d", rand.Intn(1e9))
	if !isReflectedInDOM(probeCtx, req.URL, probe, log) {
		log.Debug("DOMXSS (Fragment): Probe was not reflected. Aborting fragment-based scan.")
		return nil
	}

	// Phase 2: Attack
	log.Success("DOMXSS (Fragment): Probe reflected. Proceeding with exploit payloads.")
	for _, testCase := range payloads.DOMXSSPayloads {
		exploitCtx, cancelExploit := chromedp.NewContext(allocatorContext)
		defer cancelExploit()

		marker := fmt.Sprintf("dursgo-proof-%d", rand.Intn(1e9))
		payloadWithMarker := strings.Replace(testCase.Payload, "DURSGO_DOM_XSS_MARKER", marker, -1)

		var executed bool
		if strings.HasPrefix(testCase.Payload, "javascript:") {
			log.Debug("DOMXSS (Fragment): Testing javascript: protocol payload via Evaluate.")
			executed = confirmExecutionViaJSProtocol(exploitCtx, req.URL, payloadWithMarker, marker, log)
		} else {
			log.Debug("DOMXSS (Fragment): Testing HTML injection payload via Navigate.")
			executed = confirmExecution(exploitCtx, req.URL, payloadWithMarker, marker, log)
		}

		if executed {
			return []scanner.VulnerabilityResult{{
				VulnerabilityType: "DOM-Based Cross-Site Scripting (via URL Fragment)",
				URL:               req.URL + "#" + payloadWithMarker,
				Payload:           payloadWithMarker,
				Location:          "URL Fragment (#)",
				Details:           fmt.Sprintf("A probe was reflected and a payload successfully created a new element. Description: %s", testCase.Description),
				Severity:          "High",
				Evidence:          fmt.Sprintf("An HTML element with unique ID '#%s' was injected and found in the DOM.", marker),
				Remediation:       "Avoid writing user-controllable data into dangerous HTML sinks like 'innerHTML'. Use safe alternatives like 'textContent' and implement trusted-types CSP.",
				ScannerName:       s.Name(),
			}}
		}
	}
	return nil
}

// testPostMessageDOMXSS contains logic for scanning web message vulnerabilities.
// It first detects if a 'message' event listener is present and then attempts
// to exploit it by sending crafted postMessages with XSS payloads.
func (s *DOMXSSScanner) testPostMessageDOMXSS(allocatorContext context.Context, req crawler.ParameterizedRequest, log *logger.Logger) []scanner.VulnerabilityResult {
	log.Debug("DOMXSS (postMessage): Starting scan on: %s", req.URL)

	// 'Spy' script to detect 'message' event listeners.
	const listenerSpyScript = `
		window.dursgo_hasMessageListener = false;
		const originalAddEventListener = window.addEventListener;
		window.addEventListener = function(type, listener, options) {
			if (type === 'message') {
				window.dursgo_hasMessageListener = true;
			}
			originalAddEventListener.apply(this, arguments);
		};
	`

	// Phase 1: Listener Detection
	detectCtx, cancelDetect := chromedp.NewContext(allocatorContext)
	defer cancelDetect()

	var hasListener bool
	err := chromedp.Run(detectCtx,
		// Use AddScriptToEvaluateOnNewDocument to avoid race conditions
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(listenerSpyScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(req.URL),
		chromedp.Sleep(2*time.Second), // Give time for the original page script to run and add listeners.
		chromedp.Evaluate(`window.dursgo_hasMessageListener`, &hasListener),
	)

	if err != nil || !hasListener {
		log.Debug("DOMXSS (postMessage): No 'message' event listener detected. Aborting scan.")
		return nil
	}

	// Phase 2: Attack
	log.Success("DOMXSS (postMessage): 'message' event listener detected. Proceeding with exploit payloads.")
	for _, testCase := range payloads.DOMXSSPayloads {
		exploitCtx, cancelExploit := chromedp.NewContext(allocatorContext)
		defer cancelExploit()

		marker := fmt.Sprintf("dursgo-proof-%d", rand.Intn(1e9))
		payloadWithMarker := strings.Replace(testCase.Payload, "DURSGO_DOM_XSS_MARKER", marker, -1)

		// Replace single quotes to avoid breaking JavaScript string
		jsPayload := strings.ReplaceAll(payloadWithMarker, "'", `\'`)

		postMessageScript := fmt.Sprintf(`window.postMessage('%s', '*')`, jsPayload)
		markerSelector := "#" + marker

		var found bool
		err := chromedp.Run(exploitCtx,
			chromedp.Navigate(req.URL),
			chromedp.Sleep(1*time.Second), // Wait for page to be ready
			chromedp.Evaluate(postMessageScript, nil),
			// Wait up to 5 seconds for the proof element to appear
			chromedp.ActionFunc(func(ctx context.Context) error {
				waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
				defer waitCancel()
				if err := chromedp.Run(waitCtx, chromedp.WaitVisible(markerSelector, chromedp.ByID)); err == nil {
					found = true
				}
				return nil
			}),
		)

		if err == nil && found {
			log.Success("DOMXSS (postMessage): Payload successfully executed and injected marker element!")
			return []scanner.VulnerabilityResult{{
				VulnerabilityType: "DOM-Based Cross-Site Scripting (via postMessage)",
				URL:               req.URL,
				Payload:           payloadWithMarker,
				Location:          "postMessage event data",
				Details:           fmt.Sprintf("The page listens for web messages and writes message data to the DOM unsafely. Payload Description: %s", testCase.Description),
				Severity:          "High",
				Evidence:          fmt.Sprintf("An HTML element with unique ID '#%s' was injected into the DOM via postMessage.", marker),
				Remediation:       "Always validate the origin of incoming messages. Avoid writing message data into dangerous HTML sinks like 'innerHTML'. Use safe alternatives like 'textContent'.",
				ScannerName:       s.Name(),
			}}
		}
	}

	return nil
}

// Scan now acts as an orchestrator that calls both scanning methods.
// It checks if the headless browser is enabled and if the page is HTML before proceeding.
func (s *DOMXSSScanner) Scan(req crawler.ParameterizedRequest, _ *httpclient.Client, log *logger.Logger, opts scanner.ScannerOptions) ([]scanner.VulnerabilityResult, error) {
	if opts.Renderer == nil {
		log.Debug("DOMXSS: Skipping scan because headless browser is not enabled (--render-js).")
		return nil, nil
	}

	// Check Content-Type using GET for higher reliability.
	getReq, _ := http.NewRequest("GET", req.URL, nil)
	getResp, err := opts.Client.Do(getReq)
	if err != nil {
		return nil, nil
	}
	// Ensure body is closed to prevent resource leaks.
	io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	if !strings.Contains(getResp.Header.Get("Content-Type"), "text/html") {
		log.Debug("DOMXSS: Skipping non-HTML page: %s (Content-Type: %s)", req.URL, getResp.Header.Get("Content-Type"))
		return nil, nil
	}

	rand.Seed(time.Now().UnixNano())
	allocatorContext := opts.Renderer.GetAllocatorContext()
	var findings []scanner.VulnerabilityResult

	// 1. Run Fragment-based scan
	fragmentFindings := s.testFragmentDOMXSS(allocatorContext, req, log)
	if fragmentFindings != nil {
		findings = append(findings, fragmentFindings...)
		// If found, we can stop for efficiency.
		return findings, nil
	}

	// 2. Run postMessage-based scan
	postMessageFindings := s.testPostMessageDOMXSS(allocatorContext, req, log)
	if postMessageFindings != nil {
		findings = append(findings, postMessageFindings...)
	}

	return findings, nil
}
