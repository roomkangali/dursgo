package fingerprint

import (
	"github.com/roomkangali/dursgo/internal/httpclient"
	"github.com/roomkangali/dursgo/internal/logger"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

// Fingerprint is a type to store the results of technology identification.
type Fingerprint map[string]string

// Fingerprinter is the struct for the technology identification engine.
type Fingerprinter struct {
	client *httpclient.Client // HTTP client for making requests.
	log    *logger.Logger     // Logger for outputting messages.
}

// NewFingerprinter creates a new instance of Fingerprinter.
func NewFingerprinter(client *httpclient.Client, log *logger.Logger) *Fingerprinter {
	return &Fingerprinter{
		client: client,
		log:    log,
	}
}

// Analyze runs an analysis on the target URL to identify technologies.
func (f *Fingerprinter) Analyze(targetURL string) Fingerprint {
	result := make(Fingerprint) // Initialize an empty Fingerprint map.

	f.log.Debug("Fingerprinter: Starting analysis on %s", targetURL)

	resp, err := f.client.Get(targetURL)
	if err != nil {
		f.log.Warn("Fingerprinter: Could not fetch target URL for analysis: %v", err)
		return result // Return empty result on fetch error.
	}
	defer resp.Body.Close() // Ensure response body is closed.

	// Analyze HTTP headers for technology clues.
	f.analyzeHeaders(resp, result)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		f.log.Warn("Fingerprinter: Could not read response body: %v", err)
		return result // Return current result on body read error.
	}
	responseBody := string(bodyBytes)

	// Analyze HTML content for technology clues.
	f.analyzeHTMLContent(responseBody, result)

	return result // Return the identified technologies.
}

// analyzeHeaders examines HTTP headers for technology clues.
func (f *Fingerprinter) analyzeHeaders(resp *http.Response, result Fingerprint) {
	// Check "Server" header.
	if server := resp.Header.Get("Server"); server != "" {
		result["WebServer"] = server
		f.log.Debug("Fingerprint: Found Server header: %s", server)
	}
	// Check "X-Powered-By" header.
	if xPoweredBy := resp.Header.Get("X-Powered-By"); xPoweredBy != "" {
		result["X-Powered-By"] = xPoweredBy
		f.log.Debug("Fingerprint: Found X-Powered-By header: %s", xPoweredBy)
	}
	// Check "X-Generator" header.
	if xGenerator := resp.Header.Get("X-Generator"); xGenerator != "" {
		result["X-Generator"] = xGenerator
		f.log.Debug("Fingerprint: Found X-Generator header: %s", xGenerator)
	}
	// Check cookies for specific technology indicators.
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "wordpress_") {
			result["WordPress"] = "Detected from cookie"
			f.log.Debug("Fingerprint: Detected WordPress from cookie: %s", cookie.Name)
		}
		if strings.HasPrefix(cookie.Name, "laravel_session") {
			result["Laravel"] = "Detected from cookie"
			f.log.Debug("Fingerprint: Detected Laravel from cookie: %s", cookie.Name)
		}
	}
}

// analyzeHTMLContent scans the HTML body for technology clues.
func (f *Fingerprinter) analyzeHTMLContent(body string, result Fingerprint) {
	// Check for WordPress specific paths in HTML content.
	if strings.Contains(body, "/wp-content/") || strings.Contains(body, "wp-emoji") {
		if _, exists := result["WordPress"]; !exists { // Only add if not already detected.
			result["WordPress"] = "Detected from HTML content"
			f.log.Debug("Fingerprint: Detected WordPress from HTML content path '/wp-content/'")
		}
	}

	// Parse HTML document to find meta tags.
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return // Return on HTML parsing error.
	}
	var findMeta func(*html.Node) // Recursive function to traverse HTML nodes.
	findMeta = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			var name, content string
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				}
				if a.Key == "content" {
					content = a.Val
				}
			}
			// Check for "generator" meta tag.
			if name == "generator" && content != "" {
				result["Generator"] = content
				f.log.Debug("Fingerprint: Found meta generator tag: %s", content)
			}
		}
		// Recursively call for child nodes.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findMeta(c)
		}
	}
	findMeta(doc) // Start traversal from the document root.
}
