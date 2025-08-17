package crawler

import (
	"crypto/sha1"
	"crypto/sha256"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/renderer"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

// excludedExtensions defines file types that are not relevant for vulnerability scanning.
var excludedExtensions = []string{
	// Images
	".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico",
	// Stylesheets
	".css",
	// Fonts
	".woff", ".woff2", ".ttf", ".eot",
	// Archives
	".zip", ".rar", ".tar", ".gz",
	// Documents
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	// Media
	".mp3", ".mp4", ".avi", ".mov", ".flv", ".wmv",
}

// OpenAPIv3 represents the structure for parsing OpenAPI/Swagger files.
type OpenAPIv3 struct {
	Paths map[string]interface{} `json:"paths" yaml:"paths"`
}

// SourceMap represents the structure of a .map file, used for JavaScript source map analysis.
type SourceMap struct {
	Sources []string `json:"sources"`
}

// commonAPISpecPaths holds common names for API specification files to discover.
var commonAPISpecPaths = []string{
	"openapi.json", "swagger.json", "api.json",
	"openapi.yaml", "swagger.yaml", "api.yaml",
	"openapi.yml", "swagger.yml", "api.yml",
	"docs/openapi.json", "docs/swagger.json",
	"docs/openapi.yaml", "docs/swagger.yaml",
	"api/openapi.json", "api/swagger.json",
	"api/openapi.yaml", "api/swagger.yaml",
}

// jsPathRegexes are regular expressions used to extract potential paths from JavaScript files.
var jsPathRegexes []*regexp.Regexp

// init initializes jsPathRegexes once for efficiency.
func init() {
	patterns := []string{
		`(?:"|')((?:/[a-zA-Z0-9_.-]+)+/?)(?:"|')`,          // Absolute paths like "/api/users"
		`(?:"|')(\.\./(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+)(?:"|')`, // Relative paths like "../data/config.json"
		`(?:"|')([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)+)(?:"|')`,      // Paths without leading slash like "assets/js/main.js"
	}
	for _, pattern := range patterns {
		jsPathRegexes = append(jsPathRegexes, regexp.MustCompile(pattern))
	}
}

// commonParameters lists common parameter names to proactively test for reflection.
var commonParameters = []string{
	"id", "q", "search", "query", "keyword", "s",
	"lang", "language", "locale",
	"redirect", "url", "next", "return", "returnTo", "goto", "dest", "destination",
	"view", "page", "p", "pg",
	"file", "path", "document", "folder", "dir",
	"name", "user", "username", "account",
	"message", "msg", "error", "alert", "text",
	"input", "data", "json", "val", "value",
	"item", "category", "product", "type",
	"callback", "jsonp",
	"token", "key", "api_key",
}

// MaxPathSegments defines the maximum number of path segments to crawl to prevent infinite loops.
const MaxPathSegments = 15

// SitemapIndex represents the structure of a sitemap index file.
type SitemapIndex struct {
	XMLName  xml.Name  `xml:"sitemapindex"`
	Sitemaps []Sitemap `xml:"sitemap"`
}

// Sitemap represents a single sitemap entry within a sitemap index.
type Sitemap struct {
	XMLName xml.Name `xml:"sitemap"`
	Loc     string   `xml:"loc"`
	LastMod string   `xml:"lastmod"`
}

// URLSet represents the structure of a standard sitemap file.
type URLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []URL    `xml:"url"`
}

// URL represents a single URL entry within a sitemap.
type URL struct {
	XMLName    xml.Name `xml:"url"`
	Loc        string   `xml:"loc"`
	LastMod    string   `xml:"lastmod"`
	ChangeFreq string   `xml:"changefreq"`
	Priority   string   `xml:"priority"`
}

// ParameterizedRequest holds details of a request with identifiable parameters, suitable for scanning.
type ParameterizedRequest struct {
	Method         string   // HTTP method (GET, POST, etc.)
	URL            string   // Full URL of the request.
	Path           string   // URL path.
	ParamNames     []string // Names of parameters found.
	ParamLocations []string // Locations of parameters (e.g., "query", "body").
	FormPostData   string   // Raw POST data for form submissions.
	SourceURL      string   // URL of the page where the form was discovered.
}

// CrawlJob represents a single unit of work for the crawler.
type CrawlJob struct {
	URL   string // URL to crawl.
	Depth int    // Current crawling depth.
}

// FrameworkType is an enum for detected JavaScript frameworks.
type FrameworkType int

const (
	FrameworkUnknown FrameworkType = iota // No specific framework detected.
	FrameworkNextJS                       // Next.js framework.
	FrameworkNuxtJS                       // Nuxt.js framework.
)

// frameworkConfigFilePaths maps framework types to their common build/config file paths.
var frameworkConfigFilePaths = map[FrameworkType][]string{
	FrameworkNextJS: {
		"/_next/build-manifest.json", // Common Next.js build manifest.
	},
	FrameworkNuxtJS: {}, // Add Nuxt.js specific paths here if needed.
}

// NextJSBuildManifest represents the structure of a Next.js build manifest file.
type NextJSBuildManifest struct {
	Pages map[string][]string `json:"pages"` // Map of page paths to their associated JS files.
}

// getURLHash creates a SHA256 hash of a URL string for deduplication.
func getURLHash(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

// Crawler represents the main crawling engine.
type Crawler struct {
	httpClient            *httpclient.Client          // HTTP client for making requests.
	logger                *logger.Logger              // Logger for outputting messages.
	visitedURLHashes      map[string]bool             // Set of visited URL hashes to prevent redundant crawling.
	urlDepths             map[string]int              // Map to store the depth at which each URL was discovered.
	mu                    sync.Mutex                  // Mutex for protecting concurrent access to shared resources.
	targetDomain          string                      // The base domain of the target application.
	resultsChan           chan string                 // Channel to send discovered URLs to.
	wg                    sync.WaitGroup              // WaitGroup to manage goroutines for crawling.
	maxConcurrency        int                         // Maximum number of concurrent crawling workers.
	queue                 chan CrawlJob               // Channel for distributing crawl jobs to workers.
	robotsDisallowed      map[string]bool             // Map of paths disallowed by robots.txt.
	maxDepth              int                         // Maximum crawling depth.
	parameterizedRequests map[string]ParameterizedRequest // Map to store unique parameterized requests for scanning.
	renderer              *renderer.Renderer          // Headless browser renderer for JavaScript-heavy pages.
	detectedFramework     FrameworkType               // Detected JavaScript framework.
	frameworkChecked      bool                        // Flag to ensure framework detection runs only once.
}

// NewCrawler creates and initializes a new Crawler instance.
func NewCrawler(httpClient *httpclient.Client, log *logger.Logger, targetURL string, maxConcurrency int, maxDepth int, rend *renderer.Renderer) (*Crawler, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	targetDomain := parsedURL.Scheme + "://" + parsedURL.Host
	// Set default concurrency if invalid value is provided.
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}
	// Set default max depth if invalid value is provided.
	if maxDepth < 0 {
		maxDepth = 0
	}
	return &Crawler{
		httpClient:            httpClient,
		logger:                log,
		visitedURLHashes:      make(map[string]bool),
		urlDepths:             make(map[string]int),
		targetDomain:          targetDomain,
		resultsChan:           make(chan string, 100), // Buffered channel for results.
		maxConcurrency:        maxConcurrency,
		queue:                 make(chan CrawlJob, maxConcurrency*2), // Buffered channel for crawl jobs.
		robotsDisallowed:      make(map[string]bool),
		maxDepth:              maxDepth,
		parameterizedRequests: make(map[string]ParameterizedRequest),
		renderer:              rend,
	}, nil
}

// addToQueue adds a new URL to the crawling queue if it meets the criteria.
func (c *Crawler) addToQueue(newURL string, currentDepth int) {
	// Check if the URL should be crawled and is not disallowed by robots.txt.
	if c.shouldCrawl(newURL) && !c.isDisallowedByRobots(newURL) {
		c.markAsVisited(newURL, currentDepth) // Mark URL as visited.
		c.wg.Add(1)                           // Increment WaitGroup counter.
		// Add the crawl job to the queue in a new goroutine to avoid blocking.
		go func() { c.queue <- CrawlJob{URL: newURL, Depth: currentDepth} }()
		c.resultsChan <- newURL // Send the new URL to the results channel.
	}
}

// processJSFile extracts and processes potential endpoints from JavaScript content.
func (c *Crawler) processJSFile(jsContent string, baseURL string, currentDepth int) {
	go func() {
		// Extract source map URL if present.
		sourceMapRegex := regexp.MustCompile(`//# sourceMappingURL=(.+)`)
		matches := sourceMapRegex.FindStringSubmatch(jsContent)
		if len(matches) > 1 {
			sourceMapPath := strings.TrimSpace(matches[1])
			sourceMapURL := c.resolveURL(baseURL, sourceMapPath)
			if sourceMapURL != "" {
				c.fetchAndParseSourceMap(sourceMapURL, currentDepth) // Fetch and parse the source map.
			}
		}
	}()
	c.logger.Debug("JS Extractor: Analyzing JS content from %s", baseURL)
	foundEndpoints := make(map[string]bool)
	// Iterate through regexes to find potential endpoints.
	for _, re := range jsPathRegexes {
		matches := re.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := strings.Trim(match[1], `"' `)
				// Add valid, non-absolute endpoints to the foundEndpoints map.
				if len(endpoint) > 1 && !strings.HasPrefix(endpoint, "http") {
					foundEndpoints[endpoint] = true
				}
			}
		}
	}
	// Add discovered endpoints to the crawling queue.
	if len(foundEndpoints) > 0 {
		c.logger.Success("JS Extractor: Found %d potential endpoints in %s", len(foundEndpoints), baseURL)
		for endpoint := range foundEndpoints {
			resolvedURL := c.resolveURL(baseURL, endpoint)
			if resolvedURL != "" {
				c.logger.Debug("JS Extractor: Adding resolved endpoint to queue: %s", resolvedURL)
				c.addToQueue(resolvedURL, currentDepth)
			}
		}
	}
}

// fetchAndParseSourceMap fetches and parses a JavaScript source map file to discover original source paths.
func (c *Crawler) fetchAndParseSourceMap(sourceMapURL string, currentDepth int) {
	c.logger.Debug("Source Map: Attempting to fetch and parse %s", sourceMapURL)
	resp, err := c.httpClient.Get(sourceMapURL)
	if err != nil {
		c.logger.Warn("Source Map: Failed to fetch %s: %v", sourceMapURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var sm SourceMap
	if err := json.Unmarshal(body, &sm); err != nil {
		c.logger.Warn("Source Map: Failed to parse JSON from %s: %v", sourceMapURL, err)
		return
	}
	if len(sm.Sources) > 0 {
		c.logger.Success("Source Map: Found %d source files in %s", len(sm.Sources), sourceMapURL)
		for _, sourcePath := range sm.Sources {
			// Clean up webpack/source-map specific prefixes.
			cleanedPath := regexp.MustCompile(`^(webpack|source-map):///`).ReplaceAllString(sourcePath, "")
			cleanedPath = strings.TrimPrefix(cleanedPath, ".") // Remove leading dot if present.
			resolvedURL := c.resolveURL(sourceMapURL, cleanedPath)
			if resolvedURL != "" {
				c.logger.Debug("Source Map: Adding discovered source path to queue: %s", resolvedURL)
				c.addToQueue(resolvedURL, currentDepth) // Add resolved source path to the queue.
			}
		}
	}
}

// Crawl starts the crawling process from the given entry points.
// It returns a channel of discovered URLs.
func (c *Crawler) Crawl(entryPoints []string, initialDepth int) chan string {
	c.fetchAndParseRobotsTxt() // Fetch and parse robots.txt.
	for _, baseURL := range entryPoints {
		go c.fetchAndParseAPISpecs(baseURL) // Discover and parse API specifications.
		c.fetchAndParseSitemap(baseURL)     // Discover and parse sitemaps.
		c.addToQueue(baseURL, initialDepth) // Add initial entry points to the queue.
	}
	// Start worker goroutines for concurrent crawling.
	for i := 0; i < c.maxConcurrency; i++ {
		go c.worker()
	}

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
				fmt.Printf("\rCrawling... %s ", spinner[i])
				i = (i + 1) % len(spinner)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	// --- End Spinner ---

	// Goroutine to close channels once all crawling jobs are done.
	go func() {
		c.wg.Wait()         // Wait for all worker goroutines to finish.
		done <- true        // Stop the spinner
		close(c.queue)      // Close the job queue.
		close(c.resultsChan) // Close the results channel.
	}()
	return c.resultsChan // Return the channel for consuming discovered URLs.
}

// worker is a goroutine that processes crawl jobs from the queue.
func (c *Crawler) worker() {
	for job := range c.queue {
		c.crawl(job.URL, job.Depth) // Process each crawl job.
	}
}

// crawl performs the actual crawling of a given URL.
func (c *Crawler) crawl(currentURL string, currentDepth int) {
	defer c.wg.Done() // Decrement WaitGroup counter when the function exits.

	parsedCurrentURL, err := url.Parse(currentURL)
	if err != nil {
		return // Skip if URL parsing fails.
	}

	// Skip URL if path depth limit is exceeded.
	if strings.Count(parsedCurrentURL.Path, "/") > MaxPathSegments {
		c.logger.Debug("Crawler: Skipping %s due to exceeding path depth limit.", currentURL)
		return
	}
	// Skip URL if max crawling depth is exceeded.
	if c.maxDepth > 0 && currentDepth >= c.maxDepth {
		c.logger.Debug("Crawler: Skipping %s due to exceeding max crawl depth.", currentURL)
		return
	}

	c.logger.Debug("Crawling: %s (Depth: %d)", currentURL, currentDepth)

	var bodyString string
	var crawlErr error

	// Use headless browser renderer if enabled.
	if c.renderer != nil {
		c.logger.Debug("Renderer: Using headless browser for %s", currentURL)
		bodyString, crawlErr = c.renderer.GetRenderedHTML(currentURL, 30*time.Second)
	} else {
		// Otherwise, use standard HTTP client.
		resp, httpErr := c.httpClient.Get(currentURL)
		if httpErr != nil {
			return // Skip if HTTP request fails.
		}
		defer resp.Body.Close() // Ensure response body is closed.
		if resp.StatusCode != http.StatusOK {
			return // Skip if response status is not OK.
		}

		contentType := resp.Header.Get("Content-Type")
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return // Skip if reading response body fails.
		}
		bodyString = string(bodyBytes)
		crawlErr = nil // No error if successful.

		// Detect and analyze framework if not already checked.
		c.mu.Lock()
		if !c.frameworkChecked {
			c.detectedFramework = c.detectFramework(string(bodyBytes), resp.Header)
			if c.detectedFramework != FrameworkUnknown {
				c.analyzeFrameworkConfig(currentURL)
			}
			c.frameworkChecked = true
		}
		c.mu.Unlock()

		// Process JavaScript files.
		if strings.Contains(contentType, "javascript") || strings.HasSuffix(currentURL, ".js") {
			c.processJSFile(bodyString, currentURL, currentDepth)
			return // Stop crawling this URL if it's a JS file.
		}
	}

	// Handle crawling errors.
	if crawlErr != nil {
		c.logger.Warn("Failed to get content for %s: %v", currentURL, crawlErr)
		return
	}

	// Parse HTML document.
	doc, err := html.Parse(strings.NewReader(bodyString))
	if err != nil {
		return // Skip if HTML parsing fails.
	}

	// Extract links and forms from the HTML document.
	newLinks, newForms := c.extractLinksAndForms(doc, currentURL)

	// Add new links to the queue.
	for _, newURL := range newLinks {
		c.addToQueue(newURL, currentDepth+1)
	}
	// Add new forms as parameterized requests.
	for _, formReq := range newForms {
		c.addParameterizedRequest(formReq)
	}

	// Add requests with common parameters.
	commonParamRequests := c.addCommonParameters(currentURL)
	for _, req := range commonParamRequests {
		c.logger.Debug("Adding common parameter request: %s", req.URL)
		c.addParameterizedRequest(req)
	}

	// Add requests with existing query parameters.
	if parsedCurrentURL.RawQuery != "" {
		req := ParameterizedRequest{
			Method:         "GET",
			URL:            currentURL,
			Path:           parsedCurrentURL.Path,
			ParamNames:     getKeys(parsedCurrentURL.Query()),
			ParamLocations: []string{"query"},
		}
		c.logger.Debug("Adding request with existing parameters: %s", req.URL)
		c.addParameterizedRequest(req)
	}
}

// extractLinksAndForms extracts links (a, link, script, img) and forms from an HTML document.
func (c *Crawler) extractLinksAndForms(doc *html.Node, baseURL string) ([]string, []ParameterizedRequest) {
	var links []string
	var forms []ParameterizedRequest
	var f func(*html.Node) // Recursive function for traversing HTML nodes.

	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract links from <a>, <link>, <script>, and <img> tags.
			if n.Data == "a" || n.Data == "link" || n.Data == "script" || n.Data == "img" {
				var attrKey string
				// Use 'src' for <script> and <img>, 'href' for <a> and <link>.
				if n.Data == "script" || n.Data == "img" {
					attrKey = "src"
				} else {
					attrKey = "href"
				}
				for _, a := range n.Attr {
					if a.Key == attrKey {
						resolvedURL := c.resolveURL(baseURL, a.Val)
						// Add resolved URL to links if it's within the target domain.
						if resolvedURL != "" && strings.HasPrefix(resolvedURL, c.targetDomain) {
							links = append(links, resolvedURL)
						}
						break // Move to the next tag after finding the relevant attribute.
					}
				}
			}
			// Additional check for <script src="..."> (redundant with above, but kept for clarity).
			if n.Data == "script" {
				for _, a := range n.Attr {
					if a.Key == "src" {
						resolvedURL := c.resolveURL(baseURL, a.Val)
						if resolvedURL != "" && strings.HasPrefix(resolvedURL, c.targetDomain) {
							links = append(links, resolvedURL)
						}
						break
					}
				}
			}
			// Extract forms.
			if n.Data == "form" {
				var action, method, enctype string
				for _, attr := range n.Attr {
					switch strings.ToLower(attr.Key) {
					case "action":
						action = attr.Val
					case "method":
						method = strings.ToUpper(attr.Val)
					case "enctype":
						enctype = strings.ToLower(attr.Val)
					}
				}
				formURL := c.resolveURL(baseURL, action)
				c.logger.Debug("Crawler: Found <form> tag. Raw action='%s', Resolved URL='%s'", action, formURL)
				// Skip form if its URL is empty or out of scope.
				if formURL == "" || !strings.HasPrefix(formURL, c.targetDomain) {
					c.logger.Debug("Crawler: Skipping form, URL is out of scope.")
					return // Return from this recursive call, not the main function.
				}
				if method == "" {
					method = "GET" // Default form method is GET.
				}
				isMultipart := enctype == "multipart/form-data"
				var formParamNames []string
				formInitialValues := url.Values{}
				var findInputs func(*html.Node) // Recursive function to find input elements within the form.
				findInputs = func(node *html.Node) {
					if node.Type == html.ElementNode {
						switch node.Data {
						case "input", "textarea", "select", "button":
							var name, value, elemType string
							for _, attr := range node.Attr {
								switch strings.ToLower(attr.Key) {
								case "name":
									name = attr.Val
								case "value":
									value = attr.Val
								case "type":
									elemType = strings.ToLower(attr.Val)
								}
							}
							// Skip submit/reset buttons without a name.
							if (elemType == "submit" || elemType == "reset") && name == "" {
								return
							}
							if name != "" {
								// For buttons, use inner text as value if value attribute is empty.
								if node.Data == "button" && value == "" && node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
									value = node.FirstChild.Data
								}
								formParamNames = append(formParamNames, name)
								formInitialValues.Add(name, value)
							}
						}
					}
					// Recursively call for child nodes.
					for child := node.FirstChild; child != nil; child = child.NextSibling {
						findInputs(child)
					}
				}
				findInputs(n) // Start finding inputs from the current form node.

				// Add parameterized request if form has named parameters.
				if len(formParamNames) > 0 {
					parsedFormActionURL, _ := url.Parse(formURL)
					paramLocations := []string{"body"} // Default to body for POST forms.
					if method == "GET" {
						paramLocations = []string{"query"} // Use query for GET forms.
					}
					postData := ""
					if !isMultipart {
						postData = formInitialValues.Encode() // Encode form data for non-multipart forms.
					}
					forms = append(forms, ParameterizedRequest{
						Method:         method,
						URL:            formURL,
						Path:           parsedFormActionURL.Path,
						ParamNames:     formParamNames,
						ParamLocations: paramLocations,
						FormPostData:   postData,
						SourceURL:      baseURL, // Store the URL of the page where the form was found.
					})
				} else {
					c.logger.Debug("Crawler: Skipping form because no named parameters were found inside.")
				}
			}
		}
		// Recursively call for child nodes.
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(doc) // Start traversal from the document root.
	return links, forms
}

// detectFramework attempts to identify the JavaScript framework used on a page.
func (c *Crawler) detectFramework(body string, headers http.Header) FrameworkType {
	// Detect Next.js based on specific HTML elements or X-Powered-By header.
	if strings.Contains(body, "<div id=\"__next\">") || headers.Get("X-Powered-By") == "Next.js" {
		c.logger.Info("Framework Detected: Next.js")
		return FrameworkNextJS
	}
	// Detect Nuxt.js based on specific HTML elements or X-Powered-By header.
	if strings.Contains(body, "<div id=\"__nuxt\">") || headers.Get("X-Powered-By") == "Nuxt.js" {
		c.logger.Info("Framework Detected: Nuxt.js")
		return FrameworkNuxtJS
	}
	return FrameworkUnknown // No known framework detected.
}

// analyzeFrameworkConfig fetches and parses framework-specific configuration files.
func (c *Crawler) analyzeFrameworkConfig(baseURL string) {
	paths, ok := frameworkConfigFilePaths[c.detectedFramework]
	if !ok {
		return // No config paths defined for the detected framework.
	}
	for _, path := range paths {
		configURL := c.resolveURL(baseURL, path)
		if configURL != "" {
			go c.fetchAndParseFrameworkConfig(configURL) // Fetch and parse config in a new goroutine.
		}
	}
}

// fetchAndParseFrameworkConfig fetches and parses a specific framework configuration file.
func (c *Crawler) fetchAndParseFrameworkConfig(configURL string) {
	c.logger.Debug("Framework Analysis: Attempting to fetch %s", configURL)
	resp, err := c.httpClient.Get(configURL)
	if err != nil {
		c.logger.Warn("Framework Analysis: Failed to fetch %s: %v", configURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return // Skip if response is not OK.
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Warn("Framework Analysis: Failed to read body from %s: %v", configURL, err)
		return
	}
	// Parse based on detected framework type.
	switch c.detectedFramework {
	case FrameworkNextJS:
		if strings.HasSuffix(configURL, "build-manifest.json") {
			c.parseNextBuildManifest(body, configURL) // Parse Next.js build manifest.
		}
	}
}

// parseNextBuildManifest parses a Next.js build manifest file to discover additional pages.
func (c *Crawler) parseNextBuildManifest(body []byte, baseURL string) {
	var manifest NextJSBuildManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		c.logger.Warn("Framework Analysis: Failed to parse build-manifest.json: %v", err)
		return
	}
	c.logger.Success("Framework Analysis: Found %d pages from build-manifest.json", len(manifest.Pages))
	for pagePath := range manifest.Pages {
		if strings.HasPrefix(pagePath, "/_") {
			continue // Skip internal Next.js paths.
		}
		// Replace dynamic route segments (e.g., [id]) with a placeholder for consistent crawling.
		reg := regexp.MustCompile(`\[(.*?)\]`)
		pagePath = reg.ReplaceAllString(pagePath, "DURSGO_PARAM")
		resolvedURL := c.resolveURL(baseURL, pagePath)
		if resolvedURL != "" {
			c.logger.Debug("Framework Analysis: Adding discovered page to queue: %s", resolvedURL)
			c.addToQueue(resolvedURL, 0) // Add resolved page URL to the queue.
		}
	}
}

// addCommonParameters adds parameterized requests for common parameters to a given URL.
func (c *Crawler) addCommonParameters(originalURL string) []ParameterizedRequest {
	var requests []ParameterizedRequest
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		c.logger.Debug("Failed to parse URL %s: %v", originalURL, err)
		return requests
	}
	// If the URL already has query parameters, create a ParameterizedRequest for them.
	if queryParams := parsedURL.Query(); len(queryParams) > 0 {
		originalReq := ParameterizedRequest{
			Method:         "GET",
			URL:            originalURL,
			Path:           parsedURL.Path,
			ParamNames:     getKeys(queryParams),
			ParamLocations: make([]string, len(queryParams)),
		}
		for i := range originalReq.ParamLocations {
			originalReq.ParamLocations[i] = "query" // All existing params are in the query.
		}
		requests = append(requests, originalReq)
	}
	return requests
}

// resolveURL resolves a relative URL (href) against a base URL.
func (c *Crawler) resolveURL(baseURL, href string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	resolved.Fragment = "" // Remove URL fragments.
	return resolved.String()
}

// shouldCrawl determines if a URL should be crawled based on various criteria.
func (c *Crawler) shouldCrawl(u string) bool {
	hash := getURLHash(u)
	if hash == "" {
		return false
	}
	c.mu.Lock()
	_, visited := c.visitedURLHashes[hash]
	c.mu.Unlock()
	if visited {
		return false // Skip if already visited.
	}
	if !strings.HasPrefix(u, c.targetDomain) {
		return false // Skip if outside the target domain.
	}

	// Check for excluded file extensions to avoid scanning irrelevant files.
	parsedURL, err := url.Parse(u)
	if err == nil {
		path := parsedURL.Path
		for _, ext := range excludedExtensions {
			if strings.HasSuffix(strings.ToLower(path), ext) {
				c.logger.Debug("Crawler: Skipping URL with excluded extension %s: %s", ext, u)
				return false
			}
		}
	}

	// Skip URLs containing logout keywords.
	lowerU := strings.ToLower(u)
	logoutKeywords := []string{"logout", "logoff", "signout", "exit", "quit"}
	for _, keyword := range logoutKeywords {
		if strings.Contains(lowerU, keyword) {
			c.logger.Debug("Crawler: Skipping potential logout URL: %s", u)
			return false
		}
	}
	return true // URL should be crawled.
}

// markAsVisited marks a URL as visited and records its depth.
func (c *Crawler) markAsVisited(u string, depth int) {
	hash := getURLHash(u)
	if hash == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.visitedURLHashes[hash]; !exists {
		c.visitedURLHashes[hash] = true
		c.urlDepths[u] = depth
	}
}

// GetDiscoveredURLs returns a list of all unique URLs discovered by the crawler.
func (c *Crawler) GetDiscoveredURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	urls := make([]string, 0, len(c.urlDepths))
	for u := range c.urlDepths {
		urls = append(urls, u)
	}
	return urls
}

// addParameterizedRequest adds a new parameterized request to the crawler's collection, handling deduplication.
func (c *Crawler) addParameterizedRequest(newReq ParameterizedRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Strings(newReq.ParamNames) // Sort parameter names for consistent hashing.
	paramHash := sha1.New()
	paramHash.Write([]byte(strings.Join(newReq.ParamNames, ",")))
	// Create a unique key for deduplication based on method, path, and parameter names.
	dedupeKey := fmt.Sprintf("%s %s %s", newReq.Method, newReq.Path, hex.EncodeToString(paramHash.Sum(nil)))
	if _, exists := c.parameterizedRequests[dedupeKey]; exists {
		return // Skip if request already exists.
	} else {
		c.parameterizedRequests[dedupeKey] = newReq
		c.logger.Debug("Crawler: Added new parameterized request target: %s %s with params %v", newReq.Method, newReq.Path, newReq.ParamNames)
	}
}

// GetParameterizedRequestsForScanning returns a deduplicated list of parameterized requests for vulnerability scanning.
func (c *Crawler) GetParameterizedRequestsForScanning() []ParameterizedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []ParameterizedRequest
	keys := make([]string, 0, len(c.parameterizedRequests))
	for k := range c.parameterizedRequests {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort keys for consistent output.
	for _, k := range keys {
		result = append(result, c.parameterizedRequests[k])
	}
	return result
}

// DiscoverParameters proactively discovers additional hidden parameters by injecting common parameter names.
func (c *Crawler) DiscoverParameters(requests []ParameterizedRequest) []ParameterizedRequest {
	c.logger.Info("Starting proactive parameter discovery to find hidden parameters...")
	rand.Seed(time.Now().UnixNano()) // Seed random number generator.
	searchParam := "search"          // Example common parameter.
	c.logger.Debug("Testing for parameter: %s and %d other common parameters", searchParam, len(commonParameters)-1)

	type probeJob struct {
		request ParameterizedRequest
		param   string
	}
	type foundParam struct {
		requestKey string
		paramName  string
	}

	jobsChan := make(chan probeJob)    // Channel for probe jobs.
	foundChan := make(chan foundParam) // Channel for found parameters.
	var wg sync.WaitGroup              // WaitGroup for probe workers.

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
				fmt.Printf("\rParameterDiscovery... %s ", spinner[i])
				i = (i + 1) % len(spinner)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	// --- End Spinner ---

	// Start probe worker goroutines.
	for i := 0; i < c.maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				reflectionString := fmt.Sprintf("dursgoReflect%d", rand.Intn(1e9)) // Unique reflection string.
				base, err := url.Parse(c.targetDomain)
				if err != nil {
					continue
				}
				base.Path = job.request.Path
				query := url.Values{}
				query.Set(job.param, reflectionString)
				base.RawQuery = query.Encode()
				testURLStr := base.String()

				c.logger.Debug("Probing parameter '%s' on %s", job.param, job.request.Path)
				c.logger.Debug("Probing URL: %s", testURLStr)

				// Set standard headers for the probe request.
				headers := map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
					"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
				}
				client := &http.Client{
					Timeout: 10 * time.Second, // Set a timeout for the probe request.
				}
				req, err := http.NewRequest("GET", testURLStr, nil)
				if err != nil {
					c.logger.Debug("Failed to create request: %v", err)
					continue
				}
				for k, v := range headers {
					req.Header.Set(k, v)
				}

				resp, err := client.Do(req)
				if err != nil {
					c.logger.Debug("Probe request for %s failed: %v", testURLStr, err)
					continue
				}
				defer resp.Body.Close()
				bodyBytes, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					c.logger.Debug("Failed to read response body: %v", readErr)
					continue
				}
				bodyStr := string(bodyBytes)
				// Log a preview of the response body.
				previewLen := 300
				if len(bodyStr) < previewLen {
					previewLen = len(bodyStr)
				}
				c.logger.Debug("Response Body Preview (for %s on %s): %s", job.param, job.request.Path, strings.ReplaceAll(bodyStr[:previewLen], "\n", " "))

				// If the reflection string is found in the response, a new parameter is discovered.
				if strings.Contains(bodyStr, reflectionString) {
					foundChan <- foundParam{
						requestKey: job.request.Method + " " + job.request.Path,
						paramName:  job.param,
					}
				}
			}
		}()
	}

	// Distribute probe jobs.
	go func() {
		for _, req := range requests {
			currentReq := req
			if currentReq.Method != "GET" { // Only probe GET requests for reflection.
				continue
			}
			existingParams := make(map[string]bool)
			for _, pName := range currentReq.ParamNames {
				existingParams[pName] = true
			}
			for _, paramToTest := range commonParameters {
				if existingParams[paramToTest] {
					continue // Skip if parameter already exists.
				}
				jobsChan <- probeJob{request: currentReq, param: paramToTest}
			}
		}
		close(jobsChan) // Close the jobs channel when all jobs are distributed.
	}()

	var collectionWg sync.WaitGroup
	collectionWg.Add(1)
	// Goroutine to wait for all probes to finish and close the found channel.
	go func() {
		wg.Wait()        // Wait for all probe workers to finish.
		done <- true     // Stop the spinner
		close(foundChan) // Close the channel of found parameters.
		collectionWg.Done()
	}()

	// Collect found parameters and update requests.
	requestMap := make(map[string]ParameterizedRequest)
	for _, req := range requests {
		requestMap[req.Method+" "+req.Path] = req
	}
	for found := range foundChan {
		c.logger.Success("Found new reflected parameter '%s' on %s", found.paramName, found.requestKey)
		if req, ok := requestMap[found.requestKey]; ok {
			req.ParamNames = append(req.ParamNames, found.paramName)
			requestMap[found.requestKey] = req
		}
	}
	collectionWg.Wait() // Wait for all found parameters to be collected.

	// Convert map back to slice for final requests.
	finalRequests := make([]ParameterizedRequest, 0, len(requestMap))
	for _, req := range requestMap {
		req.ParamNames = mergeUnique(req.ParamNames, []string{}) // Ensure unique and sorted parameter names.
		sort.Strings(req.ParamNames)
		finalRequests = append(finalRequests, req)
	}
	c.logger.Info("Proactive parameter discovery finished.")
	return finalRequests
}

// fetchAndParseAPISpecs fetches and parses common API specification files (OpenAPI/Swagger).
func (c *Crawler) fetchAndParseAPISpecs(baseURL string) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	for _, specPath := range commonAPISpecPaths {
		specURL := fmt.Sprintf("%s://%s/%s", parsedBase.Scheme, parsedBase.Host, strings.TrimLeft(specPath, "/"))
		resp, err := c.httpClient.Get(specURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		defer resp.Body.Close()
		c.logger.Success("API Spec: Found potential spec file at %s", specURL)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		var spec OpenAPIv3
		// Try parsing as YAML, then as JSON.
		if yaml.Unmarshal(body, &spec) != nil {
			if json.Unmarshal(body, &spec) != nil {
				c.logger.Warn("API Spec: Failed to parse %s as JSON or YAML", specURL)
				continue
			}
		}
		// Add discovered API paths to the crawling queue.
		if len(spec.Paths) > 0 {
			c.logger.Success("API Spec: Parsed %d paths from %s", len(spec.Paths), specURL)
			for apiPath := range spec.Paths {
				resolvedPath := c.resolveURL(specURL, apiPath)
				if resolvedPath != "" {
					c.logger.Debug("API Spec: Adding path %s to queue", resolvedPath)
					c.addToQueue(resolvedPath, 0)
				}
			}
		}
	}
}

// fetchAndParseRobotsTxt is a placeholder for fetching and parsing robots.txt.
func (c *Crawler) fetchAndParseRobotsTxt() {}

// isDisallowedByRobots is a placeholder for checking if a URL is disallowed by robots.txt.
func (c *Crawler) isDisallowedByRobots(u string) bool { return false }

// fetchAndParseSitemap is a placeholder for fetching and parsing sitemap files.
func (c *Crawler) fetchAndParseSitemap(b string) {}

// fetchSitemapURL is a placeholder for fetching a URL from a sitemap.
func (c *Crawler) fetchSitemapURL(s string) bool { return false }

// getKeys returns the keys of a url.Values map as a sorted string slice.
func getKeys(m url.Values) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mergeUnique merges two string slices and returns a new slice with unique elements, sorted.
func mergeUnique(s1, s2 []string) []string {
	m := make(map[string]bool)
	for _, item := range s1 {
		m[item] = true
	}
	for _, item := range s2 {
		m[item] = true
	}
	result := make([]string, 0, len(m))
	for item := range m {
		result = append(result, item)
	}
	sort.Strings(result) // Ensure the result is sorted.
	return result
}
