package httpclient

import (
	"Dursgo/internal/logger"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Client represents a custom HTTP client for Dursgo, encapsulating http.Client and custom behaviors.
type Client struct {
	httpClient   *http.Client      // The underlying standard HTTP client.
	logger       *logger.Logger    // Logger for client-related messages.
	userAgent    string            // Custom User-Agent header for requests.
	maxRetries   int               // Maximum number of retries for failed requests.
	requestDelay time.Duration     // Delay between retries.
	authHeaders  map[string]string // Authentication headers to be added to requests.
}

// ClientOptions holds configuration parameters for initializing the HTTP Client.
type ClientOptions struct {
	Timeout            time.Duration     // Timeout for HTTP requests.
	FollowRedirects    bool              // Whether to follow HTTP redirects.
	InsecureSkipVerify bool              // Whether to skip TLS certificate verification.
	UserAgent          string            // Custom User-Agent string.
	MaxRetries         int               // Maximum number of retries for requests.
	RequestDelay       time.Duration     // Delay between retries.
	TargetBaseURL      string            // Base URL of the target, used for cookie scope.
	AuthCookie         string            // Static cookie string for authentication.
	AuthHeaders        map[string]string // Static headers for authentication.
}

// NewClient creates and returns a new HTTP client instance with specified options.
func NewClient(log *logger.Logger, opts ClientOptions) *Client {
	// Set default User-Agent if not provided.
	if opts.UserAgent == "" {
		opts.UserAgent = "Dursgo-Scanner/2.0"
	}
	// Set default timeout if not provided.
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	// Ensure max retries is not negative.
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	}

	// Initialize cookie jar for session management.
	jar, _ := cookiejar.New(nil)
	// Configure TLS transport, allowing insecure skip verify if specified.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
	}

	// Create the custom Client instance.
	client := &Client{
		httpClient: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
			Jar:       jar,
		},
		logger:       log,
		userAgent:    opts.UserAgent,
		maxRetries:   opts.MaxRetries,
		requestDelay: opts.RequestDelay,
		authHeaders:  opts.AuthHeaders,
	}

	// Set static authentication cookie if provided.
	if opts.AuthCookie != "" {
		log.Info("Static cookie authentication configured.")
		targetURL, err := url.Parse(opts.TargetBaseURL)
		if err != nil {
			log.Error("Failed to parse target URL for setting cookie: %v", err)
		} else {
			header := http.Header{}
			header.Add("Cookie", opts.AuthCookie)
			request := http.Request{Header: header}
			client.httpClient.Jar.SetCookies(targetURL, request.Cookies())
			log.Debug("Static session cookie set for domain %s", targetURL.Host)
		}
	}

	// Log if static header authentication is configured.
	if len(opts.AuthHeaders) > 0 {
		log.Info("Static header authentication configured.")
	}

	// Configure redirect policy for the HTTP client.
	client.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects {
			return http.ErrUseLastResponse // Do not follow redirects.
		}
		if len(via) >= 10 {
			log.Warn("Exceeded maximum redirects (10).")
			return http.ErrUseLastResponse // Stop following redirects after 10.
		}
		return nil // Continue following redirects.
	}
	return client // Return the initialized client.
}

// Do performs an HTTP request, including setting headers, handling retries, and adaptive rate-limiting.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Set the User-Agent header for the request.
	req.Header.Set("User-Agent", c.userAgent)

	// Add any configured authentication headers.
	if len(c.authHeaders) > 0 {
		for key, value := range c.authHeaders {
			req.Header.Set(key, value)
		}
	}

	c.logger.Trace("Sending request: %s %s", req.Method, req.URL.String())
	// Log cookies being sent from the cookie jar.
	if cookies := c.httpClient.Jar.Cookies(req.URL); len(cookies) > 0 {
		var cookieStrings []string
		for _, cookie := range cookies {
			cookieStrings = append(cookieStrings, cookie.Name+"="+cookie.Value)
		}
		c.logger.Trace("  -> Cookies from Jar to be sent: %s", strings.Join(cookieStrings, "; "))
	}

	var resp *http.Response
	var err error

	// Implement retry logic with exponential backoff for rate limits.
	for i := 0; i <= c.maxRetries; i++ {
		if i > 0 {
			// Apply a base delay for regular retries.
			time.Sleep(c.requestDelay)
		}

		// Clone the request to allow retrying with a fresh body.
		var reqClone *http.Request
		if req.Body != nil {
			// Read and reset the request body for cloning.
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone = req.Clone(req.Context())
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else {
			reqClone = req.Clone(req.Context())
		}

		// Execute the HTTP request.
		resp, err = c.httpClient.Do(reqClone)

		// --- Rate Limit and Server Error Handling Logic ---
		if err == nil {
			// Condition 1: Request successful (not 429 or 5xx).
			if resp.StatusCode != http.StatusTooManyRequests && (resp.StatusCode < 500 || resp.StatusCode > 599) {
				return resp, nil // Return successful response.
			}

			// Condition 2: Rate limit detected (429 Too Many Requests).
			if resp.StatusCode == http.StatusTooManyRequests {
				// Wait longer before retrying for rate limits.
				backoffDuration := 5 * time.Second // Significant wait time.
				c.logger.Warn("Rate limit detected (429 Too Many Requests). Waiting for %v before retrying...", backoffDuration)
				time.Sleep(backoffDuration)
				// Close the current response body before retrying.
				if resp != nil {
					resp.Body.Close()
				}
				continue // Continue to the next retry iteration.
			}
		}
		// --- End of Rate Limit and Server Error Handling ---

		// If there's any other error or a 5xx status, close the body and retry.
		if resp != nil {
			resp.Body.Close()
		}
	}

	return resp, err // Return the last response and error after all retries.
}

// Get performs an HTTP GET request using the custom client.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req) // Delegate to the Do method for request execution.
}

// Post performs an HTTP POST request using the custom client.
func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType) // Set the Content-Type header for POST requests.
	return c.Do(req)                            // Delegate to the Do method for request execution.
}

// GetClient returns the underlying standard http.Client instance.
func (c *Client) GetClient() *http.Client {
	return c.httpClient
}

// GetClientWithoutRedirects returns a new http.Client instance that does not follow redirects.
// This is useful for checking the status code of responses that might redirect (e.g., logins).
func (c *Client) GetClientWithoutRedirects() *http.Client {
	// Create a new client with the same transport and timeout but with redirects disabled.
	return &http.Client{
		Transport: c.httpClient.Transport,
		Jar:       c.httpClient.Jar,
		Timeout:   c.httpClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // This error prevents the client from following redirects.
		},
	}
}

// TemporarilyDisableRedirects temporarily disables redirect following for the underlying http.Client.
// It returns the original CheckRedirect function, which should be used to restore the behavior.
func (c *Client) TemporarilyDisableRedirects() func(req *http.Request, via []*http.Request) error {
	originalFunc := c.httpClient.CheckRedirect // Store the original function.
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Always return this error to prevent redirects.
	}
	return originalFunc // Return the original function for later restoration.
}

// RestoreRedirects restores the original redirect following behavior of the http.Client.
func (c *Client) RestoreRedirects(originalFunc func(req *http.Request, via []*http.Request) error) {
	c.httpClient.CheckRedirect = originalFunc // Set the CheckRedirect back to its original function.
}
