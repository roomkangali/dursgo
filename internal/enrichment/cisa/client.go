package cisa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultKEVURL is the official CISA KEV catalog URL
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	
	// DefaultCacheTTL is the default time-to-live for the cache (24 hours)
	DefaultCacheTTL = 24 * time.Hour
	
	// DefaultTimeout is the default HTTP request timeout
	DefaultTimeout = 30 * time.Second
)

// Client handles interaction with the CISA KEV catalog
type Client struct {
	httpClient *http.Client
	cacheDir   string
	cacheFile  string
	cacheTTL   time.Duration
	kevURL     string
	forceUpdate bool  // Flag to force update the catalog
	
	cache     *Catalog
	cacheTime time.Time
	mu        sync.RWMutex
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client for the CISA client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithForceUpdate forces an update of the KEV catalog
func WithForceUpdate(force bool) ClientOption {
	return func(c *Client) {
		c.forceUpdate = force
	}
}

// WithKEVURL sets a custom KEV URL for the CISA client
func WithKEVURL(url string) ClientOption {
	return func(c *Client) {
		c.kevURL = url
	}
}

// NewClient creates a new CISA KEV client
func NewClient(cacheDir string, opts ...ClientOption) (*Client, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	client := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		cacheDir:  cacheDir,
		cacheFile: filepath.Join(cacheDir, "cisa_kev_catalog.json"),
		cacheTTL:  DefaultCacheTTL,
		kevURL:    DefaultKEVURL,
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// IsInKEV checks if a CVE is in the KEV catalog
func (c *Client) IsInKEV(ctx context.Context, cveID string) (bool, *KEVEntry, error) {
	if cveID == "" {
		return false, nil, nil
	}

	catalog, err := c.getCatalog(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get catalog: %w", err)
	}
	
	for _, entry := range catalog.Vulnerabilities {
		if entry.CVEID == cveID {
			return true, &entry, nil
		}
	}
	
	return false, nil, nil
}

// getCatalog returns the KEV catalog, fetching it if necessary
func (c *Client) getCatalog(ctx context.Context) (*Catalog, error) {
	c.mu.RLock()
	// If we have a recent enough cache and not forcing an update, use it
	if !c.forceUpdate && c.cache != nil && time.Since(c.cacheTime) < c.cacheTTL {
		cache := c.cache
		c.mu.RUnlock()
		return cache, nil
	}
	c.mu.RUnlock()

	// If not forcing an update, try to load from cache first
	if !c.forceUpdate {
		catalog, err := c.loadFromCache()
		if err == nil && catalog != nil && time.Since(c.cacheTime) < c.cacheTTL*24 {
			// Update in-memory cache
			c.mu.Lock()
			c.cache = catalog
			c.cacheTime = time.Now()
			c.mu.Unlock()
			return catalog, nil
		}
	}

	// If we're forcing an update or cache is invalid, fetch from remote
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear the force update flag after first use
	c.forceUpdate = false

	// Fetch fresh catalog
	catalog, err := c.fetchCatalog(ctx)
	if err != nil {
		// If fetch fails but we have a cached version, use it
		if c.cache != nil {
			return c.cache, nil
		}
		return nil, fmt.Errorf("failed to fetch catalog: %w", err)
	}

	// Save to cache in background
	go func() {
		if err := c.saveToCache(catalog); err != nil {
			// Log error but don't fail the operation
			_ = err
		}
	}()

	c.cache = catalog
	c.cacheTime = time.Now()

	return catalog, nil
}

// fetchCatalog fetches the KEV catalog from CISA
func (c *Client) fetchCatalog(ctx context.Context) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.kevURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CISA KEV catalog: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Decode into raw struct first
	var raw rawCatalog
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode CISA KEV catalog: %w", err)
	}
	
	// Convert to the actual Catalog struct with proper time types
	catalog := &Catalog{
		Title:        raw.Title,
		CatalogType:  raw.CatalogType,
		Count:        raw.Count,
	}
	
	// Parse the date released
	dateReleased, err := parseDate(raw.DateReleased)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dateReleased: %w", err)
	}
	catalog.DateReleased = dateReleased
	
	// Convert each vulnerability entry
	catalog.Vulnerabilities = make([]KEVEntry, len(raw.Vulnerabilities))
	for i, rawVuln := range raw.Vulnerabilities {
		dateAdded, err := parseDate(rawVuln.DateAdded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dateAdded for %s: %w", rawVuln.CVEID, err)
		}
		
		var dueDate time.Time
		if rawVuln.DueDate != "" {
			dueDate, err = parseDate(rawVuln.DueDate)
			if err != nil {
				return nil, fmt.Errorf("failed to parse dueDate for %s: %w", rawVuln.CVEID, err)
			}
		}
		
		catalog.Vulnerabilities[i] = KEVEntry{
			CVEID:             rawVuln.CVEID,
			VendorProject:     rawVuln.VendorProject,
			Product:           rawVuln.Product,
			VulnerabilityName: rawVuln.VulnerabilityName,
			DateAdded:         dateAdded,
			ShortDescription:  rawVuln.ShortDescription,
			RequiredAction:    rawVuln.RequiredAction,
			DueDate:           dueDate,
			Notes:             rawVuln.Notes,
		}
	}
	
	return catalog, nil
}

// loadFromCache loads the catalog from the local cache file
func (c *Client) loadFromCache() (*Catalog, error) {
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return nil, err
	}

	// Decode into raw struct first
	var raw rawCatalog
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Convert to the actual Catalog struct with proper time types
	catalog := &Catalog{
		Title:        raw.Title,
		CatalogType:  raw.CatalogType,
		Count:        raw.Count,
	}

	// Parse the date released
	dateReleased, err := parseDate(raw.DateReleased)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dateReleased: %w", err)
	}
	catalog.DateReleased = dateReleased

	// Convert each vulnerability entry
	catalog.Vulnerabilities = make([]KEVEntry, len(raw.Vulnerabilities))
	for i, rawVuln := range raw.Vulnerabilities {
		dateAdded, err := parseDate(rawVuln.DateAdded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dateAdded for %s: %w", rawVuln.CVEID, err)
		}
		
		var dueDate time.Time
		if rawVuln.DueDate != "" {
			dueDate, err = parseDate(rawVuln.DueDate)
			if err != nil {
				return nil, fmt.Errorf("failed to parse dueDate for %s: %w", rawVuln.CVEID, err)
			}
		}
		
		catalog.Vulnerabilities[i] = KEVEntry{
			CVEID:             rawVuln.CVEID,
			VendorProject:     rawVuln.VendorProject,
			Product:           rawVuln.Product,
			VulnerabilityName: rawVuln.VulnerabilityName,
			DateAdded:         dateAdded,
			ShortDescription:  rawVuln.ShortDescription,
			RequiredAction:    rawVuln.RequiredAction,
			DueDate:           dueDate,
			Notes:             rawVuln.Notes,
		}
	}

	return catalog, nil
}

// saveToCache saves the catalog to the local cache file
func (c *Client) saveToCache(catalog *Catalog) error {
	if catalog == nil {
		return fmt.Errorf("catalog is nil")
	}

	// Convert to raw format for consistent serialization
	raw := rawCatalog{
		Title:           catalog.Title,
		CatalogType:     catalog.CatalogType,
		DateReleased:    catalog.DateReleased.Format("2006-01-02"),
		Count:           catalog.Count,
		Vulnerabilities: make([]rawKEVEntry, len(catalog.Vulnerabilities)),
	}

	// Convert each vulnerability entry
	for i, vuln := range catalog.Vulnerabilities {
		raw.Vulnerabilities[i] = rawKEVEntry{
			CVEID:             vuln.CVEID,
			VendorProject:     vuln.VendorProject,
			Product:           vuln.Product,
			VulnerabilityName: vuln.VulnerabilityName,
			DateAdded:         vuln.DateAdded.Format("2006-01-02"),
			ShortDescription:  vuln.ShortDescription,
			RequiredAction:    vuln.RequiredAction,
			DueDate:           vuln.DueDate.Format("2006-01-02"),
			Notes:             vuln.Notes,
		}
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal catalog: %w", err)
	}

	return os.WriteFile(c.cacheFile, data, 0644)
}

// Close releases any resources used by the client
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}

	return nil
}
