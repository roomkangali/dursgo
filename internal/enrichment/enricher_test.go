package enrichment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"Dursgo/internal/enrichment/cisa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServerResponse is a helper struct to define test server responses
type testServerResponse struct {
	catalog *cisa.Catalog
}

func TestNewEnricher(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		mockErr error
		wantErr bool
	}{
		{
			name:    "Success",
			dir:     t.TempDir(),
			mockErr: nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enricher, err := NewEnricher(tt.dir)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, enricher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, enricher)
				if enricher != nil {
					err := enricher.Close()
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestEnricher_Enrich(t *testing.T) {
	// Setup test server with a handler that returns a test catalog
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feeds/known_exploited_vulnerabilities.json" {
			now := time.Now()
			catalog := &cisa.Catalog{
				Title:        "CISA Known Exploited Vulnerabilities Catalog",
				CatalogType:  "CISA KEV",
				DateReleased: now,
				Count:        1,
				Vulnerabilities: []cisa.KEVEntry{
					{
						CVEID:             "CVE-2021-44228",
						VendorProject:     "Apache",
						Product:           "Log4j",
						VulnerabilityName: "Apache Log4j Remote Code Execution Vulnerability",
						DateAdded:         now,
						DueDate:           now.AddDate(0, 1, 0),
						RequiredAction:    "Apply updates",
						ShortDescription:  "A critical vulnerability in Apache Log4j",
						Notes:             "This is a test entry",
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(catalog)
		} else {
			http.NotFound(w, r)
		}
	})

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	// Create a custom HTTP client that redirects all requests to our test server
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				// Rewrite the URL to point to our test server
				newURL, _ := url.Parse(testServer.URL)
				newURL.Path = req.URL.Path
				newURL.RawQuery = req.URL.RawQuery
				return newURL, nil
			},
		},
		Timeout: 30 * time.Second,
	}

	// Setup test cases
	tests := []struct {
		name           string
		cveID         string
		setupClient   func(*cisa.Client)
		expectedError  bool
		expectedEnrich bool
	}{
		{
			name:   "Vulnerability with CVE in KEV",
			cveID:  "CVE-2021-44228",
			setupClient: func(c *cisa.Client) {
				// No need to modify client for this test case
			},
			expectedError:  false,
			expectedEnrich: true,
		},
		{
			name:   "Vulnerability with CVE not in KEV",
			cveID:  "CVE-2021-12345",
			setupClient: func(c *cisa.Client) {
				// No need to modify client for this test case
			},
			expectedError:  false,
			expectedEnrich: false,
		},
		{
			name:   "Vulnerability without CVE",
			cveID:  "",
			setupClient: func(c *cisa.Client) {
				// No need to modify client for this test case
			},
			expectedError:  false,
			expectedEnrich: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for cache
			tempDir, err := os.MkdirTemp("", "dursgo-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			// Create CISA client with custom HTTP client and KEV URL
			client, err := cisa.NewClient(
				tempDir,
				cisa.WithHTTPClient(httpClient),
				cisa.WithKEVURL(testServer.URL + "/feeds/known_exploited_vulnerabilities.json"),
			)
			require.NoError(t, err)
			defer client.Close()

			// Setup client if needed
			if tt.setupClient != nil {
				tt.setupClient(client)
			}

			// Create enricher with the client
			enricher := &enricher{
				cisaClient: client,
			}

			// Create test vulnerability
			vuln := &Vulnerability{
				CVE: tt.cveID,
			}

			// Test Enrich
			err = enricher.Enrich(context.Background(), vuln)


			// Assertions
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedEnrich {
					assert.NotNil(t, vuln.Enrichment)
					assert.NotNil(t, vuln.Enrichment.CISAKEV)
					assert.True(t, vuln.Enrichment.CISAKEV.InCatalog)
				} else {
					if vuln.Enrichment == nil || vuln.Enrichment.CISAKEV == nil {
						// No enrichment data is expected
						return
					}
					assert.False(t, vuln.Enrichment.CISAKEV.InCatalog)
				}
			}
		})
	}
}
