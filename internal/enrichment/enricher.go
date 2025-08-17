package enrichment

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"Dursgo/internal/enrichment/cisa"
)

// Enricher provides vulnerability enrichment capabilities
type Enricher interface {
	// Enrich enriches a vulnerability with additional data
	Enrich(ctx context.Context, vuln *Vulnerability) error
	// Close releases any resources used by the enricher
	Close() error
}

// Vulnerability represents a vulnerability that can be enriched
type Vulnerability struct {
	// Original fields
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Parameter   string                 `json:"parameter,omitempty"`
	Payload     string                 `json:"payload,omitempty"`
	Details     string                 `json:"details"`
	Severity    string                 `json:"severity"`
	Remediation string                 `json:"remediation,omitempty"`
	CVE         string                 `json:"cve,omitempty"`
	
	// Enrichment fields
	Enrichment  *EnrichmentData        `json:"enrichment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// EnrichmentData contains enriched vulnerability data
type EnrichmentData struct {
	CISAKEV     *CISAKEVData `json:"cisa_kev,omitempty"`
	// Future enrichment sources will be added here
}

// CISAKEVData contains CISA KEV enrichment data
type CISAKEVData struct {
	InCatalog      bool      `json:"in_catalog"`
	DateAdded      time.Time `json:"date_added,omitempty"`
	DueDate        time.Time `json:"due_date,omitempty"`
	RequiredAction string    `json:"required_action,omitempty"`
	Notes          string    `json:"notes,omitempty"`
}

// EnricherOption represents an option for the enricher
type EnricherOption func(*enricherOptions)

type enricherOptions struct {
	forceUpdate bool
}

// WithForceUpdate forces an update of the CISA KEV catalog
func WithForceUpdate(force bool) EnricherOption {
	return func(opts *enricherOptions) {
		opts.forceUpdate = force
	}
}

// NewEnricher creates a new enricher with the specified options
func NewEnricher(cacheDir string, opts ...EnricherOption) (Enricher, error) {
	// Set default options
	options := &enricherOptions{
		forceUpdate: false,
	}

	// Apply provided options
	for _, opt := range opts {
		opt(options)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create enrichment cache directory: %w", err)
	}
	
	// Create CISA client with options
	cisaOpts := []cisa.ClientOption{}
	if options.forceUpdate {
		cisaOpts = append(cisaOpts, cisa.WithForceUpdate(true))
	}

	cisaClient, err := cisa.NewClient(filepath.Join(cacheDir, "cisa"), cisaOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CISA client: %w", err)
	}

	return &enricher{
		cisaClient: cisaClient,
	}, nil
}

type enricher struct {
	cisaClient *cisa.Client
}

// Enrich enriches a vulnerability with additional data from various sources
func (e *enricher) Enrich(ctx context.Context, vuln *Vulnerability) error {
	if vuln == nil {
		return nil
	}

	// Initialize enrichment data if needed
	if vuln.Enrichment == nil {
		vuln.Enrichment = &EnrichmentData{}
	}

	// Only enrich if we have a CVE
	if vuln.CVE == "" {
		return nil
	}

	// Enrich with CISA KEV data
	inKEV, entry, err := e.cisaClient.IsInKEV(ctx, vuln.CVE)
	if err != nil {
		// Log the error but don't fail the entire enrichment
		log.Printf("Warning: Failed to check CISA KEV for %s: %v", vuln.CVE, err)
		return nil
	}

	if inKEV && entry != nil {
		vuln.Enrichment.CISAKEV = &CISAKEVData{
			InCatalog:      true,
			DateAdded:      entry.DateAdded,
			DueDate:        entry.DueDate,
			RequiredAction: entry.RequiredAction,
			Notes:          entry.Notes,
		}
	}

	return nil
}

// Close releases any resources used by the enricher
func (e *enricher) Close() error {
	if e == nil || e.cisaClient == nil {
		return nil
	}

	if err := e.cisaClient.Close(); err != nil {
		return fmt.Errorf("error closing CISA client: %w", err)
	}

	return nil
}
