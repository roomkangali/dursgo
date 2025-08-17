package cisa

import (
	"fmt"
	"time"
)

// KEVEntry represents a single entry in the CISA KEV catalog
type KEVEntry struct {
	CVEID             string    `json:"cveID"`
	VendorProject     string    `json:"vendorProject"`
	Product           string    `json:"product"`
	VulnerabilityName string    `json:"vulnerabilityName"`
	DateAdded         time.Time `json:"dateAdded"`
	ShortDescription  string    `json:"shortDescription"`
	RequiredAction    string    `json:"requiredAction"`
	DueDate           time.Time `json:"dueDate"`
	Notes             string    `json:"notes"`
}

// rawKEVEntry is used for JSON unmarshaling to handle custom date formats
type rawKEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

// rawCatalog is used for JSON unmarshaling
type rawCatalog struct {
	Title           string        `json:"title"`
	CatalogType     string        `json:"catalogType"`
	DateReleased    string        `json:"dateReleased"`
	Count           int           `json:"count"`
	Vulnerabilities []rawKEVEntry `json:"vulnerabilities"`
}

// Catalog represents the CISA KEV catalog
type Catalog struct {
	Title           string     `json:"title"`
	CatalogType     string     `json:"catalogType"`
	DateReleased    time.Time  `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// parseDate attempts to parse a date string in various formats
func parseDate(dateStr string) (time.Time, error) {
	// Try common date formats
	formats := []string{
		"2006-01-02T15:04:05Z07:00", // ISO 8601 with timezone
		"2006-01-02T15:04:05",        // ISO 8601 without timezone
		"2006-01-02",                 // Just date
	}

	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}
