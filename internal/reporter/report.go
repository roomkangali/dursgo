package reporter

import (
	"github.com/roomkangali/dursgo/internal/crawler" // Required to access the ParameterizedRequest struct
	"github.com/roomkangali/dursgo/internal/scanner"
	"time"
)

// DiscoveredEndpoint is a new struct to store details of discovered endpoints.
// It holds information about the URL, HTTP method, and any parameters found for an endpoint.
type DiscoveredEndpoint struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Params []string `json:"params,omitempty"`
}

// Report is the main, enhanced data structure for scan results.
// It aggregates various aspects of a security scan, including summary,
// discovered endpoints, and identified vulnerabilities.
type Report struct {
	ScanSummary         ScanSummary                   `json:"scan_summary"`
	DiscoveredEndpoints []DiscoveredEndpoint          `json:"discovered_endpoints,omitempty"` // New field added for discovered endpoints
	Vulnerabilities     []scanner.VulnerabilityResult `json:"vulnerabilities"`
}

// ScanSummary contains metadata and a summary of the scan.
// It provides an overview of the scan's execution, including timing,
// scope, and high-level results.
type ScanSummary struct {
	TargetURL                  string            `json:"target_url"`
	ScanStartTime              string            `json:"scan_start_time"`
	ScanEndTime                string            `json:"scan_end_time"`
	TotalDuration              string            `json:"total_duration"`
	ScannersRun                []string          `json:"scanners_run"`
	TechnologiesDetected       map[string]string `json:"technologies_detected"`
	TotalURLsDiscovered        int               `json:"total_urls_discovered"`
	TotalParameterizedRequests int               `json:"total_parameterized_requests"` // New field for summary
	TotalVulnsFound            int               `json:"total_vulnerabilities_found"`
}

// NewReport creates a new report instance.
// This function initializes a new Report struct with the target URL and scan start time.
// It also ensures that the DiscoveredEndpoints and Vulnerabilities slices are
// initialized to empty slices to prevent them from being null in JSON output if empty.
func NewReport(target string, startTime time.Time) *Report {
	return &Report{
		ScanSummary: ScanSummary{
			TargetURL:     target,
			ScanStartTime: startTime.Format(time.RFC3339),
		},
		// Initialize slices to prevent them from being null in JSON if empty
		DiscoveredEndpoints: make([]DiscoveredEndpoint, 0),
		Vulnerabilities:     make([]scanner.VulnerabilityResult, 0),
	}
}

// Finalize completes the report with all final data before saving.
// Its signature now accepts results from the crawler.
// This function populates the scan summary with end times, durations,
// and counts of vulnerabilities and discovered URLs. It also transforms
// the raw crawler data into a clean report format for discovered endpoints.
func (r *Report) Finalize(
	endTime time.Time,
	startTime time.Time,
	vulns []scanner.VulnerabilityResult,
	scanners []string,
	tech map[string]string,
	urlsDiscovered int,
	paramRequests []crawler.ParameterizedRequest, // New data from crawler
) {
	r.ScanSummary.ScanEndTime = endTime.Format(time.RFC3339)
	r.ScanSummary.TotalDuration = endTime.Sub(startTime).Round(time.Second).String()
	r.Vulnerabilities = vulns
	r.ScanSummary.TotalVulnsFound = len(vulns)
	r.ScanSummary.ScannersRun = scanners
	r.ScanSummary.TechnologiesDetected = tech
	r.ScanSummary.TotalURLsDiscovered = urlsDiscovered
	r.ScanSummary.TotalParameterizedRequests = len(paramRequests)

	// Transform data from crawler into a clean report format
	for _, req := range paramRequests {
		r.DiscoveredEndpoints = append(r.DiscoveredEndpoints, DiscoveredEndpoint{
			URL:    req.URL,
			Method: req.Method,
			Params: req.ParamNames,
		})
	}
}
