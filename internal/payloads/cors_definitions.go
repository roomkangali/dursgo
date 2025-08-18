package payloads

// CORSTestCase represents a single test case for a CORS misconfiguration.
type CORSTestCase struct {
	// OriginHeader is the value of the Origin header to be sent in the request.
	OriginHeader string
	// Description provides a brief explanation of what is being tested.
	Description string
	// Severity is the severity level if this test successfully identifies a misconfiguration.
	Severity string
}

// CORSTests contains the list of CORS test cases Dursgo will execute.
var CORSTests []CORSTestCase

func init() {
	// Assumes the trusted domain for testing bypasses is "dursgo-scanner.com"
	trustedDomain := "dursgo-scanner.com"

	CORSTests = []CORSTestCase{
		// --- High Severity Tests ---
		{
			OriginHeader: "https://evil-scanner.com",
			Description:  "Tests if the server reflects an arbitrary and unrecognized Origin header.",
			Severity:     "High",
		},
		{
			// This is to test if a wildcard (*) is used.
			// While we don't send "Origin: *", we check if the response is "*".
			// We still need to send a valid-looking origin to trigger the CORS response.
			OriginHeader: "https://" + trustedDomain,
			Description:  "Tests if the server responds with a wildcard (*), allowing any domain.",
			Severity:     "High",
		},
		{
			OriginHeader: "https://" + trustedDomain + ".evil-scanner.com",
			Description:  "Tests for weak regex that only checks if the Origin 'ends with' a trusted domain.",
			Severity:     "High",
		},
		{
			OriginHeader: "https://evil-" + trustedDomain,
			Description:  "Tests for weak regex that only checks if the Origin 'starts with' a trusted domain.",
			Severity:     "High",
		},
		{
			OriginHeader: "https://sub.evil-scanner.com/" + trustedDomain,
			Description:  "Tests for weak regex that just checks if the trusted domain string 'is contained' anywhere.",
			Severity:     "High",
		},
		// --- Medium Severity Tests ---
		{
			OriginHeader: "null",
			Description:  "Tests if the server allows the 'null' origin, which is dangerous for local files and redirects.",
			Severity:     "Medium",
		},
		{
			OriginHeader: "https://" + trustedDomain + ":1234",
			Description:  "Tests if an arbitrary port on a trusted domain is allowed.",
			Severity:     "Medium",
		},
		// --- Low Severity Tests ---
		{
			OriginHeader: "http://" + trustedDomain,
			Description:  "Tests if a non-HTTPS origin is allowed by an HTTPS site.",
			Severity:     "Low",
		},
	}
}
