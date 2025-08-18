package payloads

// HeaderCheck defines the structure for each security header to be checked.
type HeaderCheck struct {
	// Name is the header name (case-insensitive during checks).
	Name string
	// Description is a brief explanation of the header's function.
	Description string
	// RecommendedValue is the recommended value. If empty, only the presence is checked.
	// Can also contain a simple pattern (e.g., "max-age=" for HSTS).
	RecommendedValue string
	// Severity is the level of severity if the header is missing or misconfigured.
	Severity string // Example: "High", "Medium", "Low", "Informational"
	// CheckOnHTTPSOnly indicates whether the header is only relevant for HTTPS connections.
	CheckOnHTTPSOnly bool
	// Remediation is the suggested fix.
	Remediation string
}

// SecurityHeaderChecks contains the list of all security headers that will be checked by Dursgo.
var SecurityHeaderChecks []HeaderCheck

func init() {
	SecurityHeaderChecks = []HeaderCheck{
		// --- Critical Security Headers for Preventing Common Attacks ---
		{
			Name:             "Content-Security-Policy",
			Description:      "Helps prevent XSS and other injection attacks by restricting the content sources allowed to load in the browser.",
			RecommendedValue: "", // Only check presence, as the policy can be highly complex.
			Severity:         "High",
			CheckOnHTTPSOnly: false,
			Remediation:      "Implement a strict Content Security Policy (CSP) to restrict sources for scripts, styles, images, and other content.",
		},
		{
			Name:             "Strict-Transport-Security",
			Description:      "Forces the browser to always communicate with the server using HTTPS.",
			RecommendedValue: "max-age=", // We only check if the max-age directive exists.
			Severity:         "Medium",
			CheckOnHTTPSOnly: true,
			Remediation:      "Apply HSTS by setting the header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.",
		},
		{
			Name:             "X-Frame-Options",
			Description:      "Protects against clickjacking attacks by controlling whether a page can be displayed within an iframe. Note: The 'frame-ancestors' directive in a CSP is the modern replacement for this header.",
			RecommendedValue: "DENY", // Or SAMEORIGIN
			Severity:         "Medium",
			CheckOnHTTPSOnly: false,
			Remediation:      "Set the header 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking. For more granular control, use CSP's 'frame-ancestors' directive.",
		},
		{
			Name:             "X-Content-Type-Options",
			Description:      "Prevents the browser from MIME-sniffing a response away from the declared content-type, which can lead to execution of malicious content.",
			RecommendedValue: "nosniff",
			Severity:         "Low",
			CheckOnHTTPSOnly: false,
			Remediation:      "Set the header 'X-Content-Type-Options: nosniff' for all responses.",
		},
		// --- Headers for Enabling Cross-Origin Isolation ---
		{
			Name:             "Cross-Origin-Opener-Policy",
			Description:      "Protects against cross-origin attacks by isolating the top-level Browse context from other documents.",
			RecommendedValue: "same-origin", // or same-origin-allow-popups
			Severity:         "Low",
			CheckOnHTTPSOnly: true,
			Remediation:      "Set 'Cross-Origin-Opener-Policy: same-origin' to enable process isolation and mitigate attacks like XS-Leaks.",
		},
		{
			Name:             "Cross-Origin-Embedder-Policy",
			Description:      "Prevents a document from loading any cross-origin resources that don't explicitly grant the document permission.",
			RecommendedValue: "require-corp",
			Severity:         "Informational",
			CheckOnHTTPSOnly: true,
			Remediation:      "To enable a cross-origin isolated state, set 'Cross-Origin-Embedder-Policy: require-corp'. This can be complex and may break third-party integrations.",
		},
		// --- Headers for Controlling Features and Referrer Information ---
		{
			Name:             "Permissions-Policy",
			Description:      "Controls which browser features and APIs can be used by the page (e.g., geolocation, microphone, camera). Successor to Feature-Policy.",
			RecommendedValue: "", // Only check presence, as the policy can be highly complex.
			Severity:         "Low",
			CheckOnHTTPSOnly: false,
			Remediation:      "Apply a strict Permissions-Policy to disable unnecessary browser features. Example: 'Permissions-Policy: geolocation=(), microphone=()'.",
		},
		{
			Name:             "Referrer-Policy",
			Description:      "Controls how much referrer (source URL) information is sent when users navigate away from your page.",
			RecommendedValue: "strict-origin-when-cross-origin", // A good secure default
			Severity:         "Low",
			CheckOnHTTPSOnly: false,
			Remediation:      "Set the 'Referrer-Policy' header to a safe value such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
		},
		// --- Caching and Data Management Headers ---
		{
			Name:             "Cache-Control",
			Description:      "Controls caching policies. For sensitive data, it should prevent storing.",
			RecommendedValue: "no-store", // Or must contain "no-cache"
			Severity:         "Medium",
			CheckOnHTTPSOnly: false,
			Remediation:      "For pages with sensitive information, set the header 'Cache-Control: no-store, no-cache, must-revalidate' to prevent caching.",
		},
		{
			Name:             "Clear-Site-Data",
			Description:      "Clears Browse data (cookies, storage, cache) for the site. Especially useful on logout pages.",
			RecommendedValue: `"cache", "cookies", "storage"`,
			Severity:         "Informational",
			CheckOnHTTPSOnly: true,
			Remediation:      "On logout pages, consider setting 'Clear-Site-Data: \"cache\", \"cookies\", \"storage\"' to ensure all user session data is removed from the browser.",
		},
		// --- Legacy / Defense-in-Depth Headers ---
		{
			Name:             "X-XSS-Protection",
			Description:      "Legacy header to enable the browser's built-in XSS filter. Deprecated in modern browsers but provides defense-in-depth for older browser users.",
			RecommendedValue: "1; mode=block",
			Severity:         "Low",
			CheckOnHTTPSOnly: false,
			Remediation:      "Set 'X-XSS-Protection: 1; mode=block' for older browsers, but rely on a strong CSP as the primary defense against XSS.",
		},
	}
}
