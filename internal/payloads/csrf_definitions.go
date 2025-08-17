package payloads

// CommonCSRFTokenNames contains a list of common names for CSRF tokens in forms and headers.
var CommonCSRFTokenNames = []string{
	// Standard & Framework-specific
	"csrf_token",
	"csrftoken",
	"csrfmiddlewaretoken",        // Django
	"authenticity_token",         // Ruby on Rails
	"_token",                     // Laravel
	"YII_CSRF_TOKEN",             // Yii
	"__requestverificationtoken", // ASP.NET
	"anticsrf",

	// Common prefixes/suffixes
	"_csrf",
	"_csrf_token",
	"csrf",

	// Generic token names
	"token",
	"security_token",
	"form_token",
	"nonce",
	"state_token", // Common in OAuth flows

	// XSRF variations
	"xsrf_token",
	"xsrf",
	"_xsrf",

	// Header-style names (often used in AJAX requests)
	"X-CSRF-Token",
	"X-CSRFToken",
	"X-XSRF-TOKEN",
	"X-CSRF-Header",
}

// CSRFTokenValidationFailedKeywords contains common substrings found in responses
// when a CSRF token validation fails.
var CSRFTokenValidationFailedKeywords = []string{
	// Generic CSRF/XSRF messages
	"csrf token mismatch", "invalid csrf token", "missing csrf token", "csrf validation failed",
	"csrf check failed", "the csrf token is invalid", "incorrect csrf token", "csrf violation",
	"csrftoken mismatch", "invalid csrftoken", "missing csrftoken",
	"xsrf token validation failed", "invalid xsrf token", "missing xsrf token", "bad xsrf token",
	"a required security token was not provided",
	"an error occurred because a security token was missing or mismatched",
	"validation of the security token failed",
	"the security token did not match",
	"unable to verify your request",
	"your request could not be verified",

	// Framework-specific messages
	"authenticity token error", "invalid authenticity token", "could not verify the authenticity token", "wrong authenticity token", // Rails
	"the page has expired due to inactivity",                                 // Laravel
	"expected csrf token not found",                                          // Spring
	"request verification token error", "invalid request verification token", // ASP.NET

	// Nonce messages
	"nonce is invalid", "nonce check failed", "bad nonce", "missing nonce", "invalid nonce",

	// General denial/rejection messages
	"action denied",
	"request rejected",
	"illegal request",
	"forbidden",
	"403 forbidden",
	"permission denied",
	"this action could not be completed",
	"a potential security vulnerability was detected",
	"the submitted data was not valid for the server",

	// Form-related messages
	"form tampering detected", "tampered request",
	"the form is invalid, please try again",
	"invalid form submission",
}
