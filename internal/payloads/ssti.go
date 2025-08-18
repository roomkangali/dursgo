package payloads

import (
	"fmt"
	"math/rand" // rand is now used in GenerateSSTIPayload
	"strings"
)

// SSTIPayloadTest represents a single SSTI test case.
type SSTIPayloadTest struct {
	PayloadTemplate string // The template string to be injected into a parameter, e.g., "{{{CALC_RESULT}}}".
	ExpectedPattern string // The regex pattern to search for in the response, e.g., "CALC_RESULT".
	EngineName      string // The name of the template engine(s) targeted by this payload.
}

// SSTIPayloads contains a list of SSTI test cases for various template engines.
var SSTIPayloads []SSTIPayloadTest

// init initializes the SSTIPayloads slice with various test cases.
func init() {
	// Using unique arithmetic operations (e.g., 23*23=529) is a reliable detection method
	// because the result is highly unlikely to appear coincidentally on a page,
	// even if the page state is preserved across requests.
	// Payloads are ordered to prioritize common, high-success-rate engines first.
	SSTIPayloads = []SSTIPayloadTest{
		// --- High-Frequency / Common Engines ---
		{
			PayloadTemplate: "{{%d*%d}}",
			ExpectedPattern: "%d",
			EngineName:      "Jinja2 / Twig / Nunjucks / Pebble",
		},
		{
			PayloadTemplate: "${%d*%d}",
			ExpectedPattern: "%d",
			EngineName:      "FreeMarker / Velocity / Mako",
		},
		{
			PayloadTemplate: "<%%= %d*%d %%>",
			ExpectedPattern: "%d",
			EngineName:      "ERB (Ruby) / EJS (JavaScript)",
		},
		{
			PayloadTemplate: "#{%d*%d}",
			ExpectedPattern: "%d",
			EngineName:      "JavaServer Faces (JSF) / Pug (Jade)",
		},
		{
			PayloadTemplate: "*{%d*%d}",
			ExpectedPattern: "%d",
			EngineName:      "Thymeleaf",
		},
		{
			PayloadTemplate: "[[%d*%d]]",
			ExpectedPattern: "%d",
			EngineName:      "Thymeleaf (inline)",
		},
		{
			PayloadTemplate: "${(function(){return %d*%d})()}",
			ExpectedPattern: "%d",
			EngineName:      "JavaScript Template Literal",
		},

		// --- Less Common / More Specific Engines ---
		{
			PayloadTemplate: "@(%d*%d)",
			ExpectedPattern: "%d",
			EngineName:      "ASP.NET Razor",
		},
		{
			PayloadTemplate: "{math equation=\"%d*%d\"}",
			ExpectedPattern: "%d",
			EngineName:      "Smarty (PHP)",
		},
		{
			PayloadTemplate: "<%%= %d*%d %%>", // Generic PHP, using different marker to avoid collision
			ExpectedPattern: "%d",
			EngineName:      "Generic PHP",
		},
		{
			PayloadTemplate: "DURSGO${{%d*%d}}<%%={%d*%d}%%>[[(%d*%d)]]",
			ExpectedPattern: "DURSGO%d%d%d",
			EngineName:      "Polyglot (Jinja2, ERB, etc.)",
		},

		// --- Error-Prone / Niche Engines (placed last) ---
		{
			PayloadTemplate: "{{ mul %d %d }}",
			ExpectedPattern: "%d", // This will be the expected output if it doesn't error
			EngineName:      "Go Template",
		},
	}
}

// GenerateSSTIPayload generates a unique SSTI payload and its expected output for a given test case.
func GenerateSSTIPayload(testCase SSTIPayloadTest) (string, string) {
	// Use two random numbers for the arithmetic operation to ensure uniqueness.
	num1 := 10 + rand.Intn(90) // Number between 10 and 99
	num2 := 10 + rand.Intn(90) // Number between 10 and 99
	
	// Calculate the expected result.
	expectedResult := num1 * num2

	// Format the payload and expected output based on the template.
	payload := fmt.Sprintf(testCase.PayloadTemplate, num1, num2)
	expectedOutput := fmt.Sprintf(testCase.ExpectedPattern, expectedResult)

	// Handle polyglot case where multiple results are expected.
	if strings.Contains(testCase.ExpectedPattern, "DURSGO%d%d%d") {
		payload = fmt.Sprintf(testCase.PayloadTemplate, num1, num2, num1, num2, num1, num2)
		expectedOutput = fmt.Sprintf(testCase.ExpectedPattern, expectedResult, expectedResult, expectedResult)
	}

	return payload, expectedOutput
}
