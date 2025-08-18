package payloads

// CommonIDParameterNames contains a list of common parameter names that may be vulnerable to IDOR.
var CommonIDParameterNames = []string{
	// Generic IDs
	"identifier", "uid", "record_id", "entity_id",

	// User-related IDs
	"user_id", "userid", "user", "account_id", "accountid", "customer_id", "customerid",
	"member_id", "memberid", "profile_id", "profileid",

	// Object/Item-related IDs
	"item_id", "itemid", "article_id", "articleid",
	"doc_id", "document_id", "file_id", "photo_id",

	// Action-related IDs
	"order_id", "orderid", "invoice_id", "invoiceid", "cart_id", "cartid", "booking_id",
	"message_id", "comment_id", "thread_id", "group_id", "event_id", "report_id",
	"view", "addressID", "recipient_id", "sender_id", "transfer_amount", "amount", "resetBalance",

	// UUIDs and reference numbers
	"uuid", "guid",
}

// IDORNegativeKeywords are substrings found in a response that suggest an IDOR attempt failed.
// A successful IDOR is indicated by the *absence* of these keywords.
var IDORNegativeKeywords = []string{
	// Not Found
	"not found", "does not exist", "doesn't exist", "could not be found",
	"the requested resource was not found", "record not found", "item not found",
	"user not found", "unable to find", "cannot find", "no such", "unable to locate",

	// Access Denied / Unauthorized
	"access denied", "unauthorized", "forbidden", "permission denied",
	"no permission", "not permitted", "you do not have permission", "access is denied",
	"not authorized", "authorization failed",

	// Login / Authentication Required
	"login required", "please login", "authenticate", "authentication required",
	"session has expired", "sign in to continue",

	// Invalid Input / Errors
	"invalid id", "invalid parameter", "an invalid value was specified",

	// HTTP Status Code text
	"404 not found", "403 forbidden", "401 unauthorized",
}
