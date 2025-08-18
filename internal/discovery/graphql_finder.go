package discovery

import (
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/payloads"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// GraphQLFinder is responsible for discovering and confirming GraphQL endpoints.
type GraphQLFinder struct {
	client *httpclient.Client // HTTP client for making requests.
	log    *logger.Logger     // Logger for outputting messages.
}

// NewGraphQLFinder creates a new instance of GraphQLFinder.
func NewGraphQLFinder(client *httpclient.Client, log *logger.Logger) *GraphQLFinder {
	return &GraphQLFinder{
		client: client,
		log:    log,
	}
}

// FindEndpoint attempts to discover a valid GraphQL endpoint for a given domain.
// It returns the URL of the discovered endpoint, or an empty string if none is found.
func (f *GraphQLFinder) FindEndpoint(targetDomain string) string {
	f.log.Info("Starting GraphQL endpoint discovery for %s...", targetDomain)

	// Iterate through common GraphQL paths to probe for endpoints.
	for _, path := range payloads.CommonGraphQLPaths {
		testURL := targetDomain + path
		f.log.Debug("GraphQL Finder: Probing path: %s", testURL)

		// Send an Introspection Query using a POST request.
		req, err := http.NewRequest("POST", testURL, bytes.NewBufferString(payloads.GraphQLQueries.IntrospectionSimple))
		if err != nil {
			continue // Skip if request creation fails.
		}
		req.Header.Set("Content-Type", "application/json") // Set Content-Type for GraphQL.

		resp, err := f.client.Do(req)
		if err != nil {
			// Close response body if it exists, even on error.
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue // Skip if HTTP request fails.
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close() // Close response body after reading.
		bodyString := string(bodyBytes)

		// Check if the response body contains known GraphQL keywords.
		for _, keyword := range payloads.GraphQLResponseKeywords {
			if strings.Contains(bodyString, keyword) {
				f.log.Success("GraphQL endpoint confirmed at: %s", testURL)
				return testURL // Success! Return the discovered URL.
			}
		}
	}

	f.log.Info("No GraphQL endpoint found for %s.", targetDomain)
	return "" // No GraphQL endpoint found.
}
