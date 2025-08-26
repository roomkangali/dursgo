package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"Dursgo/internal/ai" // Import the new AI package
	"Dursgo/internal/config"
	"Dursgo/internal/crawler"
	"Dursgo/internal/discovery"
	"Dursgo/internal/enrichment"
	"Dursgo/internal/fingerprint"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
	"Dursgo/internal/renderer"
	"Dursgo/internal/reporter"
	"Dursgo/internal/scanner"
	"Dursgo/internal/scanner/blindssrf"
	"Dursgo/internal/scanner/bola"
	"Dursgo/internal/scanner/cmdinjection"
	"Dursgo/internal/scanner/cors"
	"Dursgo/internal/scanner/csrf"
	"Dursgo/internal/scanner/domxss"
	"Dursgo/internal/scanner/exposed"
	"Dursgo/internal/scanner/fileupload"
	"Dursgo/internal/scanner/graphql"
	"Dursgo/internal/scanner/idor"
	"Dursgo/internal/scanner/lfi"
	"Dursgo/internal/scanner/massassignment"
	"Dursgo/internal/scanner/openredirect"
	"Dursgo/internal/scanner/securityheaders"
	"Dursgo/internal/scanner/sqli"
	"Dursgo/internal/scanner/ssrf"
	"Dursgo/internal/scanner/ssti"
	"Dursgo/internal/scanner/xss"
	"regexp"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

// main is the entry point of the Dursgo application.
func main() {
	// Initialize logger with INFO level.
	log := logger.NewLogger(logger.INFO)
	startTime := time.Now()

	// Load configuration from config.yaml.
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Error("Failed to load config: %v", err)
	} else {
		// Enable debug logging if verbose mode is set in config.
		log.Debug("Config loaded - Verbose mode: %v", cfg.Output.Verbose)
		if cfg.Output.Verbose {
			log = logger.NewLogger(logger.DEBUG)
			log.Info("Debug logging enabled")
		}
	}
	if err != nil {
		log.Error("Failed to load config.yaml: %v", err)
		os.Exit(1)
	}

	// Handle old authentication config format for backward compatibility.
	if cfg.Authentication.Type == "header" && cfg.Authentication.HeaderName != "" && cfg.Authentication.Value != "" {
		log.Info("Old authentication config format detected. Converting to new 'headers' format.")
		if cfg.Authentication.Headers == nil {
			cfg.Authentication.Headers = make(map[string]string)
		}
		cfg.Authentication.Headers[cfg.Authentication.HeaderName] = cfg.Authentication.Value
		log.Debug("Converted old auth config to: Headers[%s] = %s", cfg.Authentication.HeaderName, "token_value")
	}

	// Parse command-line arguments.
	args := os.Args[1:]
	for i, arg := range args {
		// Handle force update of CISA KEV catalog.
		if arg == "--update-kev" || arg == "-update-kev" {
			log.Info("Forcing update of CISA KEV catalog...")
			cacheDir := filepath.Join(os.TempDir(), "dursgo-cache")
			enricher, err := enrichment.NewEnricher(cacheDir, enrichment.WithForceUpdate(true))
			if err != nil {
				log.Error("Failed to initialize enricher: %v", err)
				os.Exit(1)
			}
			enricher.Close()
			log.Info("CISA KEV catalog has been updated")
			os.Exit(0)
		}
		if strings.HasPrefix(arg, "--update-kev") || strings.HasPrefix(arg, "-update-kev") {
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	// Re-set os.Args after processing --update-kev flag.
	os.Args = append([]string{os.Args[0]}, args...)

	// --- Custom Flag Definitions & Help Screen ---

	// Define command-line flags.
	var targetURLStr, scannersToRunStr, jsonOutputFile string
	var concurrency, maxRetries, delay, maxDepth int
	var verbose, trace, oast, enableEnrichment, updateKEV, renderJS, enableAI bool

	flag.StringVar(&targetURLStr, "u", cfg.Target, "Target URL for scanning")
	flag.StringVar(&scannersToRunStr, "s", cfg.Scanners, "Comma-separated list of scanners to run (e.g., xss,sqli)")
	flag.IntVar(&concurrency, "c", cfg.Concurrency, "Number of concurrent workers/threads")
	flag.IntVar(&maxDepth, "d", cfg.MaxDepth, "Maximum crawling depth")
	flag.IntVar(&delay, "delay", cfg.Delay, "Delay between requests in milliseconds (ms)")
	flag.IntVar(&maxRetries, "r", cfg.MaxRetries, "Maximum number of retries for failed requests")
	flag.BoolVar(&oast, "oast", cfg.OAST, "Enable OAST (Out-of-Band) for blind vulnerabilities")
	flag.StringVar(&jsonOutputFile, "output-json", "", "Path to save the report file in JSON format")
	flag.BoolVar(&renderJS, "render-js", cfg.RenderJS, "Enable JavaScript rendering for crawling SPAs")
	flag.BoolVar(&enableEnrichment, "enrich", false, "Enable vulnerability enrichment with CISA KEV data")
	flag.BoolVar(&enableAI, "enable-ai", cfg.AI.Enabled, "Enable AI-powered vulnerability analysis")
	flag.BoolVar(&updateKEV, "update-kev", false, "Force update CISA KEV catalog and exit")
	flag.BoolVar(&verbose, "v", cfg.Output.Verbose, "Enable verbose output (DEBUG level)")
	flag.BoolVar(&trace, "vv", false, "Enable trace-level output (highly verbose)")

	// Custom Usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DursGo is a web application security scanner designed for penetration testing and automated security audits.\nBuilt with Go, DursGo offers high-performance and flexible security scanning capabilities.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "TARGET:\n")
		fmt.Fprintf(os.Stderr, "  -u string\n    \tTarget URL for scanning (e.g., \"http://example.com\")\n")

		fmt.Fprintf(os.Stderr, "\nSCANNERS:\n")
		fmt.Fprintf(os.Stderr, "  -s string\n")
		fmt.Fprintf(os.Stderr, "    \tScanners to run, comma-separated (e.g., xss,sqli,idor).\n")
		fmt.Fprintf(os.Stderr, "    \tUse 'all' to run all scanners, 'none' for crawling only.\n")
		fmt.Fprintf(os.Stderr, "    \tAvailable: none,xss,sqli,lfi,openredirect,ssrf,exposed,idor,csrf,cmdinjection,ssti,securityheaders,cors,fileupload,bola,massassignment,graphql,blindssrf,domxss\n")

		fmt.Fprintf(os.Stderr, "\nCRAWLING & PERFORMANCE:\n")
		fmt.Fprintf(os.Stderr, "  -c int\n    \tNumber of concurrent workers (default: %d)\n", cfg.Concurrency)
		fmt.Fprintf(os.Stderr, "  -d int\n    \tMaximum crawling depth (default: %d)\n", cfg.MaxDepth)
		fmt.Fprintf(os.Stderr, "  -delay int\n    \tDelay between requests in milliseconds (ms) (default: %d)\n", cfg.Delay)
		fmt.Fprintf(os.Stderr, "  -r int\n    \tMaximum number of retries for failed requests (default: %d)\n", cfg.MaxRetries)

		fmt.Fprintf(os.Stderr, "\nDETECTION:\n")
		fmt.Fprintf(os.Stderr, "  -oast\n    \tEnable OAST for blind vulnerabilities (e.g., Blind SSRF, Blind Command Injection)\n")
		fmt.Fprintf(os.Stderr, "  -render-js\n    \tEnable JavaScript rendering via headless browser (required for 'domxss' scanner)\n")
		fmt.Fprintf(os.Stderr, "  -enrich\n    \tEnable vulnerability enrichment with CISA KEV data\n")
		fmt.Fprintf(os.Stderr, "  --enable-ai\n    \tEnable AI-powered analysis for found vulnerabilities\n")

		fmt.Fprintf(os.Stderr, "\nOUTPUT & REPORTING:\n")
		fmt.Fprintf(os.Stderr, "  -output-json string\n    \tPath to save the report file in JSON format (e.g., report.json)\n")
		fmt.Fprintf(os.Stderr, "  -v\n    \tEnable verbose output (DEBUG level)\n")
		fmt.Fprintf(os.Stderr, "  -vv\n    \tEnable trace-level output (highly verbose)\n")

		fmt.Fprintf(os.Stderr, "\nUTILITIES:\n")
		fmt.Fprintf(os.Stderr, "  -update-kev\n    \tForce update CISA KEV catalog and exit\n")

		fmt.Fprintf(os.Stderr, "\nCONFIGURATION:\n")
		fmt.Fprintf(os.Stderr, "  DursGo automatically loads 'config.yaml' from the current directory.\n")
		fmt.Fprintf(os.Stderr, "  Command-line flags will override settings from the configuration file.\n")

		fmt.Fprintf(os.Stderr, "\nEXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  # Basic scan for XSS and SQLi\n")
		fmt.Fprintf(os.Stderr, "  dursgo -u http://example.com -s xss,sqli\n\n")
		fmt.Fprintf(os.Stderr, "  # Scan for Blind SSRF using OAST (run OAST scanners separately)\n")
		fmt.Fprintf(os.Stderr, "  dursgo -u http://example.com -s blindssrf -oast\n\n")
		fmt.Fprintf(os.Stderr, "  # Crawl a Single-Page Application and save the report\n")
		fmt.Fprintf(os.Stderr, "  dursgo -u http://spa.example.com -s all -render-js -output-json report.json\n\n")
	}

	// Parse all defined flags.
	flag.Parse()

	// Synchronize command-line flags with the loaded configuration struct.
	// This ensures flags override the YAML file settings.
	if enableAI {
		cfg.AI.Enabled = true
	}

	// Determine if the run is command-line driven (-u flag is present).
	// If not, and no output file is specified via flags, use the one from config.yaml.
	uFlagProvided := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "u" {
			uFlagProvided = true
		}
	})

	if jsonOutputFile == "" && !uFlagProvided && cfg.Output.OutputFile != "" {
		jsonOutputFile = cfg.Output.OutputFile
		log.Debug("Using output file from config.yaml: %s", jsonOutputFile)
	}

	// Adjust log level based on verbosity flags.
	if trace {
		log.SetMinLevel(logger.TRACE)
		log.Info("Trace logging enabled (-vv).")
	} else if verbose {
		log.SetMinLevel(logger.DEBUG)
		log.Info("Debug logging enabled (-v).")
	}

	// Validate target URL.
	if targetURLStr == "" {
		log.Error("Target URL is required.")
		flag.Usage()
		os.Exit(1)
	}

	// Check if the URL provided in the command-line differs from the one in config.
	// If so, disable authentication to prevent context leaks.
	if targetURLStr != "" && cfg.Target != "" && !strings.HasPrefix(targetURLStr, cfg.Target) && !strings.HasPrefix(cfg.Target, targetURLStr) {
		log.Warn("Target URL from flag (-u) differs from config.yaml. Disabling all authentication methods for this scan to prevent context leak.")
		// Force disable authentication for this scan.
		cfg.Authentication.Enabled = false
	}

	// Parse and validate the target URL.
	parsedURL, err := url.Parse(targetURLStr)
	if err != nil || !parsedURL.IsAbs() {
		log.Error("Invalid target URL format.")
		os.Exit(1)
	}
	targetBaseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	log.Info("Starting Dursgo scan...")
	log.Info("Target URL: %s", targetBaseURL)

	// Initialize headless browser renderer if JavaScript rendering is enabled.
	var rend *renderer.Renderer
	if renderJS {
		log.Info("JavaScript rendering is ENABLED. Initializing headless browser...")
		var renderErr error
		rend, renderErr = renderer.New()
		if renderErr != nil {
			log.Error("Failed to initialize headless browser renderer: %v. Disabling JS rendering.", renderErr)
		} else {
			defer rend.Close() // Ensure renderer is closed when main exits.
		}
	}

	// Declare variables for OAST (Out-of-Band Application Security Testing) functionality.
	var interactshClient *client.Client
	var oastDomain string
	var oastInteractions []*server.Interaction
	var oastMu sync.Mutex
	var oastCorrelationMap sync.Map

	// Initialize Interactsh client if OAST is enabled.
	if oast {
		interactshClient, err = client.New(client.DefaultOptions)
		if err != nil {
			log.Error("Could not create interactsh client: %v. Disabling OAST.", err)
			oast = false
		} else {
			defer interactshClient.Close() // Ensure client is closed on exit.
			oastDomain = interactshClient.URL()
			log.Info("OAST domain for this session: %s", oastDomain)
			// Start polling for OAST interactions.
			interactshClient.StartPolling(5*time.Second, func(interaction *server.Interaction) {
				oastMu.Lock()
				oastInteractions = append(oastInteractions, interaction)
				oastMu.Unlock()
			})
			defer interactshClient.StopPolling() // Stop polling on exit.
		}
	}

	// Configure HTTP client options.
	clientOpts := httpclient.ClientOptions{
		Timeout:         15 * time.Second,
		UserAgent:       cfg.UserAgent,
		FollowRedirects: true,
		MaxRetries:      maxRetries,
		RequestDelay:    time.Duration(delay) * time.Millisecond,
		TargetBaseURL:   targetBaseURL,
	}

	// Determine if scanning is enabled.
	willScan := scannersToRunStr != "none"

	// Handle authentication based on configuration.
	if cfg.Authentication.Enabled {
		// Dynamic login via form.
		if willScan && cfg.Authentication.LoginURL != "" {
			log.Info("Authentication (Login Action) is enabled. Attempting to log in...")
			tempLoginClient := httpclient.NewClient(log, clientOpts)
			loginReqBody := strings.NewReader(cfg.Authentication.LoginData)
			loginResp, err := tempLoginClient.Post(cfg.Authentication.LoginURL, "application/x-www-form-urlencoded", loginReqBody)
			if err != nil {
				log.Error("Login request failed: %v", err)
				os.Exit(1)
			}
			bodyBytes, _ := io.ReadAll(loginResp.Body)
			loginResp.Body.Close()
			// Verify login success using a keyword.
			if cfg.Authentication.LoginCheckKeyword != "" && !strings.Contains(string(bodyBytes), cfg.Authentication.LoginCheckKeyword) {
				log.Error("Login check failed. Keyword '%s' not found.", cfg.Authentication.LoginCheckKeyword)
				os.Exit(1)
			}
			// Capture session cookies after successful login.
			loginURL, _ := url.Parse(cfg.Authentication.LoginURL)
			loginCookies := tempLoginClient.GetClient().Jar.Cookies(loginURL)
			if len(loginCookies) == 0 {
				log.Error("Login successful, but no session cookies were returned.")
				os.Exit(1)
			}
			var cookieStrings []string
			for _, cookie := range loginCookies {
				cookieStrings = append(cookieStrings, cookie.String())
			}
			finalCookieHeader := strings.Join(cookieStrings, "; ")
			log.Success("Login successful. Session cookie captured and will be used for scanning.")
			clientOpts.AuthCookie = finalCookieHeader
		} else if cfg.Authentication.Cookie != "" || len(cfg.Authentication.Headers) > 0 {
			// Static authentication via cookie or headers.
			log.Info("Static authentication is enabled and will be used for scanning.")
			clientOpts.AuthCookie = cfg.Authentication.Cookie
			clientOpts.AuthHeaders = cfg.Authentication.Headers
		}
	} else {
		log.Info("Authentication is disabled.")
	}

	// Create the main HTTP client with configured options.
	httpClient := httpclient.NewClient(log, clientOpts)

	// Start technology fingerprinting to identify web technologies used by the target.
	log.Info("Starting technology fingerprinting...")
	fp := fingerprint.NewFingerprinter(httpClient, log)
	fingerprintResult := fp.Analyze(targetBaseURL)
	if len(fingerprintResult) > 0 {
		log.Info("Technologies Detected: %v", fingerprintResult)
	}

	// Determine the current user ID for IDOR scanning if authentication is enabled.
	var currentUserID int
	if cfg.Authentication.Enabled {
		currentUserID = cfg.Authentication.ScanIDOR
	}

	// Discover GraphQL endpoint.
	graphQLEndpoint := ""
	// Check if the target URL itself is a GraphQL endpoint.
	if strings.Contains(targetURLStr, "/graphql") || strings.Contains(targetURLStr, "/gql") {
		graphQLEndpoint = targetURLStr
	} else {
		// Otherwise, use the GraphQL finder to discover it.
		finder := discovery.NewGraphQLFinder(httpClient, log)
		graphQLEndpoint = finder.FindEndpoint(targetBaseURL)
	}

	// Initialize scanner options with collected information.
	scannerOptions := scanner.ScannerOptions{
		Concurrency:        concurrency,         // Number of concurrent scan workers.
		OASTDomain:         oastDomain,          // Domain for OAST interactions.
		OASTCorrelationMap: &oastCorrelationMap, // Map to correlate OAST interactions.
		Fingerprint:        fingerprintResult,   // Detected technologies.
		UserID:             currentUserID,       // User ID for IDOR scanning.
		Renderer:           rend,                // Headless browser renderer.
		Client:             httpClient,          // HTTP client for requests.
		GraphQLEndpoint:    graphQLEndpoint,     // Discovered GraphQL endpoint.
	}

	// Initialize the crawler with the authenticated HTTP client.
	dursGoCrawler, err := crawler.NewCrawler(httpClient, log, targetBaseURL, concurrency, maxDepth, rend)
	if err != nil {
		log.Error("Failed to initialize crawler: %v", err)
		os.Exit(1)
	}

	// Prepare entry points for crawling.
	entryPoints := []string{targetURLStr}
	for _, seed := range cfg.SeedURLs {
		if seed != "" {
			entryPoints = append(entryPoints, seed)
		}
	}
	// Remove duplicate entry points for efficiency.
	uniqueEntryPoints := make(map[string]struct{})
	finalEntryPoints := []string{}
	for _, entry := range entryPoints {
		if _, exists := uniqueEntryPoints[entry]; !exists {
			uniqueEntryPoints[entry] = struct{}{}
			finalEntryPoints = append(finalEntryPoints, entry)
		}
	}

	// Start the crawling process.
	log.Info("Starting crawling from %d unique entry points...", len(finalEntryPoints))
	resultsChan := dursGoCrawler.Crawl(finalEntryPoints, 0)
	// Consume results from the crawling channel to ensure completion.
	for range resultsChan {
	}

	// Retrieve discovered parameterized requests and all discovered URLs from the crawler.
	parameterizedRequestsForScan := dursGoCrawler.GetParameterizedRequestsForScanning()
	allDiscoveredURLs := dursGoCrawler.GetDiscoveredURLs()

	// Prepare initial scan requests, merging parameters for the same path to avoid data loss.
	mergedRequests := make(map[string]*crawler.ParameterizedRequest)

	// Process requests discovered by the crawler that have parameters.
	for i := range parameterizedRequestsForScan {
		req := parameterizedRequestsForScan[i]
		key := req.Method + " " + req.Path

		if existing, ok := mergedRequests[key]; ok {
			// If a request for this path already exists, merge the parameters.
			paramSet := make(map[string]bool)
			for _, p := range existing.ParamNames {
				paramSet[p] = true
			}
			for _, newParam := range req.ParamNames {
				if !paramSet[newParam] {
					existing.ParamNames = append(existing.ParamNames, newParam)
					paramSet[newParam] = true
				}
			}
		} else {
			// Otherwise, add the new request to the map.
			reqCopy := req
			mergedRequests[key] = &reqCopy
		}
	}

	// Also process all discovered URLs to ensure they are included as GET requests.
	for _, u := range allDiscoveredURLs {
		parsedU, err := url.Parse(u)
		if err != nil {
			continue
		}
		key := "GET " + parsedU.Path
		if _, exists := mergedRequests[key]; !exists {
			mergedRequests[key] = &crawler.ParameterizedRequest{
				URL:            u,
				Method:         "GET",
				Path:           parsedU.Path,
				ParamLocations: []string{"query"},
				ParamNames:     []string{},
			}
		}
	}

	// Convert the map of merged requests back into a slice for scanning.
	initialScanRequests := make([]crawler.ParameterizedRequest, 0, len(mergedRequests))
	for _, req := range mergedRequests {
		initialScanRequests = append(initialScanRequests, *req)
	}

	// Discover additional parameters if scanning is enabled.
	var enrichedScanRequests []crawler.ParameterizedRequest
	if willScan {
		enrichedScanRequests = dursGoCrawler.DiscoverParameters(initialScanRequests)
	} else {
		enrichedScanRequests = initialScanRequests
	}

	// Log crawler results.
	log.Info("\n--- Crawler Results ---")
	log.Info("Total unique URLs discovered: %d", len(allDiscoveredURLs))
	if len(allDiscoveredURLs) > 0 {
		log.Info("Full list of discovered URLs:")
		sortedURLs := make([]string, len(allDiscoveredURLs))
		copy(sortedURLs, allDiscoveredURLs)
		sort.Strings(sortedURLs)
		for _, u := range sortedURLs {
			log.Info("- %s", u)
		}
	}
	log.Info("Found %d unique parameterized requests for vulnerability scanning.", len(enrichedScanRequests))
	if len(enrichedScanRequests) > 0 {
		var getRequests, postRequests []crawler.ParameterizedRequest
		for _, req := range enrichedScanRequests {
			if req.Method == "GET" {
				getRequests = append(getRequests, req)
			} else {
				postRequests = append(postRequests, req)
			}
		}
		// Sort requests for consistent logging.
		sort.Slice(getRequests, func(i, j int) bool { return getRequests[i].URL < getRequests[j].URL })
		sort.Slice(postRequests, func(i, j int) bool { return postRequests[i].URL < postRequests[j].URL })
		if len(getRequests) > 0 {
			log.Info("\n--- Parameterized GET Requests Found (%d) ---", len(getRequests))
			for _, req := range getRequests {
				if len(req.ParamNames) > 0 {
					log.Info("- %s (Params: %s)", req.URL, strings.Join(req.ParamNames, ", "))
				}
			}
		}
		if len(postRequests) > 0 {
			log.Info("\n--- Parameterized POST Requests Found (%d) ---", len(postRequests))
			for _, req := range postRequests {
				if len(req.ParamNames) > 0 {
					log.Info("- %s (Params: %s)", req.URL, strings.Join(req.ParamNames, ", "))
				}
			}
		}
	}

	// Declare a slice to store all discovered vulnerabilities.
	var allVulnerabilities []scanner.VulnerabilityResult

	// Proceed with scanning if 'scanners_to_run' is not set to "none".
	if willScan {
		// Determine which scanners to run based on command-line flag or config.
		scannersToRun := make(map[string]bool)
		if scannersToRunStr == "all" {
			// Register all available scanners.
			for _, s := range []string{"xss", "sqli", "lfi", "openredirect", "ssrf", "exposed", "idor", "csrf", "cmdinjection", "ssti", "securityheaders", "cors", "fileupload", "bola", "massassignment", "graphql", "domxss"} {
				scannersToRun[s] = true
			}
			// Conditionally enable blind SSRF if OAST is active.
			if oast {
				scannersToRun["blindssrf"] = true
			}
			// Conditionally enable DOM XSS if JavaScript rendering is active.
			if renderJS {
				scannersToRun["domxss"] = true
			}
		} else {
			// Register specific scanners listed in the flag.
			for _, s := range strings.Split(strings.ToLower(scannersToRunStr), ",") {
				scannersToRun[strings.TrimSpace(s)] = true
			}
		}

		// If any scanners are selected, initialize and run them.
		if len(scannersToRun) > 0 {
			log.Info("\n--- Initiating Vulnerability Scans ---")
			scannerManager := scanner.NewManager(httpClient, log, scannerOptions)

			// Register individual scanners based on the 'scannersToRun' map.
			if scannersToRun["all"] || scannersToRun["xss"] || scannersToRun["xss-reflected"] {
				scannerManager.RegisterScanner(xss.NewReflectedXSSScanner())
			}
			if scannersToRun["all"] || scannersToRun["xss"] || scannersToRun["xss-stored"] {
				scannerManager.RegisterScanner(xss.NewStoredXSSScanner())
			}
			if scannersToRun["sqli"] {
				scannerManager.RegisterScanner(sqli.NewSQLiScanner())
			}
			if scannersToRun["lfi"] {
				scannerManager.RegisterScanner(lfi.NewLFIScanner())
			}
			if scannersToRun["openredirect"] {
				scannerManager.RegisterScanner(openredirect.NewOpenRedirectScanner())
			}
			if scannersToRun["ssrf"] {
				scannerManager.RegisterScanner(ssrf.NewSSRFScanner())
			}
			if scannersToRun["idor"] {
				scannerManager.RegisterScanner(idor.NewIDORScanner())
			}
			if scannersToRun["csrf"] {
				scannerManager.RegisterScanner(csrf.NewCSRFScanner())
			}
			if scannersToRun["cmdinjection"] {
				scannerManager.RegisterScanner(cmdinjection.NewCommandInjectionScanner())
			}
			if scannersToRun["ssti"] {
				scannerManager.RegisterScanner(ssti.NewSSTIScanner())
			}
			if scannersToRun["fileupload"] {
				scannerManager.RegisterScanner(fileupload.NewFileUploadScanner())
			}
			if scannersToRun["securityheaders"] {
				scannerManager.RegisterScanner(securityheaders.NewSecurityHeadersScanner())
			}
			if scannersToRun["cors"] {
				scannerManager.RegisterScanner(cors.NewCORSScanner())
			}
			if scannersToRun["exposed"] {
				scannerManager.RegisterScanner(exposed.NewExposedScanner())
			}
			if scannersToRun["bola"] {
				scannerManager.RegisterScanner(bola.NewBOLAScanner())
			}
			if scannersToRun["massassignment"] {
				scannerManager.RegisterScanner(massassignment.NewMassAssignmentScanner())
			}
			if scannersToRun["blindssrf"] && oast {
				scannerManager.RegisterScanner(blindssrf.NewBlindSSRFScanner())
			}
			if scannersToRun["domxss"] && renderJS {
				scannerManager.RegisterScanner(domxss.NewDOMXSSScanner())
			}
			if scannersToRun["graphql"] {
				scannerManager.RegisterScanner(graphql.NewGraphQLScanner())
			}

			// Run scans if there are registered scanners and discovered requests.
			if len(scannerManager.GetRegisteredScanners()) > 0 && len(enrichedScanRequests) > 0 {
				log.Info("Running scanners on %d unique targets (including proactively discovered params)...", len(enrichedScanRequests))
				vulns := scannerManager.RunScans(enrichedScanRequests)
				allVulnerabilities = append(allVulnerabilities, vulns...)
			}
		}
	} else {
		log.Info("\nOnly crawling requested. Skipping vulnerability scan.")
	}

	// Handle OAST (Out-of-Band Application Security Testing) interactions.
	if oast {
		log.Info("Waiting for final OAST interactions (10 seconds)...")
		time.Sleep(10 * time.Second) // Wait for any pending OAST interactions.
		interactshClient.StopPolling()
		oastMu.Lock()
		defer oastMu.Unlock()
		if len(oastInteractions) > 0 {
			log.Success("--- OAST Interaction(s) Detected! Correlating results... ---")
			var confirmedOASTFindings []scanner.VulnerabilityResult
			// Iterate through potential vulnerabilities and correlate with OAST interactions.
			scannerOptions.OASTCorrelationMap.Range(func(key, value interface{}) bool {
				correlationID := key.(string)
				potentialVuln := value.(scanner.VulnerabilityResult)
				for _, interaction := range oastInteractions {
					if strings.Contains(interaction.FullId, correlationID) {
						potentialVuln.Details += fmt.Sprintf(" Confirmed via %s interaction from %s.", interaction.Protocol, interaction.RemoteAddress)
						confirmedOASTFindings = append(confirmedOASTFindings, potentialVuln)
						scannerOptions.OASTCorrelationMap.Delete(key) // Remove correlated vulnerability from map.
						return false                                  // Stop iterating for this key.
					}
				}
				return true // Continue iterating.
			})
			allVulnerabilities = append(allVulnerabilities, confirmedOASTFindings...)
		} else {
			log.Info("No OAST interactions detected.")
		}
	}

	// Display scan results.
	log.Info("\n--- Scan Results ---")
	var finalReportVulns []scanner.VulnerabilityResult
	if len(allVulnerabilities) > 0 {
		reportedVulnerabilities := make(map[string]scanner.VulnerabilityResult)
		// Deduplicate and log vulnerabilities.
		for _, vuln := range allVulnerabilities {
			parsedVulnURL, err := url.Parse(vuln.URL)
			var reportKey string
			if err == nil {
				// Normalize path for deduplication (e.g., /product/1 and /product/2 become /product/{ID}).
				normalizedPath := normalizePathForDeduplication(parsedVulnURL.Path)
				reportKey = fmt.Sprintf("%s|%s|%s", vuln.VulnerabilityType, normalizedPath, vuln.Parameter)
			} else {
				reportKey = fmt.Sprintf("%s|%s|%s", vuln.VulnerabilityType, vuln.URL, vuln.Parameter)
			}

			if _, exists := reportedVulnerabilities[reportKey]; !exists {
				reportedVulnerabilities[reportKey] = vuln
				finalReportVulns = append(finalReportVulns, vuln)
				log.Success("--------------------------------------------------")
				log.Success("Vulnerability Found: %s", vuln.VulnerabilityType)
				log.Success("  URL: %s", vuln.URL)
				if vuln.Parameter != "" {
					log.Success("  Parameter: %s", vuln.Parameter)
				}
				if vuln.Location != "" {
					log.Success("  Location: %s", vuln.Location)
				}
				if vuln.Payload != "" {
					log.Success("  Payload/Info: %s", vuln.Payload)
				}
				if vuln.Severity != "" {
					log.Success("  Severity: %s", vuln.Severity)
				}
				log.Success("  Details: %s", vuln.Details)
			}
		}
		log.Success("--------------------------------------------------")
		log.Info("Total unique vulnerabilities reported: %d", len(reportedVulnerabilities))
	} else if willScan {
		log.Info("No vulnerabilities found.")
	}

	// Generate JSON report if output file is specified.
	// Manual check for -output-json as a fallback for potential flag parsing issues.
	if jsonOutputFile == "" {
		for i, arg := range os.Args {
			if arg == "-output-json" && i+1 < len(os.Args) {
				jsonOutputFile = os.Args[i+1]
				log.Debug("Manually parsed -output-json flag as a fallback: %s", jsonOutputFile)
				break
			}
		}
	}

	if jsonOutputFile != "" {
		// --- REPORT SAVING LOGIC ---
		reportsDir := "reports"
		fullReportPath := jsonOutputFile

		// If the provided path is not absolute and does not already start with "reports/",
		// then join it with the "reports" directory.
		if !filepath.IsAbs(fullReportPath) && !strings.HasPrefix(fullReportPath, reportsDir+string(os.PathSeparator)) {
			fullReportPath = filepath.Join(reportsDir, fullReportPath)
		}

		// Ensure the directory for the report file exists.
		reportDir := filepath.Dir(fullReportPath)
		if err := os.MkdirAll(reportDir, 0755); err != nil {
			log.Error("Failed to create reports directory '%s': %v", reportDir, err)
		} else {
			log.Info("Generating JSON report to %s...", fullReportPath)

			activeScannersList := make([]string, 0)
			if willScan {
				scannersToRun := make(map[string]bool)
				if scannersToRunStr == "all" {
					for _, s := range []string{"xss", "sqli", "lfi", "openredirect", "ssrf", "exposed", "idor", "csrf", "cmdinjection", "ssti", "securityheaders", "cors", "fileupload", "bola", "massassignment", "graphql", "domxss"} {
						scannersToRun[s] = true
					}
				} else {
					for _, s := range strings.Split(strings.ToLower(scannersToRunStr), ",") {
						scannersToRun[strings.TrimSpace(s)] = true
					}
				}
				for scannerName := range scannersToRun {
					activeScannersList = append(activeScannersList, scannerName)
				}
				sort.Strings(activeScannersList)
			}

			var paramRequestsForReport []crawler.ParameterizedRequest
			if !willScan {
				// In pure crawling mode, preserve discovered endpoints and their parameters for the report.
				paramRequestsForReport = enrichedScanRequests
			}

			enrichedVulns := make([]scanner.VulnerabilityResult, len(finalReportVulns))
			copy(enrichedVulns, finalReportVulns)

			// Enrich vulnerabilities with CISA KEV data if enabled.
			if enableEnrichment {
				log.Info("Enriching vulnerabilities with CISA KEV data...")

				if enableEnrichment {
					cacheDir := filepath.Join(os.TempDir(), "dursgo-cache")
					enricher, err := enrichment.NewEnricher(cacheDir)
					if err != nil {
						log.Error("Failed to initialize enricher: %v", err)
					} else {
						defer enricher.Close()
						var enrichErr error
						enrichedVulns, enrichErr = enrichVulnerabilities(enrichedVulns, enricher, log)
						if enrichErr != nil {
							log.Error("Failed to enrich vulnerabilities: %v", err)
						}
					}
				}
			}

			// Analyze vulnerabilities with AI if enabled.
			if cfg.AI.Enabled {
				log.Info("Analyzing vulnerabilities with AI...")
				aiClient, err := ai.NewAIClient(&cfg.AI)
				if err != nil {
					log.Error("Failed to initialize AI client: %v", err)
				} else {
					// Create a new slice for vulnerabilities that include AI analysis.
					analyzedVulns := make([]scanner.VulnerabilityResult, len(enrichedVulns))
					var wg sync.WaitGroup
					for i, vuln := range enrichedVulns {
						wg.Add(1)
						go func(index int, v scanner.VulnerabilityResult) {
							defer wg.Done()
							log.Debug("Sending vulnerability to AI for analysis: %s on %s", v.VulnerabilityType, v.URL)
							analysis, err := aiClient.AnalyzeVulnerability(context.Background(), v)
							if err != nil {
								log.Error("Failed to analyze vulnerability with AI: %v", err)
								analyzedVulns[index] = v // Keep original vuln on error
							} else {
								v.AIAnalysis = analysis
								analyzedVulns[index] = v
								log.Info("Successfully received AI analysis for %s on %s", v.VulnerabilityType, v.URL)
							}
						}(i, vuln)
					}
					wg.Wait()
					enrichedVulns = analyzedVulns // Replace with the analyzed results.
				}
			}

			// Finalize and write the report.
			reportData := reporter.NewReport(targetURLStr, startTime)
			reportData.Finalize(time.Now(), startTime, enrichedVulns, activeScannersList, fingerprintResult, len(allDiscoveredURLs), paramRequestsForReport)

			reportErr := reporter.WriteJSONReport(reportData, fullReportPath)
			if reportErr != nil {
				log.Error("Failed to write JSON report: %v", reportErr)
			} else {
				log.Success("JSON report successfully saved to %s", fullReportPath)
			}
		}
	}

	log.Info("Dursgo scan completed.")
}

// normalizePathForDeduplication replaces numeric parts of a URL path with a placeholder
// to group vulnerabilities found in rewritten URLs (e.g., /product/1, /product/2).
func normalizePathForDeduplication(path string) string {
	// This regex finds any sequence of one or more digits.
	re := regexp.MustCompile(`\d+`)
	// Replace all numeric sequences with a static placeholder.
	return re.ReplaceAllString(path, "{ID}")
}

// convertToEnrichmentVulnerability converts a vulnerability from the scanner format to the enrichment format.
func convertToEnrichmentVulnerability(vuln scanner.VulnerabilityResult) *enrichment.Vulnerability {
	cve := vuln.CVE

	// If CVE is not directly available, try to extract it from the details.
	if cve == "" {
		cve = extractCVEFromDetails(vuln.Details)
	}

	fmt.Printf("Extracted CVE for vulnerability: %s\n", cve)

	return &enrichment.Vulnerability{
		ID:          "", // ID is typically generated by the reporting system or left empty.
		Type:        vuln.VulnerabilityType,
		URL:         vuln.URL,
		Parameter:   vuln.Parameter,
		Payload:     vuln.Payload,
		Details:     vuln.Details,
		Severity:    vuln.Severity,
		Remediation: vuln.Remediation,
		CVE:         cve,
	}
}

// extractCVEFromDetails attempts to extract a CVE ID from a given string.
func extractCVEFromDetails(details string) string {
	start := strings.Index(details, "CVE-")
	if start == -1 {
		return ""
	}

	end := start + 20 // Assume max CVE length for initial slice.
	if end > len(details) {
		end = len(details)
	}
	candidate := details[start:end]

	// Basic validation for CVE format (e.g., CVE-YYYY-NNNNN).
	if len(candidate) >= 9 &&
		strings.HasPrefix(candidate, "CVE-") &&
		candidate[4:8] >= "1999" && // CVEs started in 1999.
		candidate[8] == '-' {

		// Find the end of the numeric part of the CVE.
		for i := 9; i < len(candidate); i++ {
			if candidate[i] < '0' || candidate[i] > '9' {
				return candidate[:i] // Return the valid CVE part.
			}
		}
		return candidate // Return the full candidate if it's all digits after the year.
	}
	return "" // Not a valid CVE format.
}

// enrichVulnerabilities enriches a list of vulnerabilities with CISA KEV data.
func enrichVulnerabilities(vulns []scanner.VulnerabilityResult, enricher enrichment.Enricher, log *logger.Logger) ([]scanner.VulnerabilityResult, error) {
	ctx := context.Background()
	enrichedVulns := make([]scanner.VulnerabilityResult, 0, len(vulns))

	if log != nil {
		log.Info("Starting enrichment of %d vulnerabilities...", len(vulns))
	}

	for i := 0; i < len(vulns); i++ {
		if log != nil {
			log.Info("Processing vulnerability %d of %d", i+1, len(vulns))
		}

		vuln := vulns[i]

		if log != nil {
			log.Info("Vulnerability details: %+v", vuln)
		}

		// Convert scanner's vulnerability format to enrichment's format.
		enrichVuln := convertToEnrichmentVulnerability(vuln)

		// Perform the enrichment.
		if err := enricher.Enrich(ctx, enrichVuln); err != nil {
			if log != nil {
				log.Error("Failed to enrich vulnerability: %v", err)
			}
		}

		// If CISA KEV data is available, append it to vulnerability details and metadata.
		if enrichVuln.Enrichment != nil && enrichVuln.Enrichment.CISAKEV != nil {
			kev := enrichVuln.Enrichment.CISAKEV

			enrichmentInfo := "\n\n--- CISA KEV ENRICHMENT ---\n"
			enrichmentInfo += "In CISA KEV Catalog: Yes\n"
			if !kev.DateAdded.IsZero() {
				enrichmentInfo += fmt.Sprintf("Date Added: %s\n", kev.DateAdded.Format("2006-01-02"))
			}
			if !kev.DueDate.IsZero() {
				enrichmentInfo += fmt.Sprintf("Due Date: %s\n", kev.DueDate.Format("2006-01-02"))
			}
			if kev.RequiredAction != "" {
				enrichmentInfo += fmt.Sprintf("Required Action: %s\n", kev.RequiredAction)
			}
			if kev.Notes != "" {
				enrichmentInfo += fmt.Sprintf("Notes: %s\n", kev.Notes)
			}
			vuln.Details += enrichmentInfo

			// Store CISA KEV data in the vulnerability's enrichment map.
			if vuln.Enrichment == nil {
				vuln.Enrichment = make(map[string]interface{})
			}

			cisaKEVData := make(map[string]interface{})
			cisaKEVData["in_catalog"] = true
			if !kev.DateAdded.IsZero() {
				cisaKEVData["date_added"] = kev.DateAdded.Format("2006-01-02")
			}
			if !kev.DueDate.IsZero() {
				cisaKEVData["due_date"] = kev.DueDate.Format("2006-01-02")
			}
			if kev.RequiredAction != "" {
				cisaKEVData["required_action"] = kev.RequiredAction
			}
			if kev.Notes != "" {
				cisaKEVData["notes"] = kev.Notes
			}

			vuln.Enrichment["cisa_kev"] = cisaKEVData
		}

		enrichedVulns = append(enrichedVulns, vuln)
	}

	if log != nil {
		log.Info("Finished enriching %d vulnerabilities", len(enrichedVulns))
	}
	return enrichedVulns, nil
}
