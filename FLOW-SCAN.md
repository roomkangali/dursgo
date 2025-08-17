# Dursgo Scanner Flowchart (Using Command-Line Flags)

This flowchart illustrates the detailed workflow of the Dursgo scanner when initiated with command-line flags like `-u`, `-s`, etc.

```
+--------------------------------------------------+
|  PHASE 1: INITIALIZATION & CONFIGURATION         |
+--------------------------------------------------+
|
|  [+] Dursgo Starts
|   |
|   '--> [ Command-Line Flags: -u, -s, -c, -v, etc. ]
|         (Primary source for this scan's settings. Overrides config.yaml)
|
|  [>] Core Process: Flag Parsing Engine
|   |   (main.go: flag.Parse)
|   |
|   '--> V (Reads and parses command-line arguments)
|
|  [>] Output: Populated Variables (targetURLStr, scannersToRunStr, etc.)
|   |
|   '--> V (Settings are now in memory for this specific scan)
|
+--------------------------------------------------+
|  PHASE 2: PRE-SCAN SETUP                         |
+--------------------------------------------------+
|
|  [!] Authentication is DISABLED
|      (Note: Auth can only be configured via config.yaml.
|       Using -u with a different target disables it for safety.)
|
|  [+] Component Initialization
|   |
|   |--- [ HTTP Client ]
|   |      (Initialized with concurrency, delay from flags. No auth.)
|   |
|   |--- [ OAST Client (Interactsh) ] (if -oast flag is present)
|   |      (Starts polling for out-of-band interactions)
|   |
|   '--- [ Headless Browser (Renderer) ] (if -render-js flag is present)
|         (Launches a Chrome instance for JavaScript rendering)
|
|  [>] Core Process: Technology Fingerprinting
|   |   (fingerprint.Analyze on the -u target)
|   |
|   '--> [>] Output: Detected Technologies (e.g., WordPress, Laravel)
|
+--------------------------------------------------+
|  PHASE 3: DISCOVERY & CRAWLING                   |
+--------------------------------------------------+
|
|  [+] Crawler Initialization
|   |   (crawler.NewCrawler with the unauthenticated client)
|   |
|   '--> V (Entry point is the URL from the -u flag)
|
|  [>] Core Process: Concurrent Crawling Engine
|   |
|   |--- (Fetches robots.txt, sitemaps, API specs)
|   |
|   |--- (Extracts links from HTML, JS files, Source Maps)
|   |
|   |--- (Discovers forms and parameters)
|   |
|   '--- (Proactively probes for common hidden parameters)
|
|  [>] Output: List of Parameterized Requests
|   |   (Unique, crawlable endpoints with identified parameters)
|   |
|   '--> V (Ready for scanning)
|
+--------------------------------------------------+
|  PHASE 4: VULNERABILITY SCANNING                 |
+--------------------------------------------------+
|
|  [+] Scanner Manager Initialization
|   |   (scanner.NewManager)
|   |
|   '--> V (Registers scanners listed in the -s flag, e.g., "xss,sqli")
|
|  [>] Core Process: Concurrent Scanning Engine
|   |   (manager.RunScans with multiple worker goroutines)
|   |
|   |--- [ Individual Scanners ]
|   |      (e.g., SQLi, XSS, LFI scanners run in parallel)
|   |      |
|   |      '--> (Each scanner sends crafted payloads to the list of
|   |           Parameterized Requests and analyzes responses)
|   |
|   '--- [ OAST Correlation ] (if -oast flag is present)
|         (Waits for and correlates any out-of-band pings
|          with sent payloads like Blind SSRF)
|
|  [>] Output: List of Vulnerability Findings
|
+--------------------------------------------------+
|  PHASE 5: REPORTING                              |
+--------------------------------------------------+
|
|  [+] Result Processing
|   |
|   |--- [ Deduplication Engine ]
|   |      (Normalizes paths like /user/1 and /user/2 to /user/{ID}
|   |       to report unique vulnerabilities only once)
|   |
|   '--- [ CISA KEV Enrichment ] (if -enrich flag is present)
|         (Checks findings against the Known Exploited Vulnerabilities catalog)
|
|  [>] Core Process: Report Generation
|   |
|   |--- (Displays findings on the console)
|   |
|   '--- (Saves detailed report to the path specified in -output-json flag)
|
|  [+] Dursgo Scan Finished
|
+--------------------------------------------------+
