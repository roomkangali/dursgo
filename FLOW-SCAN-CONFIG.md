# Dursgo Scanner Flowchart (Using config.yaml)

This flowchart illustrates the detailed workflow of the Dursgo scanner when initiated with a `config.yaml` file.

```
+--------------------------------------------------+
|  PHASE 1: INITIALIZATION & CONFIGURATION         |
+--------------------------------------------------+
|
|  [+] Dursgo Starts
|   |
|   '--> [ config.yaml ]
|         (Primary source for all settings: target, auth, scanners, etc.)
|
|  [>] Core Process: Configuration Loading Engine
|   |   (main.go: config.LoadConfig)
|   |
|   '--> V (Reads and parses config.yaml)
|
|  [>] Output: Populated Config Struct (cfg)
|   |
|   '--> V (Settings are now in memory)
|
+--------------------------------------------------+
|  PHASE 2: PRE-SCAN SETUP                         |
+--------------------------------------------------+
|
|  [+] Authentication Handling (if enabled in cfg)
|   |
|   |--- [ Dynamic Form Login ]
|   |      (Sends POST to auth.login_url with auth.login_data,
|   |       verifies with auth.login_check_keyword, captures session cookies)
|   |
|   '--- [ Static Credentials ]
|         (Applies auth.cookie and/or auth.headers to the HTTP client)
|
|  [+] Component Initialization
|   |
|   |--- [ HTTP Client ]
|   |      (Initialized with auth cookies/headers, concurrency, delay, etc.)
|   |
|   |--- [ OAST Client (Interactsh) ] (if oast: true)
|   |      (Starts polling for out-of-band interactions)
|   |
|   '--- [ Headless Browser (Renderer) ] (if render_js: true)
|         (Launches a Chrome instance for JavaScript rendering)
|
|  [>] Core Process: Technology Fingerprinting
|   |   (fingerprint.Analyze on cfg.target)
|   |
|   '--> [>] Output: Detected Technologies (e.g., WordPress, Laravel)
|
+--------------------------------------------------+
|  PHASE 3: DISCOVERY & CRAWLING                   |
+--------------------------------------------------+
|
|  [+] Crawler Initialization
|   |   (crawler.NewCrawler with authenticated client)
|   |
|   '--> V (Entry points: cfg.target and cfg.seed_urls)
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
|   '--> V (Registers scanners listed in cfg.scanners_to_run)
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
|   '--- [ OAST Correlation ] (if oast: true)
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
|   '--- [ CISA KEV Enrichment ] (if enrich: true)
|         (Checks findings against the Known Exploited Vulnerabilities catalog)
|
|  [>] Core Process: Report Generation
|   |   (reporter.WriteJSONReport)
|   |
|   |--- (Displays findings on the console)
|   |
|   '--- (Saves detailed report to cfg.output.output_file in JSON format)
|
|  [+] Dursgo Scan Finished
|
+--------------------------------------------------+
