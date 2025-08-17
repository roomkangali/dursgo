# DursGo - Web Application Security Scanner

DursGo is a web application security scanner designed for penetration testing and automated security audits. Built with Go, DursGo offers high-performance and flexible security scanning capabilities.

## Key Features

- **Intelligent, Context-Aware Scanning:** Detects a wide range of vulnerabilities using context-aware logic for high accuracy.
- **Advanced False Positive Reduction:** Employs sophisticated verification methods to minimize false positives.
- **Comprehensive Authentication Support:** Capable of scanning applications protected by login forms, bearer tokens, or session cookies.
- **In-Depth Automated Discovery:** Performs comprehensive crawling of web applications, including JavaScript-based SPAs and API endpoints.
- **Accurate Finding Deduplication:** Presents clean, unique findings by normalizing and deduplicating results.
- **OAST (Out-of-Band) Integration:** Detects blind vulnerabilities through out-of-band verification.
- **CISA KEV Enrichment:** Enriches findings with context from the CISA Known Exploited Vulnerabilities (KEV) catalog.
- **Flexible Configuration:** Highly customizable via both YAML configuration files and command-line flags.
- **High-Performance Engine:** Lightweight and fast, leveraging the performance of Go.

## Scan Workflow

Dursgo follows a systematic, multi-stage workflow to ensure comprehensive coverage and accurate results:

1.  **Initial Technology Fingerprinting:** Dursgo begins by fingerprinting the technologies used by the target application (e.g., WordPress, Laravel, Git). This data is used to tailor subsequent scan modules.
2.  **Intelligent Crawling & Endpoint Discovery:** The application is crawled to discover all accessible URLs, forms, and endpoints. If `-render-js` is enabled, Dursgo utilizes a headless browser to render and discover content on Single-Page Applications (SPAs).
3.  **Proactive Parameter Discovery:** In addition to visible parameters, Dursgo proactively injects common parameter names to discover "hidden" parameters that may be vulnerable.
4.  **Scanner Execution:** The selected scanner modules (e.g., XSS, SQLi) are executed concurrently against all discovered targets. Each scanner employs specialized logic to maximize detection and minimize false positives.
5.  **OAST Verification (If Active):** If the `-oast` flag is enabled, Dursgo polls the OAST server for any out-of-band interactions that confirm blind vulnerabilities.
6.  **Deduplication & Reporting:** All findings are aggregated, deduplicated based on vulnerability type and a normalized path, and then presented in the console output and/or a JSON report file.

## Installation

### Prerequisites

- **Go Language:** Ensure Go version 1.23 or newer is installed.
  - To check your Go version: `go version`
  - To install Go, visit: [https://golang.org/doc/install](https://golang.org/doc/install)

### Installation Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/username/DursGo.git
    cd DursGo
    ```
    *(Replace the URL with the actual repository URL)*

2.  **Build the Application:**
    Compile the source code into an executable binary. This command will create a `dursgo` file (or `dursgo.exe` on Windows) in the current directory.
    ```bash
    go build -o dursgo ./cmd/dursgo
    ```

3.  **(Optional) Move the Binary to Your PATH:**
    To run `dursgo` from any directory, move the compiled binary to a location in your system's PATH.
    ```bash
    # For Linux/macOS
    sudo mv dursgo /usr/local/bin/
    ```

### Initial Configuration

-   **`config.yaml`:** Dursgo automatically looks for a `config.yaml` file in the directory it is run from. Be sure to customize this file for your target and scanning needs.
-   **Authentication:** If your target requires authentication, configure the `authentication` section in `config.yaml`.

### Additional Prerequisites for Specific Scanners

-   **For the DOM XSS Scanner (`-s domxss`):**
    -   **Headless Browser (Chromium):** This scanner requires a headless browser like Google Chrome or Chromium to be installed. The underlying library will attempt to find it automatically.
    -   *Example Chromium Installation (Linux):* `sudo apt-get install chromium-browser`
-   **For OAST-Based Scanners (`-s blindssrf`, `-s cmdinjection` with OAST):**
    -   **OAST Service (Interactsh):** These scanners rely on an external OAST service. Dursgo will automatically use the default public Interactsh server when the `--oast` flag is used.

## Quick Start

### Basic Scan
```bash
./dursgo -u http://example.com -s xss,sqli
```

### Scan with OAST (Out-of-Band)
To run a scanner that relies on OAST, use the `--oast` flag.

**Important Note:** For accurate and reliable OAST correlation, it is strongly recommended to run **only one OAST-dependent scanner at a time**.

```bash
# Correct: Scan for Blind SSRF
./dursgo -u http://example.com -s blindssrf --oast

# Correct: Scan for Blind Command Injection
./dursgo -u http://example.com -s cmdinjection --oast

# Avoid: Running multiple OAST scanners together may lead to correlation issues.
# ./dursgo -u http://example.com -s blindssrf,cmdinjection --oast
```

### Using a Configuration File
DursGo automatically loads `config.yaml` from the current working directory if no flags are specified. The configuration in `config.yaml` serves as the default settings.

Command-line flags (e.g., `-u http://new-target.com`) will **override** the corresponding values in `config.yaml` for the current scan execution.

## Command-Line Options

| Flag           | Description                                         | Example                    |
|----------------|-----------------------------------------------------|----------------------------|
| `-h`, `--help` | Show the help message and exit.                     | `-h`                       |
| `-u`           | Target URL for the scan.                            | `-u http://example.com`    |
| `-s`           | Comma-separated list of scanners to run.            | `-s xss,sqli,idor`         |
| `-c`           | Number of concurrent workers/threads.               | `-c 10`                    |
| `-d`           | Maximum crawl depth.                                | `-d 3`                     |
| `-delay`       | Delay between requests in milliseconds (ms).        | `-delay 100`               |
| `-enrich`      | Enable vulnerability enrichment with CISA KEV data. | `-enrich`                  |
| `-oast`        | Enable OAST (Out-of-Band) for blind vulnerabilities.| `-oast`                    |
| `-output-json` | Path to save the report file in JSON format.        | `-output-json result.json` |
| `-r`           | Maximum number of retries for failed requests.      | `-r 3`                     |
| `-render-js`   | Enable JavaScript rendering for crawling SPAs.      | `-render-js`               |
| `-update-kev`  | Force an update of the CISA KEV catalog and exit.   | `-update-kev`              |
| `-v`           | Enable verbose output (DEBUG level).                | `-v`                       |
| `-vv`          | Enable trace-level output (highly verbose).         | `-vv`                      |

## Configuration File (`config.yaml`)

DursGo supports configuration via a YAML file for more complex settings, particularly for authentication.

### Example Basic Configuration
```yaml
# Primary target
target: "http://example.com"

# Number of concurrent workers
concurrency: 10

# List of scanners to run
scanners_to_run: "xss,sqli,idor"

# Output settings
output:
  verbose: false
  format: "text"
  output_file: "scan_results.txt"
```

### Authentication Configuration

DursGo supports multiple authentication methods. Choose the one that matches your target application.

#### 1. Form-Based Authentication (Dynamic Login)
Use this when credentials are available and DursGo can handle the login process automatically.

```yaml
authentication:
  enabled: true
  login_url: "http://example.com/login"
  login_method: "POST"
  login_data: "username=admin&password=password123"
  login_check_keyword: "Logout"
```

#### 2. Cookie-Based Authentication (Static)
Use this when a valid session cookie has been obtained.

```yaml
authentication:
  enabled: true
  cookie: "session=a1b2c3d4e5f6; user_id=123; role=admin"
```

#### 3. Header-Based Authentication (Static)
Use this for API Keys or JWT (Bearer) Tokens.

```yaml
authentication:
  enabled: true
  headers:
    Authorization: "Bearer eyJhbGciOiJIUzI1Ni...[token]"
    X-API-Key: "secret-api-key-12345"
```

## JSON Report Structure

When using the `--output-json` flag, DursGo generates a structured JSON file with the following main components:

-   **`scan_summary`**: Contains metadata about the scan, including the target URL, start/end times, total duration, scanners run, technologies detected, and total counts of discovered URLs and vulnerabilities.
-   **`discovered_endpoints`**: A list of all unique URLs and their parameters found by the crawler. This provides a complete overview of the application's attack surface. This section is primarily populated when running in crawling-only mode (`-s none`).
-   **`vulnerabilities`**: An array of all unique, confirmed vulnerabilities. Each vulnerability object contains detailed information such as its type, URL, parameter, payload, severity, and remediation advice.

This machine-readable format is ideal for integration with CI/CD pipelines, vulnerability management systems, or custom security dashboards.

#### Important Notes on Authentication:
- **`scan_idor`:** If the `idor` scanner is enabled, ensure the `scan_idor` field is populated with the numeric ID of the authenticated user session. This is crucial for IDOR scan accuracy.
  ```yaml
  authentication:
    enabled: true
    cookie: "session=..."
    scan_idor: 123 # The authenticated user's ID
  ```
- **Combination:** If multiple static authentication methods (e.g., `cookie` and `headers`) are configured, DursGo will attempt to send **both**. It is generally recommended to specify only one method.

## Available Scanners

DursGo provides a variety of scanner modules. Scans can be run with one or more scanners using the `-s` flag (comma-separated), or with `-s all` to run all relevant scanners.

```bash
- `none` - A special option to perform crawling only, without vulnerability scanning.
- `blindssrf` - Detects Blind SSRF vulnerabilities (requires `-oast` flag).
- `cmdinjection` - Detects Command Injection vulnerabilities ( OAST - requires `-oast` flag).
- `domxss` - Detects DOM-Based XSS vulnerabilities (requires `--render-js` flag).
- `bola` - Detects Broken Object Level Authorization (BOLA) vulnerabilities.
- `cors` - Detects Cross-Origin Resource Sharing (CORS) misconfigurations.
- `csrf` - Detects Cross-Site Request Forgery (CSRF) vulnerabilities.
- `exposed` - Detects exposed sensitive files, directories, and directory listings.
- `fileupload` - Detects Unrestricted File Upload vulnerabilities.
- `graphql` - Detects vulnerabilities in GraphQL APIs (e.g., introspection, injection).
- `idor` - Detects Insecure Direct Object Reference (IDOR) vulnerabilities.
- `lfi` - Detects Local File Inclusion (LFI) vulnerabilities.
- `massassignment` - Detects Mass Assignment vulnerabilities.
- `openredirect` - Detects Open Redirect vulnerabilities.
- `securityheaders` - Detects missing or misconfigured HTTP security headers.
- `sqli` - Detects SQL Injection vulnerabilities.
- `ssrf` - Detects in-band Server-Side Request Forgery (SSRF) vulnerabilities.
- `ssti` - Detects Server-Side Template Injection (SSTI) vulnerabilities.
- `xss` - Runs both XSS scanners: `xss-reflected` and `xss-stored`.
- `xss-reflected` - Detects Reflected XSS vulnerabilities.
- `xss-stored` - Detects Stored XSS vulnerabilities.
```

## The DursGo Difference: Intelligence Under the Hood

DursGo is an advanced automated scanner that combines the speed of Go with contextual scanning logic for accurate and relevant results.

### 1. Context-Aware Scanning Logic

Each DursGo scanner module adapts its strategy to the target:
-   **XSS (Reflected & Stored):** Automatically detects the reflection context (HTML, Attribute, JavaScript, URL), applies only relevant payloads, and can handle `postMessage`-based XSS.
-   **LFI (Local File Inclusion):** Performs OS fingerprinting (Unix/Windows) and adjusts payloads accordingly.
-   **Exposed Files/Directories:** Utilizes technology fingerprinting results (e.g., WordPress, Laravel, Git) to build a highly specific and relevant target list.
-   **GraphQL:** Executes a comprehensive, multi-phase test suite, including introspection, injection, and BOLA detection via schema analysis.
-   **Command Injection:** Employs a multi-phase strategy (output-based, time-based, OAST) with OS-aware payloads.

### 2. Robust False Positive Reduction

DursGo prioritizes reporting accuracy to minimize false positives:
-   **IDOR & BOLA:** Uses intelligent baseline comparisons (comparing responses from invalid vs. valid IDs) to ensure reported vulnerabilities are genuine.
-   **XSS:** Verifies that payloads are reflected in a non-HTML-encoded form, ensuring only executable XSS is reported.
-   **SSTI (Server-Side Template Injection):** Utilizes a highly reliable three-step differential analysis (comparing baseline, payload, and expected output responses) to confirm template evaluation.
-   **CORS & Exposed:** Intelligently suppresses or downgrades the severity of findings on public endpoints that are intentionally permissive or do not involve credentials.

### 3. Precise Finding Deduplication

DursGo ensures concise and interpretable reports through finding deduplication:
-   Uses `normalizePathForDeduplication` logic to group identical vulnerabilities found on functionally equivalent but different URLs (e.g., `/product/1` and `/product/2` are reported as `/product/{ID}`).

### 4. Comprehensive & Modern Coverage

DursGo covers a wide range of common vulnerabilities with a focus on modern threats:
-   **OWASP Top 10:** Covers most critical vulnerabilities, including SQLi, XSS, LFI, SSRF, IDOR, and Mass Assignment.
-   **Modern APIs:** Features dedicated scanners for GraphQL, BOLA (Broken Object Level Authorization), and Mass Assignment, which are highly relevant for API-driven applications.

### 5. OAST & KEV Integration

-   **OAST (Out-of-Band Application Security Testing):** Built-in support for detecting blind vulnerabilities (like Blind SSRF and Blind Command Injection) via external interactions.
-   **KEV Data Enrichment:** Capable of integrating CISA Known Exploited Vulnerabilities (KEV) data directly into reports, facilitating the prioritization of actively exploited vulnerabilities.



## KEV (Known Exploited Vulnerabilities) Updates

DursGo can integrate KEV data from CISA to check for known exploited vulnerabilities:

```bash
./dursgo -update-kev
```

## Development Roadmap

This document outlines the current feature status and future development plans for the DursGo security scanner.

### 1. IDOR (Insecure Direct Object Reference) Scanner

#### Current Status

The IDOR scanner currently has an intelligent and reliable implementation for **URL path-based IDOR**.

- **Strengths:**
  - **Baseline Comparison Logic:** Uses a request to an invalid ID (e.g., 999999) to establish an "error baseline". A vulnerability is only reported if a request to another ID (e.g., 2) is successful **AND** differs from this baseline, making it highly effective at reducing false positives.
  - **Authentication Context:** Requires `scan_idor` in `config.yaml` to ensure scans are performed within a valid user session.
  - **Numeric ID Detection:** Automatically detects and tests any numeric segment within a URL path (e.g., `/users/123/orders`).

- **Limitations:**
  - **Path-Based Only:** Cannot yet test for IDOR in URL parameters (e.g., `?user_id=123`).
  - **Numeric IDs Only:** Cannot yet test for non-numeric IDs like UUIDs (`a1b2-c3d4-e5f6`).

#### Next Steps

##### a. Implement Parameter-Based IDOR Scanning
This is the top priority for the IDOR scanner.
- **Objective:** Enable the currently stubbed `testParamsForIDOR` function.
- **Logic:**
  1. Use the `CommonIDParameterNames` list from `idor_definitions.go` to identify relevant parameters (e.g., `user_id`, `message_id`, `product_id`).
  2. Implement the same baseline comparison logic as the path-based scanner for high accuracy.
  3. Test parameters in both GET (query string) and POST (form body) requests.

##### b. Support for Non-Numeric IDs (UUIDs & GUIDs)
- **Objective:** Expand ID detection capabilities to include non-numeric formats.
- **Logic:**
  1. Update detection logic in both path and parameter scanners to recognize UUID/GUID patterns (e.g., `[a-f0-9]{8}-[a-f0-9]{4}-...`).
  2. Devise a mechanism to generate or guess other valid non-numeric IDs for testing, as simple enumeration (like 1, 2, 3) will not work. This may require additional configuration.

### 2. General Roadmap for DursGo

The following are potential areas for future development to make DursGo a more comprehensive and leading-edge scanner.

#### a. API Scanning Enhancements
- **OpenAPI/Swagger Support:** Implement the ability to parse OpenAPI (v2/v3) and Swagger specifications. This would allow DursGo to automatically discover all API endpoints, parameters, and expected data types, enabling much more comprehensive and targeted API security testing beyond what the crawler can find.

#### b. Enhancements to Existing Scanner Modules

- **SQLi Scanner:**
  - Add more payloads for different database types (e.g., Oracle, SQLite).
  - Develop detection for out-of-band SQLi (using OAST).
- **XSS Scanner:**
  - Improve DOM XSS detection with deeper analysis that does not always require a headless browser.
  - Add detection for XSS in more complex contexts, such as inside JavaScript attributes (`onmouseover`, etc.).

#### c. New Scanner Modules

- **XXE (XML External Entity):** Add the capability to detect XML external entity processing vulnerabilities.
- **Deserialization:** Create a scanner to look for insecure deserialization vulnerabilities in popular platforms (e.g., Java, PHP, Python).
- **Prototype Pollution:** A dedicated scanner for Node.js applications to detect prototype pollution vulnerabilities.
- **Secret Scanning:** Add a module that can search for hardcoded secrets (API keys, passwords) within JavaScript files or JSON responses.

#### d. Reporting & Output Improvements

- **New Report Formats:** Add options to export results in an interactive HTML format or CSV for easier data analysis.
- **Vulnerability Evidence:** Include more detailed response snippets in reports to facilitate manual validation.

#### e. Configuration and Flexibility Enhancements

- **Scope & Exclusions:** Add options in `config.yaml` to exclude specific paths or parameters from scanning (e.g., logout buttons, password change forms).
- **Throttling & Rate Limiting:** More granular control over request delays to avoid being blocked by WAF/IPS.

#### f. Integration and Automation

- **Baseline Scans:** Add a feature to run an initial scan and then only report new vulnerabilities on subsequent scans, which is highly useful for CI/CD integration.
- **API Documentation:** If DursGo is developed as a service, provide API documentation for integration with other tools.
- **Web Dashboard:** Develop a web-based dashboard interface that allows users to run DursGo scans, view and manage results visually, and leverage an integrated LLM AI for advanced risk analysis and remediation recommendations.

## Contributing

Contributions are welcome! Please create an issue or pull request to report bugs or add new features.

## License

Licensed under the [MIT License](LICENSE).

## Disclaimer

This tool is for legitimate security testing purposes with permission only. Use for illegal or malicious purposes is not permitted. The user is solely responsible for their use of this tool.

---

Developed with ❤️ for the Cyber Security Community
