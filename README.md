# DursGo - The Go-Powered Web Application Scanner

<p align="center">
  <img src="logo/dursgo-logo.png" width="750">
</p>

<div align="center">

# 📦 Package Attributes

<p>
    <a href="https://golang.org/doc/install"><img src="https://img.shields.io/badge/go-1.23%2B-blue.svg" alt="Go Version"></a>
    <a href="https://github.com/roomkangali/dursgo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
</p>
<p>
    <img src="https://img.shields.io/badge/Linux-Supported-green.svg" alt="Linux Supported">
    <img src="https://img.shields.io/badge/macOS-Supported-green.svg" alt="macOS Supported">
    <img src="https://img.shields.io/badge/Windows-Supported-green.svg" alt="Windows Supported">
</p>

</div>

# DursGo - Web Application Security Scanner

DursGo is a web application security scanner designed for penetration testing and automated security audits. Built with Go, DursGo offers high-performance and flexible security scanning capabilities.

## 📋 Table of Contents

- [✨ Features](#features)
- [⚙️ Scan Workflow](#scan-workflow)
- [🔩 Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
  - [Initial Configuration](#initial-configuration)
  - [Additional Prerequisites for Specific Scanners](#additional-prerequisites-for-specific-scanners)
- [🚀 Quick Start](#quick-start)
  - [Basic Scan](#basic-scan)
  - [Scan with OAST (Out-of-Band)](#scan-with-oast-out-of-band)
  - [Scan for DOM XSS using `-render-js`](#scan-for-dom-xss-using--render-js)
- [💻 Command-Line Options](#command-line-options)
- [🛡️ Available Scanners](#available-scanners)
  - [Using a Configuration File](#using-a-configuration-file)
- [📝 Configuration File (`config.yaml`)](#configuration-file-configyaml)
  - [General Settings](#general-settings)
  - [Output Settings](#output-settings)
  - [Authentication Configuration](#authentication-configuration)
- [📊 JSON Report Structure](#json-report-structure)
- [💡 The DursGo Difference: Intelligence Under the Hood](#the-dursgo-difference-intelligence-under-the-hood)
- [📈 KEV (Known Exploited Vulnerabilities) Updates](#kev-known-exploited-vulnerabilities-updates)
- [🗺️ Development Roadmap](#development-roadmap)
  - [1. IDOR (Insecure Direct Object Reference) Scanner](#1-idor-insecure-direct-object-reference-scanner)
  - [2. General Roadmap for DursGo](#2-general-roadmap-for-dursgo)
- [❓ FAQ](#faq)
- [🙏 Contributing](#contributing)
- [📄 License](#license)
- [⚠️ Disclaimer](#disclaimer)

## Features

- **Intelligent, Context-Aware Scanning:** Detects a wide range of vulnerabilities using context-aware logic for high accuracy.
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

**A Note on Scan Duration:** The thoroughness of the crawler, especially the "Proactive Parameter Discovery" feature, has a significant multiplicative effect on the total scan duration, particularly when using `-s all`. The total number of tests is a product of `(URLs) x (Parameters) x (Payloads) x (Scanners)`. On large sites, this can result in a very high number of HTTP requests, leading to long scan times. This is a direct trade-off between deep, comprehensive coverage and speed.

## Installation

### Prerequisites

- **Go Language:** Requires Go version 1.23 or newer.
  - The installed Go version can be checked with: `go version`
  - To install Go, visit: [https://golang.org/doc/install](https://golang.org/doc/install)

### Installation Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/roomkangali/dursgo.git
    cd dursgo
    ```

2.  **Build the Application:**
    Compile the source code into an executable binary. This command will create a `dursgo` file (or `dursgo.exe` on Windows) in the current directory.
    ```bash
    go build -o dursgo ./cmd/dursgo
    ```

3.  **(Optional) Move the Binary to the System PATH:**
    To allow `dursgo` to be executed from any directory, the compiled binary can be moved to a location within the system's PATH.
    ```bash
    # For Linux/macOS
    sudo cp dursgo /usr/local/bin/
    ```

### Initial Configuration

-   **`config.yaml`:** Dursgo automatically looks for a `config.yaml` file in the directory from which it is executed. This file should be customized for the target and specific scanning needs.
-   **Authentication:** If the target application requires authentication, the `authentication` section in `config.yaml` must be configured.

### Additional Prerequisites for Specific Scanners

-   **For JavaScript Rendering (`-render-js`) and the DOM XSS Scanner (`-s domxss`):**
    -   **Google Chrome or Chromium:** These features require a headless browser to execute JavaScript. Either Google Chrome or Chromium must be installed on the system. The scanner will automatically detect the installed browser.
    -   **Installation Examples:**
        -   **Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install -y chromium-browser`
        -   **CentOS/RHEL:** `sudo yum install -y chromium`
        -   **macOS (using Homebrew):** `brew install --cask google-chrome`
-   **For OAST-Based Scanners (`-s blindssrf`, `-s cmdinjection` with OAST):**
    -   **OAST Service (Interactsh):** These scanners rely on an external OAST service. Dursgo will automatically use the default public Interactsh server when the `--oast` flag is used.

## Quick Start

### Basic Scan
```bash
./dursgo -u http://example.com -c 10 -r 3 -s xss,sqli
```

### Scan with OAST (Out-of-Band)
To run a scanner that relies on OAST, use the `--oast` flag.

**Important Note:** For accurate and reliable OAST correlation, it is strongly recommended to run **only one OAST-dependent scanner at a time**.

```bash
# Correct: Scan for Blind SSRF
./dursgo -u http://example.com -c 10 -r 3 -s blindssrf --oast

# Correct: Scan for Blind Command Injection
./dursgo -u http://example.com -c 10 -r 3 -s cmdinjection --oast

# Avoid: Running multiple OAST scanners together may lead to correlation issues.
# ./dursgo -u http://example.com -s blindssrf,cmdinjection --oast
```

### Scan for DOM XSS using `-render-js`
To detect DOM-based XSS, JavaScript rendering must be enabled. This requires a headless browser (Chrome/Chromium) to be installed.

```bash
# Scan for DOM XSS on a Single-Page Application (SPA)
./dursgo -u http://spa.example.com -c 10 -r 3 -s domxss -render-js
```

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

## Available Scanners

DursGo provides a variety of scanner modules. Scans can be run with one or more scanners using the `-s` flag (comma-separated), or with `-s all` to run all relevant scanners.

```bash
- `none` - A special option to perform crawling only, without vulnerability scanning.
- `blindssrf` - Detects Blind SSRF vulnerabilities (requires `-oast` flag).
- `cmdinjection` - Detects Command Injection vulnerabilities (supports OAST - requires `-oast` flag).
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
- `xss` - **Runs both XSS scanners:** `xss-reflected` and `xss-stored`.
- `xss-reflected` - Detects Reflected XSS vulnerabilities.
- `xss-stored` - Detects Stored XSS vulnerabilities.
```

### Using a Configuration File
DursGo automatically loads `config.yaml` from the current working directory if no flags are specified. The configuration in `config.yaml` serves as the default settings.

Command-line flags (e.g., `-u http://new-target.com`) will **override** the corresponding values in `config.yaml` for the current scan execution.

## Configuration File (`config.yaml`)

DursGo supports configuration via a YAML file for more complex settings, particularly for authentication. The file is organized into several sections:

### General Settings
This section contains the core parameters for the scan.
- `target`: The URL to be scanned.
- `concurrency`: The number of concurrent threads to use for the scan.
- `max_depth`: The maximum depth for the crawler.
- `scanners_to_run`: A comma-separated string of the scanners to be executed (e.g., "xss,sqli").
- `oast`: A boolean (`true`/`false`) to enable or disable Out-of-Band Application Security Testing (OAST).
- `render_js`: A boolean (`true`/`false`) to enable or disable JavaScript rendering in a headless browser.
- `user_agent`: The User-Agent string to be used for all HTTP requests.

### Output Settings
This section controls how the scan results are reported.
- `verbose`: A boolean (`true`/`false`) to enable or disable verbose logging.
- `format`: The output format for the report (e.g., "json").
- `output_file`: The name of the file where the report will be saved (e.g., "report-scan.json").

### Authentication Configuration

This section is used to configure DursGo to scan applications that require login. Only one authentication method can be active at a time.
- `enabled`: A boolean (`true`/`false`) to enable or disable authentication for the scan.
- `scan_idor`: A numeric user ID used by the IDOR scanner to avoid false positives.

### Important Notes on Authentication:
- **`scan_idor`:** If the `idor` scanner is enabled, ensure the `scan_idor` field is populated with the numeric ID of the authenticated user session. This is crucial for IDOR scan accuracy.
  ```yaml
  authentication:
    enabled: true
    cookie: "session=..."
    scan_idor: 123 # The authenticated user's ID
  ```
- **Combination:** If multiple static authentication methods (e.g., `cookie` and `headers`) are configured, DursGo will attempt to send **both**. It is generally recommended to specify only one method.

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

#### 4. Auth-Token Based Authentication (Static)
Use this for `X-Auth-Token` or other custom token headers.

```yaml
authentication:
  enabled: true
  type: "header"
  header_name: "X-Auth-Token"
  value: "eyJhbGciOiJIUzI1Ni...[token]"
```

For more detailed information on configuring authentication, see the [Authentication Configuration Guide](README-CONFIG.md).

## JSON Report Structure

When using the `--output-json` flag, DursGo generates a structured JSON file with the following main components:

-   **`scan_summary`**: Contains metadata about the scan, including the target URL, start/end times, total duration, scanners run, technologies detected, and total counts of discovered URLs and vulnerabilities.
-   **`discovered_endpoints`**: A list of all unique URLs and their parameters found by the crawler. This provides a complete overview of the application's attack surface. This section is primarily populated when running in crawling-only mode (`-s none`).
-   **`vulnerabilities`**: An array of all unique, confirmed vulnerabilities. Each vulnerability object contains detailed information such as its type, URL, parameter, payload, severity, and remediation advice.

This machine-readable format is ideal for integration with CI/CD pipelines, vulnerability management systems, or custom security dashboards.

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

- **Continuous Improvement:** All existing scanner modules will be continuously updated with the latest detection logic and payloads to keep pace with evolving security threats and research.
- **IDOR Scanner:**
  - Implement testing for IDOR in URL parameters (e.g., `?user_id=123`).
  - Add support for non-numeric IDs, such as UUIDs.
- **SQLi Scanner:**
  - Add more payloads for different database types (e.g., Oracle, SQLite).
  - Develop detection for out-of-band SQLi (using OAST).
- **XSS Scanner:**
  - Improve DOM XSS detection with deeper analysis that does not always require a headless browser.
  - Add detection for XSS in more complex contexts, such as inside JavaScript attributes (`onmouseover`, etc.).

#### c. New Scanner Modules

- **JWT Attacks:** A module to test for common JSON Web Token vulnerabilities, such as weak secrets, algorithm confusion (`none` algorithm), and signature stripping.
- **OAuth Authentication:** A scanner to detect misconfigurations in OAuth 2.0 flows, such as improper handling of redirect URIs.
- **HTTP Request Smuggling:** Add the capability to detect both CL.TE and TE.CL HTTP request smuggling vulnerabilities.
- **HTTP Host Header Attacks:** A module to test for vulnerabilities related to the HTTP Host header, such as password reset poisoning and cache poisoning.
- **Subdomain Scanner:** A module to discover and validate active subdomains for a given target, expanding the potential attack surface.
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

## FAQ

<details>
<summary>Why is the scan taking so long, especially with <code>-s all</code>?</summary>

The thoroughness of the crawler, especially the "Proactive Parameter Discovery" feature, has a significant multiplicative effect on the total scan duration. The total number of tests is a product of `(URLs) x (Parameters) x (Payloads) x (Scanners)`. On large sites, this can result in a very high number of HTTP requests, leading to long scan times. This is a direct trade-off between deep, comprehensive coverage and speed. For faster scans, it is recommended to target specific scanners (e.g., `-s xss,sqli`) rather than using `-s all`.
</details>

<details>
<summary>Why did the scanner not find a vulnerability on the login page?</summary>

By default, some paths like `/login` may be ignored by certain scanners to prevent accidentally logging out an authenticated session during a scan. If a login form is the specific target for a vulnerability (like an SQL Injection bypass), ensure that the scanner's configuration does not blacklist the `/login` path. This behavior has been refined, but older versions may have more aggressive blacklisting.
</details>

<details>
<summary>What do I need to install to use the <code>-render-js</code> or <code>-s domxss</code> flags?</summary>

These features require a headless browser to execute JavaScript. Either Google Chrome or Chromium must be installed on the system. The scanner will automatically detect the installed browser.

**Installation Examples:**
- **Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install -y chromium-browser`
- **CentOS/RHEL:** `sudo yum install -y chromium`
- **macOS (using Homebrew):** `brew install --cask google-chrome`
</details>

<details>
<summary>How does the scanner handle false positives for vulnerabilities like IDOR or SQLi Auth Bypass?</summary>

The scanner uses a baseline comparison logic to reduce false positives. For example, to test for an IDOR, it first requests an invalid object ID (e.g., `999999`) to establish an "error baseline". A vulnerability is only reported if a request to a different, valid-looking ID (e.g., `1`) is successful AND the response is different from the error baseline. A similar baseline comparison is used for the SQLi Auth Bypass scanner to differentiate between a real bypass and a normal failed login page.
</details>

## Contributing

Contributions are welcome! Please create an issue or pull request to report bugs or add new features.

## License

Licensed under the [MIT License](LICENSE).

## Disclaimer

This tool is for legitimate security testing purposes with permission only. Use for illegal or malicious purposes is not permitted. The user is solely responsible for their use of this tool.

---