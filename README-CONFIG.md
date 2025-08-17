# DursGo Authentication Configuration Guide

DursGo supports multiple authentication methods to enable scanning of web applications requiring login. This configuration is managed in the `config.yaml` file under the `authentication` section.

There are two main categories of authentication methods: **Dynamic Login** (where DursGo performs the login process) and **Static Authentication** (where a pre-existing session token or cookie is provided).

---

## 1. Form-Based Authentication (Dynamic Login)

This method is used for DursGo to automatically fill and submit a login form to obtain a session. It is the most suitable approach for traditional web applications that use cookie-based sessions post-login.

**Use Case:** When credentials (username and password) are available and the login process should be handled automatically by DursGo.

### Configuration Example:
```yaml
authentication:
  # Enable authentication functionality
  enabled: true

  # The URL endpoint where the login form is submitted
  login_url: "http://example.com/login.php"
  
  # HTTP method for login (usually POST)
  login_method: "POST"
  
  # Credential data to be sent in application/x-www-form-urlencoded format
  login_data: "username=admin&password=password123"
  
  # (Highly recommended) A keyword to verify successful login.
  # DursGo will search for this text in the response page after login for confirmation.
  login_check_keyword: "Welcome, admin"
```

---

## 2. Cookie-Based Authentication (Static)

This method is used when a valid session cookie is already available. The cookie can be obtained by logging in manually via a browser and copying the cookie value from the developer tools.

**Use Case:** A quick method for scanning as an authenticated user without configuring the entire login process. Useful for rapid scans or when the login process is complex.

### Configuration Example:
```yaml
authentication:
  # Enable authentication functionality
  enabled: true

  # Paste the entire cookie value here. Separate multiple cookies with a semicolon.
  cookie: "session=a1b2c3d4e5f6; user_id=123; role=admin"
```

---

## 3. Header-Based Authentication (Static)

This method is most common for APIs or modern web applications protected by tokens, such as JWT (JSON Web Token) or custom API Keys. DursGo will automatically add these headers to every request sent during the scan.

**Use Case:** Interacting with APIs or applications that require an `Authorization` token, `X-API-Key`, or other custom headers for authentication.

### Configuration Example:
```yaml
authentication:
  # Enable authentication functionality
  enabled: true

  # Define custom headers within the 'headers' section
  headers:
    # Example for a Bearer Token (JWT)
    Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    # Other headers can also be added if required, e.g., an API Key
    X-API-Key: "secret-api-key-12345"
```

---

## 4. Auth-Token Based Authentication (Static)

This method is a specific variant of header-based authentication, designed explicitly for tokens sent via headers like `X-Auth-Token`. It provides a more explicit way to configure such tokens.

**Use Case:** When the target application uses an `X-Auth-Token` header or a similar non-standard header for session authentication.

### Configuration Example:
```yaml
authentication:
  # Enable authentication functionality
  enabled: true

  # Type: "header" as the token will be sent via an HTTP header.
  type: "header"
  
  # The name of the header to be used.
  header_name: "X-Auth-Token"
  
  # Value: Paste the static token obtained.
  value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1cnNnbyIsInVzZXJfaWQiOjk5LCJpYXQiOjE1MTYyMzkwMjJ9.D-a2iYv03DEbOFpS42d_F5M9h3GZ_s5k7xo5G2jF8_8"
```

---

### Important Notes:
- Only **one** authentication method should be used at a time to avoid unexpected behavior.
- Ensure `enabled: true` is set under `authentication:` to activate any of the above methods. If set to `false`, all authentication settings will be ignored.
- **scan_idor:** If the `idor` scanner is enabled, ensure the `scan_idor` field is populated with the numeric ID of the user whose session is being used. This is crucial for the IDOR scanner to work accurately.

### Priority and Combination
If multiple static authentication methods are configured simultaneously (e.g., both `cookie` and `headers` are filled), DursGo will attempt to send **both** in every request.

**Scenario Example:**
```yaml
authentication:
  enabled: true
  cookie: "session=LDg7CesrDojY7hAiTPBVHDo847L41ZWa"
  headers:
    X-Auth-Token: "eyJhbGciOiJIUzI1Ni...[token]"
```
In this case, every request from DursGo will include **both** the `session` cookie and the `X-Auth-Token` header. This behavior might be useful in rare cases, but it is generally recommended to specify only one method for clarity and predictability.
