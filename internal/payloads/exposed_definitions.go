package payloads

// ExposedGenericPaths is a list of common files/directories that are always checked.
var ExposedGenericPaths = []string{
	// Common Directories
	"admin/", "backup/", "test/", "old/", "dev/", "uploads/", "logs/", "log/", "tmp/", "temp/",
	".git/", ".svn/", ".ssh/", "includes/", "cgi-bin/", "vendor/", "node_modules/", "dist/", "build/",
	"config/", "conf/", "sql/", "database/", "db/", "secret/", "private/", "_private/", "assets/", "static/", "archive/", "data/",
	".aws/", ".kube/", "install/",

	// Common & Sensitive Files
	".env", ".env.local", ".env.dev", ".env.prod", ".env.example",
	"phpinfo.php",
	"error_log", "access.log", "debug.log", "app.log",
	"credentials", "credentials.txt", "secrets.txt",
	"db.sql", "database.sql", "dump.sql",
	"id_rsa", "id_rsa.pub",
	".ssh/authorized_keys", ".ssh/known_hosts",
	"robots.txt",
	"sitemap.xml",
	"README.md", "CHANGELOG.txt", "LICENSE",
	".bash_history", ".zsh_history", ".bashrc", ".zshrc",
	".npmrc", ".netrc", ".git-credentials",
	"config.json", "config.yml", "config.yaml", "secrets.json", "secrets.yml",
}

// TechSpecificPaths is a map that associates technologies with their sensitive files/directories.
var TechSpecificPaths = map[string][]string{
	"wordpress": {
		"/wp-config.php", "/wp-config.php.bak", "/wp-content/debug.log", "/wp-admin/install.php",
		"/license.txt", "/readme.html",
	},
	"laravel": {
		"/storage/logs/laravel.log", "/artisan",
	},
	"django": {
		"/settings.py", "/local_settings.py",
	},
	"flask": {
		"/config.py", "/instance/config.py",
	},
	"php": {
		"/config.php", "/config.inc.php", "/composer.lock", "/composer.json", "/php.ini", "/phpunit.xml",
	},
	"apache": {
		"/.htaccess", "/.htpasswd",
	},
	"nginx": {
		"/nginx.conf",
	},
	"rails": { // Ruby on Rails
		"/config/database.yml", "/config/secrets.yml", "/Gemfile", "/Gemfile.lock",
	},
	"docker": {
		"/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile", "/.dockerenv",
	},
	"asp.net": {
		"/web.config", "/web.config.bak", "/appsettings.json", "/appsettings.Development.json",
	},
	"java": {
		"/WEB-INF/web.xml", "/pom.xml", "/build.gradle", "/application.properties", "/application.yml", "/application.yaml",
	},
	"node": {
		"/package.json", "/package-lock.json", "/yarn.lock",
	},
	"git": {
		"/.gitignore", "/.git/config", "/.git/HEAD", "/.git/index",
	},
	"aws": {
		"/.aws/credentials", "/.aws/config",
	},
	"gcp": {
		"/key.json", "/gcloud/credentials.db",
	},
	"serverless": {
		"/serverless.yml",
	},
}

// DirListingKeywords are keywords to detect directory listing.
var DirListingKeywords = []string{
	"<title>Index of /", "<h1>Index of /", "[To Parent Directory]", "Parent Directory",
	"folder.gif", "file.gif", "Last modified", "Size", "Description",
	"Apache.*Index of", "nginx.*Index of", "[dir]",
}

// ExposedFileContentChecks maps a filename to keywords expected within its content to reduce false positives.
var ExposedFileContentChecks = map[string][]string{
	".env":               {"DB_PASSWORD", "APP_KEY", "AWS_SECRET_ACCESS_KEY", "API_KEY", "SECRET_KEY", "DATABASE_URL"},
	"id_rsa":             {"BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"},
	"credentials.txt":    {"password", "secret", "token", "passwd", "credential"},
	"config.php":         {"DB_PASSWORD", "define('DB_PASSWORD'", "dbpasswd"},
	"config.inc.php":     {"$cfg['Servers'][$i]['password']", "dbpass"},
	"error.log":          {"PHP Fatal error", "Exception:", "Traceback (most recent call last):", "Error:"},
	"access.log":         {"GET /", "POST /"},
	"phpinfo.php":        {"PHP Version", "Configuration File (php.ini) Path", "allow_url_fopen"},
	"db.sql":             {"CREATE TABLE", "INSERT INTO", "DEFAULT CHARSET", "ENGINE=InnoDB", "REFERENCES"},
	".bash_history":      {"sudo", "psql", "mysql", "ssh", "export", "gcloud", "aws"},
	".htpasswd":          {":"},
	"wp-config.php":      {"DB_PASSWORD", "AUTH_KEY", "SECURE_AUTH_KEY"},
	"appsettings.json":   {"ConnectionStrings", "ApiKey"},
	"web.config":         {"connectionString", "<appSettings>"},
	"database.yml":       {"adapter:", "password:"},
	"secrets.yml":        {"secret_key_base:"},
	"settings.py":        {"SECRET_KEY", "DATABASES"},
	"package.json":       {`"private":`, `"dependencies"`, `"scripts"`},
	"docker-compose.yml": {"environment:", "AWS_ACCESS_KEY_ID"},
	".netrc":             {"machine", "login", "password"},
	".git-credentials":   {"https://", "@"},
}
