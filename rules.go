package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var builtinRules = buildBuiltinRules()

func buildBuiltinRules() []rule {
	var out []rule
	add := func(r rule) { out = append(out, r) }
	addPath := func(id, path, name, sev, category, profile string, statuses []int, contains []string, tags ...string) {
		add(rule{ID: id, Path: path, Name: name, Severity: sev, Category: category, Confidence: "high", Statuses: statuses, Contains: contains, Profile: profile, Tags: tags})
	}

	// Version-control metadata.
	addPath("git-head", "/.git/HEAD", "exposed Git repository", "high", "vcs", "quick", []int{200}, []string{"ref:", "refs/heads/"}, "htb", "exposure")
	addPath("git-config", "/.git/config", "exposed Git configuration", "high", "vcs", "default", []int{200}, []string{"[core]", "repositoryformatversion"}, "htb", "exposure")
	addPath("git-index", "/.git/index", "exposed Git index", "high", "vcs", "full", []int{200}, nil, "htb", "exposure")
	addPath("git-logs-head", "/.git/logs/HEAD", "exposed Git history", "high", "vcs", "full", []int{200}, nil, "htb", "exposure")
	addPath("svn-entries", "/.svn/entries", "exposed Subversion metadata", "high", "vcs", "default", []int{200}, nil, "htb", "exposure")
	addPath("svn-wcdb", "/.svn/wc.db", "exposed Subversion working-copy database", "high", "vcs", "full", []int{200}, nil, "htb", "exposure")
	addPath("hg-requires", "/.hg/requires", "exposed Mercurial metadata", "high", "vcs", "default", []int{200}, nil, "htb", "exposure")
	addPath("bzr-config", "/.bzr/branch/branch.conf", "exposed Bazaar metadata", "high", "vcs", "full", []int{200}, nil, "htb", "exposure")

	// Secrets and configuration.
	configs := []struct{ id, path, name, sev, profile string }{
		{"env", "/.env", "exposed environment file", "high", "quick"},
		{"env-local", "/.env.local", "exposed local environment file", "high", "default"},
		{"env-prod", "/.env.production", "exposed production environment file", "high", "default"},
		{"env-dev", "/.env.development", "exposed development environment file", "high", "full"},
		{"env-backup", "/.env.bak", "environment-file backup exposed", "high", "full"},
		{"npmrc", "/.npmrc", "npm configuration exposed", "medium", "full"},
		{"pypirc", "/.pypirc", "PyPI configuration exposed", "medium", "full"},
		{"web-config", "/web.config", "web.config exposed", "medium", "full"},
		{"appsettings", "/appsettings.json", "ASP.NET application settings exposed", "high", "default"},
		{"appsettings-prod", "/appsettings.Production.json", "ASP.NET production settings exposed", "high", "full"},
		{"application-properties", "/application.properties", "application properties exposed", "high", "full"},
		{"application-yml", "/application.yml", "application YAML exposed", "high", "full"},
		{"application-yaml", "/application.yaml", "application YAML exposed", "high", "full"},
		{"config-yml", "/config.yml", "YAML configuration exposed", "medium", "full"},
		{"config-json", "/config.json", "JSON configuration exposed", "medium", "full"},
		{"settings-py", "/settings.py", "Django settings file exposed", "high", "full"},
		{"local-settings", "/local.settings.json", "local settings exposed", "high", "full"},
	}
	for _, x := range configs {
		addPath(x.id, x.path, x.name, x.sev, "config", x.profile, []int{200}, nil, "htb", "exposure")
	}
	addPath("aws-credentials", "/.aws/credentials", "AWS credentials file exposed", "critical", "secrets", "full", []int{200}, []string{"aws_access_key_id", "aws_secret_access_key"}, "htb", "exposure")
	addPath("kube-config", "/.kube/config", "Kubernetes client config exposed", "critical", "secrets", "full", []int{200}, []string{"apiVersion", "clusters:"}, "htb", "exposure")
	addPath("docker-config", "/.docker/config.json", "Docker client configuration exposed", "high", "secrets", "full", []int{200}, nil, "htb", "exposure")
	addPath("terraform-state", "/terraform.tfstate", "Terraform state exposed", "critical", "secrets", "full", []int{200}, []string{"terraform_version", "resources"}, "htb", "exposure")
	addPath("id-rsa", "/id_rsa", "private key exposed", "critical", "secrets", "full", []int{200}, []string{"PRIVATE KEY"}, "htb", "exposure")

	// Backups, dumps and source archives.
	archives := []struct{ id, path, name, profile string }{
		{"backup-zip", "/backup.zip", "public backup archive", "quick"},
		{"site-zip", "/site.zip", "public site archive", "default"},
		{"www-zip", "/www.zip", "public webroot archive", "full"},
		{"source-zip", "/source.zip", "public source archive", "full"},
		{"src-zip", "/src.zip", "public source archive", "full"},
		{"app-zip", "/app.zip", "public application archive", "full"},
		{"backup-targz", "/backup.tar.gz", "public backup archive", "quick"},
		{"site-targz", "/site.tar.gz", "public site archive", "full"},
		{"backup-tgz", "/backup.tgz", "public backup archive", "full"},
		{"backup-tar", "/backup.tar", "public backup archive", "full"},
	}
	for _, x := range archives {
		addPath(x.id, x.path, x.name, "high", "backup", x.profile, []int{200, 206}, nil, "htb", "exposure")
	}
	for _, p := range []string{"db.sql", "database.sql", "dump.sql", "backup.sql", "prod.sql", "production.sql", "mysql.sql"} {
		id := strings.TrimSuffix(strings.ReplaceAll(p, ".", "-"), "-")
		addPath("dump-"+id, "/"+p, "database dump exposed", "critical", "backup", "default", []int{200}, nil, "htb", "exposure")
	}
	for _, p := range []string{"db.sql.gz", "database.sql.gz", "dump.sql.gz", "backup.sql.gz"} {
		id := strings.ReplaceAll(p, ".", "-")
		addPath("dump-"+id, "/"+p, "compressed database dump exposed", "critical", "backup", "full", []int{200, 206}, nil, "htb", "exposure")
	}
	for _, p := range []string{"config.php.bak", "wp-config.php.bak", "wp-config.php~", "web.config.bak", "appsettings.json.bak", "index.php~", "index.html~"} {
		id := strings.NewReplacer(".", "-", "~", "tilde").Replace(p)
		addPath("backup-"+id, "/"+p, "backup file exposed", "high", "backup", "full", []int{200}, nil, "htb", "exposure")
	}

	// Debugging, diagnostics and monitoring.
	addPath("phpinfo", "/phpinfo.php", "phpinfo page exposed", "medium", "debug", "quick", []int{200}, []string{"PHP Version", "phpinfo()"}, "htb", "debug")
	addPath("phpinfo-info", "/info.php", "PHP information page exposed", "medium", "debug", "default", []int{200}, []string{"PHP Version", "phpinfo()"}, "htb", "debug")
	addPath("phpinfo-test", "/test.php", "PHP diagnostic page exposed", "medium", "debug", "full", []int{200}, []string{"PHP Version", "phpinfo()"}, "htb", "debug")
	addPath("server-status", "/server-status", "Apache server-status exposed", "medium", "debug", "quick", []int{200}, []string{"Apache Server Status", "Server Version"}, "htb", "debug")
	addPath("server-info", "/server-info", "Apache server-info exposed", "medium", "debug", "default", []int{200}, nil, "htb", "debug")
	addPath("pprof", "/debug/pprof/", "Go pprof index exposed", "medium", "debug", "default", []int{200}, []string{"Types of profiles", "goroutine"}, "htb", "debug")
	for _, p := range []string{"/debug/pprof/goroutine?debug=1", "/debug/pprof/heap", "/debug/pprof/cmdline"} {
		id := strings.NewReplacer("/", "-", "?", "-", "=", "-").Replace(strings.Trim(p, "/"))
		addPath("pprof-"+id, p, "Go pprof endpoint exposed", "high", "debug", "full", []int{200}, nil, "htb", "debug")
	}
	addPath("actuator", "/actuator", "Spring Boot Actuator exposed", "medium", "debug", "default", []int{200}, nil, "htb", "debug")
	for _, p := range []string{"env", "configprops", "beans", "mappings", "heapdump", "threaddump", "loggers", "prometheus"} {
		sev := "high"
		if p == "prometheus" {
			sev = "low"
		}
		addPath("actuator-"+p, "/actuator/"+p, "Spring Boot Actuator "+p+" endpoint exposed", sev, "debug", "full", []int{200}, nil, "htb", "debug")
	}
	addPath("metrics", "/metrics", "metrics endpoint exposed", "low", "monitoring", "default", []int{200}, nil, "htb", "debug")
	addPath("prometheus", "/metrics/prometheus", "Prometheus metrics exposed", "low", "monitoring", "full", []int{200}, nil, "htb", "debug")
	addPath("trace-axd", "/trace.axd", "ASP.NET trace endpoint exposed", "high", "debug", "full", []int{200}, nil, "htb", "debug")
	addPath("elmah", "/elmah.axd", "ELMAH error log exposed", "high", "debug", "full", []int{200}, nil, "htb", "debug")

	// Admin, auth and management surfaces.
	adminPaths := []struct{ id, path, name, sev, profile string }{
		{"admin", "/admin", "admin endpoint", "info", "quick"},
		{"admin-slash", "/admin/", "admin endpoint", "info", "default"},
		{"admin-login", "/admin/login", "admin login endpoint", "info", "default"},
		{"administrator", "/administrator", "administrator endpoint", "info", "default"},
		{"login", "/login", "login endpoint", "info", "quick"},
		{"signin", "/signin", "sign-in endpoint", "info", "full"},
		{"dashboard", "/dashboard", "dashboard endpoint", "info", "full"},
		{"manage", "/manage", "management endpoint", "info", "full"},
		{"manager-html", "/manager/html", "Tomcat manager endpoint", "medium", "default"},
		{"host-manager", "/host-manager/html", "Tomcat host-manager endpoint", "medium", "full"},
		{"wp-admin", "/wp-admin/", "WordPress admin endpoint", "info", "default"},
		{"wp-login", "/wp-login.php", "WordPress login endpoint", "info", "default"},
		{"phpmyadmin", "/phpmyadmin/", "phpMyAdmin endpoint", "medium", "default"},
		{"pma", "/pma/", "phpMyAdmin endpoint", "medium", "full"},
		{"grafana", "/grafana/", "Grafana endpoint", "info", "full"},
		{"jenkins", "/jenkins/", "Jenkins endpoint", "info", "full"},
		{"kibana", "/app/kibana", "Kibana endpoint", "info", "full"},
	}
	for _, x := range adminPaths {
		addPath(x.id, x.path, x.name, x.sev, "admin", x.profile, []int{200, 301, 302, 307, 308, 401, 403}, nil, "htb", "admin")
	}

	// API and documentation discovery.
	apiPaths := []struct{ id, path, name, profile string }{
		{"swagger-ui", "/swagger-ui/", "Swagger UI exposed", "default"},
		{"swagger", "/swagger/", "Swagger endpoint exposed", "full"},
		{"swagger-json", "/swagger.json", "Swagger specification exposed", "default"},
		{"api-docs", "/api-docs", "API documentation exposed", "default"},
		{"v2-api-docs", "/v2/api-docs", "Swagger v2 specification exposed", "full"},
		{"v3-api-docs", "/v3/api-docs", "OpenAPI v3 specification exposed", "default"},
		{"openapi-json", "/openapi.json", "OpenAPI specification exposed", "default"},
		{"openapi-yaml", "/openapi.yaml", "OpenAPI specification exposed", "full"},
		{"graphql", "/graphql", "GraphQL endpoint", "default"},
		{"graphiql", "/graphiql", "GraphiQL endpoint", "full"},
		{"redoc", "/redoc", "ReDoc API documentation exposed", "full"},
		{"docs", "/docs", "documentation endpoint", "full"},
		{"api-root", "/api", "API root endpoint", "full"},
		{"api-v1", "/api/v1", "API v1 endpoint", "full"},
	}
	for _, x := range apiPaths {
		statuses := []int{200, 301, 302, 307, 308, 400, 401, 403, 405}
		addPath(x.id, x.path, x.name, "low", "api", x.profile, statuses, nil, "htb", "api")
	}

	// Logs and build/dependency files.
	for _, p := range []string{"error.log", "access.log", "debug.log", "application.log", "app.log", "npm-debug.log", "yarn-error.log"} {
		id := strings.ReplaceAll(p, ".", "-")
		addPath("log-"+id, "/"+p, "log file exposed", "medium", "logs", "full", []int{200}, nil, "htb", "exposure")
	}
	addPath("laravel-log", "/storage/logs/laravel.log", "Laravel log exposed", "high", "logs", "full", []int{200}, nil, "htb", "exposure")
	buildFiles := []struct{ id, path, name, sev string }{
		{"composer-json", "/composer.json", "composer.json exposed", "low"},
		{"composer-lock", "/composer.lock", "composer.lock exposed", "low"},
		{"package-json", "/package.json", "package.json exposed", "info"},
		{"package-lock", "/package-lock.json", "package-lock.json exposed", "info"},
		{"yarn-lock", "/yarn.lock", "yarn.lock exposed", "info"},
		{"pnpm-lock", "/pnpm-lock.yaml", "pnpm lockfile exposed", "info"},
		{"requirements", "/requirements.txt", "Python requirements file exposed", "info"},
		{"pipfile", "/Pipfile", "Pipfile exposed", "info"},
		{"pipfile-lock", "/Pipfile.lock", "Pipfile.lock exposed", "info"},
		{"gemfile", "/Gemfile", "Gemfile exposed", "info"},
		{"gemfile-lock", "/Gemfile.lock", "Gemfile.lock exposed", "info"},
		{"go-mod", "/go.mod", "Go module file exposed", "info"},
		{"cargo-toml", "/Cargo.toml", "Cargo manifest exposed", "info"},
		{"pom-xml", "/pom.xml", "Maven project file exposed", "info"},
		{"gradle", "/build.gradle", "Gradle build file exposed", "info"},
		{"dockerfile", "/Dockerfile", "Dockerfile exposed", "low"},
		{"docker-compose", "/docker-compose.yml", "docker-compose file exposed", "medium"},
		{"compose-yaml", "/compose.yaml", "Compose configuration exposed", "medium"},
		{"gitlab-ci", "/.gitlab-ci.yml", "GitLab CI configuration exposed", "low"},
		{"jenkinsfile", "/Jenkinsfile", "Jenkinsfile exposed", "low"},
		{"tsconfig", "/tsconfig.json", "TypeScript configuration exposed", "info"},
		{"webpack", "/webpack.config.js", "Webpack configuration exposed", "low"},
		{"vite", "/vite.config.js", "Vite configuration exposed", "low"},
		{"app-map", "/app.js.map", "JavaScript source map exposed", "medium"},
		{"main-map", "/main.js.map", "JavaScript source map exposed", "medium"},
	}
	for _, x := range buildFiles {
		addPath(x.id, x.path, x.name, x.sev, "build", "full", []int{200}, nil, "htb", "exposure")
	}

	// Metadata and HTB-friendly discovery paths.
	addPath("robots", "/robots.txt", "robots.txt present", "info", "discovery", "quick", []int{200}, nil, "htb")
	addPath("sitemap", "/sitemap.xml", "sitemap.xml present", "info", "discovery", "default", []int{200}, nil, "htb")
	addPath("security-txt", "/.well-known/security.txt", "security.txt present", "info", "discovery", "quick", []int{200}, nil)
	addPath("crossdomain", "/crossdomain.xml", "crossdomain.xml present", "info", "discovery", "full", []int{200}, nil)
	addPath("clientaccesspolicy", "/clientaccesspolicy.xml", "clientaccesspolicy.xml present", "info", "discovery", "full", []int{200}, nil)
	addPath("ds-store", "/.DS_Store", ".DS_Store exposed", "medium", "exposure", "default", []int{200}, nil, "htb", "exposure")
	for _, p := range []string{"/backup/", "/old/", "/dev/", "/test/", "/internal/", "/private/", "/uploads/", "/files/", "/cgi-bin/"} {
		id := "interesting-" + strings.Trim(strings.ReplaceAll(p, "/", "-"), "-")
		addPath(id, p, "interesting endpoint", "info", "discovery", "full", []int{200, 301, 302, 307, 308, 401, 403}, nil, "htb")
	}

	return out
}

func loadRules(path, mode string) ([]rule, error) {
	out := make([]rule, 0, len(builtinRules))
	for _, r := range builtinRules {
		if modeAllows(mode, r) {
			n, err := normalizeRuleChecked(r)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
	}
	if path == "" {
		return out, nil
	}
	custom, err := readRuleFile(path)
	if err != nil {
		return nil, err
	}
	for _, r := range custom {
		n, err := normalizeRuleChecked(r)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func readRuleFile(path string) ([]rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func validateRulesFile(path string) error {
	rules, err := readRuleFile(path)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for i, r := range rules {
		n, err := normalizeRuleChecked(r)
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		if seen[n.ID] {
			return fmt.Errorf("duplicate rule id %q", n.ID)
		}
		seen[n.ID] = true
	}
	return nil
}

func normalizeRule(r rule) rule {
	n, _ := normalizeRuleChecked(r)
	return n
}

func normalizeRuleChecked(r rule) (rule, error) {
	if r.Path == "" || r.Name == "" {
		return r, errors.New("rules require path and name")
	}
	if len(r.Statuses) == 0 {
		r.Statuses = []int{http.StatusOK}
	}
	if r.Severity == "" {
		r.Severity = "info"
	}
	if r.Category == "" {
		r.Category = "general"
	}
	if r.Confidence == "" {
		r.Confidence = "medium"
	}
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	r.Method = strings.ToUpper(r.Method)
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return r, fmt.Errorf("unsupported method %q", r.Method)
	}
	if r.ID == "" {
		r.ID = strings.Trim(strings.ReplaceAll(r.Path, "/", "-"), "-")
	}
	if r.ID == "" {
		return r, errors.New("rule id cannot be empty")
	}
	switch lower(r.Severity) {
	case "info", "low", "medium", "med", "high", "critical", "crit":
	default:
		return r, fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Regex != "" {
		rx, err := regexp.Compile(r.Regex)
		if err != nil {
			return r, fmt.Errorf("invalid regex for %s: %w", r.ID, err)
		}
		r.compiledRegex = rx
	}
	return r, nil
}

func profileAllows(selected, minimum string) bool {
	levels := map[string]int{"quick": 0, "default": 1, "full": 2, "deep": 2}
	selectedLevel, ok := levels[selected]
	if !ok {
		return false
	}
	minimumLevel, ok := levels[minimum]
	if !ok {
		minimumLevel = 1
	}
	return selectedLevel >= minimumLevel
}

func modeAllows(mode string, r rule) bool {
	mode = lower(mode)
	switch mode {
	case "quick", "default", "full", "deep":
		return profileAllows(mode, r.Profile)
	case "htb":
		return hasTag(r.Tags, "htb") || profileAllows("default", r.Profile)
	case "exposure":
		return hasTag(r.Tags, "exposure") || r.Category == "vcs" || r.Category == "secrets" || r.Category == "config" || r.Category == "backup" || r.Category == "logs"
	case "admin":
		return r.Category == "admin"
	case "api":
		return r.Category == "api"
	case "debug":
		return r.Category == "debug" || r.Category == "monitoring"
	case "headers", "tls", "tech":
		return false
	default:
		return profileAllows("default", r.Profile)
	}
}
