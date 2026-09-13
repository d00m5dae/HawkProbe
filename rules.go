package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

var builtinRules = []rule{
	{ID: "git-head", Path: "/.git/HEAD", Name: "exposed Git repository", Severity: "high", Statuses: []int{200}, Contains: []string{"ref:", "refs/heads/"}, Profile: "quick"},
	{ID: "git-config", Path: "/.git/config", Name: "exposed Git configuration", Severity: "high", Statuses: []int{200}, Contains: []string{"[core]", "repositoryformatversion"}, Profile: "default"},
	{ID: "svn-entries", Path: "/.svn/entries", Name: "exposed Subversion metadata", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "hg-requires", Path: "/.hg/requires", Name: "exposed Mercurial metadata", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "bzr-config", Path: "/.bzr/branch/branch.conf", Name: "exposed Bazaar metadata", Severity: "high", Statuses: []int{200}, Profile: "full"},

	{ID: "env", Path: "/.env", Name: "exposed environment file", Severity: "high", Statuses: []int{200}, Profile: "quick"},
	{ID: "env-local", Path: "/.env.local", Name: "exposed local environment file", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "env-prod", Path: "/.env.production", Name: "exposed production environment file", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "env-dev", Path: "/.env.development", Name: "exposed development environment file", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "aws-credentials", Path: "/.aws/credentials", Name: "exposed AWS credentials file", Severity: "high", Statuses: []int{200}, Contains: []string{"aws_access_key_id", "aws_secret_access_key"}, Profile: "full"},
	{ID: "kube-config", Path: "/.kube/config", Name: "exposed Kubernetes config", Severity: "high", Statuses: []int{200}, Contains: []string{"apiVersion", "clusters:"}, Profile: "full"},
	{ID: "ssh-id-rsa", Path: "/id_rsa", Name: "exposed private key", Severity: "high", Statuses: []int{200}, Contains: []string{"PRIVATE KEY"}, Profile: "full"},

	{ID: "backup-zip", Path: "/backup.zip", Name: "public backup archive", Severity: "high", Statuses: []int{200}, Profile: "quick"},
	{ID: "backup-targz", Path: "/backup.tar.gz", Name: "public backup archive", Severity: "high", Statuses: []int{200}, Profile: "quick"},
	{ID: "site-zip", Path: "/site.zip", Name: "public site archive", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "www-zip", Path: "/www.zip", Name: "public webroot archive", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "db-sql", Path: "/db.sql", Name: "public database dump", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "database-sql", Path: "/database.sql", Name: "public database dump", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "dump-sql", Path: "/dump.sql", Name: "public database dump", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "backup-sql", Path: "/backup.sql", Name: "public database dump", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "db-sql-gz", Path: "/db.sql.gz", Name: "compressed database dump", Severity: "high", Statuses: []int{200}, Profile: "full"},

	{ID: "config-php-bak", Path: "/config.php.bak", Name: "backup configuration file", Severity: "high", Statuses: []int{200}, Profile: "quick"},
	{ID: "wp-config-bak", Path: "/wp-config.php.bak", Name: "WordPress config backup", Severity: "high", Statuses: []int{200}, Profile: "default"},
	{ID: "wp-config-tilde", Path: "/wp-config.php~", Name: "WordPress config editor backup", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "web-config", Path: "/web.config", Name: "exposed web.config", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "application-properties", Path: "/application.properties", Name: "exposed application properties", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "application-yml", Path: "/application.yml", Name: "exposed application configuration", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "config-yml", Path: "/config.yml", Name: "exposed YAML configuration", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "config-json", Path: "/config.json", Name: "exposed JSON configuration", Severity: "medium", Statuses: []int{200}, Profile: "full"},

	{ID: "phpinfo", Path: "/phpinfo.php", Name: "phpinfo page", Severity: "medium", Statuses: []int{200}, Contains: []string{"PHP Version", "phpinfo()"}, Profile: "quick"},
	{ID: "phpinfo-root", Path: "/info.php", Name: "PHP information page", Severity: "medium", Statuses: []int{200}, Contains: []string{"PHP Version", "phpinfo()"}, Profile: "default"},
	{ID: "server-status", Path: "/server-status", Name: "Apache server-status page", Severity: "medium", Statuses: []int{200}, Contains: []string{"Apache Server Status", "Server Version"}, Profile: "quick"},
	{ID: "server-info", Path: "/server-info", Name: "Apache server-info page", Severity: "medium", Statuses: []int{200}, Profile: "quick"},
	{ID: "pprof", Path: "/debug/pprof/", Name: "Go pprof endpoint", Severity: "medium", Statuses: []int{200}, Contains: []string{"Types of profiles", "goroutine"}, Profile: "default"},
	{ID: "actuator", Path: "/actuator", Name: "Spring Boot actuator exposed", Severity: "medium", Statuses: []int{200}, Profile: "default"},
	{ID: "actuator-env", Path: "/actuator/env", Name: "Spring Boot environment endpoint exposed", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "actuator-configprops", Path: "/actuator/configprops", Name: "Spring Boot config properties exposed", Severity: "high", Statuses: []int{200}, Profile: "full"},
	{ID: "metrics", Path: "/metrics", Name: "metrics endpoint exposed", Severity: "low", Statuses: []int{200}, Profile: "default"},
	{ID: "prometheus", Path: "/actuator/prometheus", Name: "Prometheus metrics endpoint exposed", Severity: "low", Statuses: []int{200}, Profile: "full"},
	{ID: "trace-axd", Path: "/trace.axd", Name: "ASP.NET trace endpoint exposed", Severity: "high", Statuses: []int{200}, Profile: "full"},

	{ID: "admin", Path: "/admin", Name: "admin endpoint", Severity: "info", Statuses: []int{200, 401, 403}, Profile: "quick"},
	{ID: "administrator", Path: "/administrator", Name: "administrator endpoint", Severity: "info", Statuses: []int{200, 401, 403}, Profile: "default"},
	{ID: "login", Path: "/login", Name: "login endpoint", Severity: "info", Statuses: []int{200, 401, 403}, Profile: "quick"},
	{ID: "wp-admin", Path: "/wp-admin/", Name: "WordPress admin endpoint", Severity: "info", Statuses: []int{200, 301, 302, 401, 403}, Profile: "default"},
	{ID: "phpmyadmin", Path: "/phpmyadmin/", Name: "phpMyAdmin endpoint", Severity: "medium", Statuses: []int{200, 301, 302, 401, 403}, Profile: "default"},
	{ID: "grafana", Path: "/login", Name: "Grafana login detected", Severity: "info", Statuses: []int{200}, Contains: []string{"Grafana"}, Profile: "full"},
	{ID: "jenkins", Path: "/login", Name: "Jenkins login detected", Severity: "info", Statuses: []int{200}, Contains: []string{"Jenkins"}, Profile: "full"},

	{ID: "swagger-ui", Path: "/swagger-ui/", Name: "Swagger UI exposed", Severity: "low", Statuses: []int{200, 301, 302}, Profile: "default"},
	{ID: "swagger", Path: "/swagger/", Name: "Swagger endpoint exposed", Severity: "low", Statuses: []int{200, 301, 302}, Profile: "full"},
	{ID: "api-docs", Path: "/api-docs", Name: "API documentation exposed", Severity: "low", Statuses: []int{200}, Profile: "default"},
	{ID: "v2-api-docs", Path: "/v2/api-docs", Name: "Swagger v2 API specification exposed", Severity: "low", Statuses: []int{200}, Profile: "full"},
	{ID: "v3-api-docs", Path: "/v3/api-docs", Name: "OpenAPI v3 specification exposed", Severity: "low", Statuses: []int{200}, Profile: "default"},
	{ID: "openapi-json", Path: "/openapi.json", Name: "OpenAPI specification exposed", Severity: "low", Statuses: []int{200}, Profile: "default"},
	{ID: "graphql", Path: "/graphql", Name: "GraphQL endpoint", Severity: "info", Statuses: []int{200, 400, 405}, Profile: "full"},

	{ID: "robots", Path: "/robots.txt", Name: "robots.txt", Severity: "info", Statuses: []int{200}, Profile: "quick"},
	{ID: "security-txt", Path: "/.well-known/security.txt", Name: "security.txt", Severity: "info", Statuses: []int{200}, Profile: "quick"},
	{ID: "crossdomain", Path: "/crossdomain.xml", Name: "crossdomain.xml present", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "clientaccesspolicy", Path: "/clientaccesspolicy.xml", Name: "clientaccesspolicy.xml present", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "ds-store", Path: "/.DS_Store", Name: "exposed .DS_Store", Severity: "medium", Statuses: []int{200}, Profile: "default"},

	{ID: "composer-json", Path: "/composer.json", Name: "composer.json exposed", Severity: "low", Statuses: []int{200}, Contains: []string{"require"}, Profile: "full"},
	{ID: "composer-lock", Path: "/composer.lock", Name: "composer.lock exposed", Severity: "low", Statuses: []int{200}, Contains: []string{"packages"}, Profile: "full"},
	{ID: "package-json", Path: "/package.json", Name: "package.json exposed", Severity: "info", Statuses: []int{200}, Contains: []string{"dependencies", "scripts"}, Profile: "full"},
	{ID: "package-lock", Path: "/package-lock.json", Name: "package-lock.json exposed", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "requirements", Path: "/requirements.txt", Name: "Python requirements file exposed", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "pipfile-lock", Path: "/Pipfile.lock", Name: "Pipfile.lock exposed", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "gemfile-lock", Path: "/Gemfile.lock", Name: "Gemfile.lock exposed", Severity: "info", Statuses: []int{200}, Profile: "full"},
	{ID: "dockerfile", Path: "/Dockerfile", Name: "Dockerfile exposed", Severity: "low", Statuses: []int{200}, Profile: "full"},
	{ID: "docker-compose", Path: "/docker-compose.yml", Name: "docker-compose file exposed", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "gitlab-ci", Path: "/.gitlab-ci.yml", Name: "GitLab CI config exposed", Severity: "low", Statuses: []int{200}, Profile: "full"},
	{ID: "jenkinsfile", Path: "/Jenkinsfile", Name: "Jenkinsfile exposed", Severity: "low", Statuses: []int{200}, Profile: "full"},

	{ID: "error-log", Path: "/error.log", Name: "error log exposed", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "access-log", Path: "/access.log", Name: "access log exposed", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "debug-log", Path: "/debug.log", Name: "debug log exposed", Severity: "medium", Statuses: []int{200}, Profile: "full"},
	{ID: "laravel-log", Path: "/storage/logs/laravel.log", Name: "Laravel log exposed", Severity: "high", Statuses: []int{200}, Profile: "full"},
}

func loadRules(path, profile string) ([]rule, error) {
	out := make([]rule, 0, len(builtinRules))
	for _, r := range builtinRules {
		if profileAllows(profile, r.Profile) {
			out = append(out, normalizeRule(r))
		}
	}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var custom []rule
	if err := json.Unmarshal(data, &custom); err != nil {
		return nil, err
	}
	for i := range custom {
		custom[i] = normalizeRule(custom[i])
		if custom[i].Path == "" || custom[i].Name == "" {
			return nil, errors.New("custom rules require path and name")
		}
	}
	return append(out, custom...), nil
}

func normalizeRule(r rule) rule {
	if len(r.Statuses) == 0 {
		r.Statuses = []int{200}
	}
	if r.Severity == "" {
		r.Severity = "info"
	}
	if r.ID == "" {
		r.ID = strings.Trim(strings.ReplaceAll(r.Path, "/", "-"), "-")
	}
	return r
}

func profileAllows(selected, minimum string) bool {
	levels := map[string]int{"quick": 0, "default": 1, "full": 2}
	s, ok := levels[selected]
	if !ok {
		s = 1
	}
	m, ok := levels[minimum]
	if !ok {
		m = 1
	}
	return s >= m
}
