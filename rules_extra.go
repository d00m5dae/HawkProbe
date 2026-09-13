package main

import (
	"net/http"
	"strings"
	"unicode"
)

func mergeBuiltinRules(groups ...[]rule) []rule {
	seenID := make(map[string]bool)
	seenRequest := make(map[string]bool)
	var out []rule
	for _, group := range groups {
		for _, r := range group {
			method := r.Method
			if method == "" {
				method = http.MethodGet
			}
			key := strings.ToUpper(method) + " " + r.Path
			if seenID[r.ID] || seenRequest[key] {
				continue
			}
			seenID[r.ID] = true
			seenRequest[key] = true
			out = append(out, r)
		}
	}
	return out
}

func buildExtraRules() []rule {
	out := make([]rule, 0, 450)
	add := func(path, name, sev, category, profile string, tags ...string) {
		out = append(out, rule{
			ID:         extraRuleID(category, path),
			Path:       path,
			Name:       name,
			Severity:   sev,
			Category:   category,
			Confidence: "medium",
			Statuses:   []int{200, 206, 301, 302, 307, 308, 401, 403},
			Profile:    profile,
			Tags:       tags,
		})
	}

	backupBases := []string{
		"index.php", "config.php", "configuration.php", "wp-config.php", "settings.php", "settings.py",
		"local_settings.py", "app.py", "main.py", "wsgi.py", "server.js", "app.js", "index.js", "package.json",
		"composer.json", "web.config", "application.yml", "application.properties", "appsettings.json", "database.yml",
		"config.yml", "config.json", "nginx.conf", "httpd.conf", "apache2.conf", "routes.php", "routes.rb",
	}
	backupSuffixes := []string{".bak", ".old", ".orig", ".save", ".swp", "~", ".tmp", ".copy"}
	for _, base := range backupBases {
		for _, suffix := range backupSuffixes {
			add("/"+base+suffix, "backup or editor copy exposed", "high", "backup", "full", "htb", "exposure")
		}
	}

	for _, path := range []string{
		"/.env.test", "/.env.staging", "/.env.qa", "/.env.example", "/.env.sample", "/.env.dist", "/.envrc",
		"/.htaccess", "/.htpasswd", "/.user.ini", "/php.ini", "/php.ini-development", "/php.ini-production",
		"/config.ini", "/config.toml", "/config.xml", "/settings.ini", "/settings.yml", "/settings.yaml", "/settings.json",
		"/database.ini", "/database.json", "/database.yml", "/database.yaml", "/credentials.json", "/credentials.yml",
		"/credentials.yaml", "/secrets.json", "/secrets.yml", "/secrets.yaml", "/secret.txt", "/passwords.txt",
		"/.netrc", "/.git-credentials", "/.dockercfg", "/.terraformrc", "/terraform.tfvars", "/terraform.tfvars.json",
		"/ansible.cfg", "/inventory.ini", "/hosts.ini", "/vault.yml", "/vault.yaml", "/values.yaml", "/values.yml",
		"/kustomization.yaml", "/Chart.yaml", "/serverless.yml", "/serverless.yaml", "/firebase.json", "/now.json",
	} {
		add(path, "sensitive configuration or credential file exposed", "high", "secrets", "full", "htb", "exposure", "cloud")
	}

	for _, path := range []string{
		"/admin/", "/admin/login", "/admin/index.php", "/admin.php", "/admin.html", "/administrator/", "/administrator/index.php",
		"/manage/", "/management/", "/manager/", "/manager/html", "/console/", "/console", "/control/", "/controlpanel/",
		"/cpanel/", "/webadmin/", "/siteadmin/", "/sysadmin/", "/system/", "/backend/", "/backoffice/", "/staff/",
		"/dashboard/", "/portal/", "/internal/", "/private/", "/secure/", "/auth/", "/signin", "/sign-in", "/login.php",
		"/user/login", "/users/login", "/account/login", "/accounts/login", "/auth/login", "/session/new", "/wp-login.php",
		"/phpmyadmin/", "/pma/", "/adminer.php", "/adminer/", "/pgadmin/", "/mongo-express/", "/redis-commander/",
		"/jenkins/", "/grafana/", "/kibana/", "/prometheus/", "/rabbitmq/", "/portainer/", "/traefik/", "/rundeck/",
		"/sonarqube/", "/nexus/", "/artifactory/", "/vault/ui/", "/minio/", "/harbor/", "/argocd/",
	} {
		add(path, "administrative or management endpoint", "info", "admin", "full", "htb", "admin")
	}

	for _, path := range []string{
		"/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger/index.html", "/api/swagger.json", "/api/swagger.yaml",
		"/openapi.yaml", "/openapi.yml", "/api/openapi.json", "/api/openapi.yaml", "/docs/", "/api/docs/", "/redoc/",
		"/graphql/", "/graphiql", "/graphiql/", "/playground", "/graphql-playground", "/api/graphql", "/api/v1/", "/api/v2/", "/api/v3/",
		"/v1/", "/v2/", "/v3/", "/rest/", "/rest/api/", "/api/status", "/api/health", "/api/version", "/api/config",
		"/api/debug", "/api/internal", "/api/admin", "/api/users", "/api/auth", "/api/login", "/api/schema", "/schema.json",
		"/swagger-resources", "/swagger-resources/configuration/ui", "/api-docs/swagger.json", "/.well-known/openapi.json",
	} {
		add(path, "API or developer endpoint", "info", "api", "full", "htb", "api")
	}

	for _, path := range []string{
		"/debug/", "/debug.php", "/debugbar/", "/_debugbar/", "/__debug__/", "/trace", "/trace/", "/status", "/status/",
		"/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/metrics/", "/stats", "/stats/", "/server-status?auto",
		"/actuator/health", "/actuator/info", "/actuator/beans", "/actuator/mappings", "/actuator/threaddump", "/actuator/heapdump",
		"/actuator/loggers", "/actuator/scheduledtasks", "/actuator/httptrace", "/actuator/auditevents", "/actuator/caches",
		"/debug/pprof/goroutine", "/debug/pprof/heap", "/debug/pprof/profile", "/debug/vars", "/vars", "/env",
		"/_profiler/", "/_wdt/", "/_ignition/health-check", "/_ignition/execute-solution", "/telescope/", "/horizon/",
	} {
		add(path, "debug, health, or monitoring endpoint", "medium", "debug", "full", "htb", "debug")
	}

	for _, path := range []string{
		"/.gitlab-ci.yml", "/.github/workflows/ci.yml", "/.github/workflows/build.yml", "/.github/workflows/deploy.yml",
		"/.circleci/config.yml", "/.travis.yml", "/bitbucket-pipelines.yml", "/azure-pipelines.yml", "/cloudbuild.yaml",
		"/Dockerfile.dev", "/Dockerfile.prod", "/docker-compose.override.yml", "/docker-compose.prod.yml", "/compose.override.yaml",
		"/kubernetes.yml", "/kubernetes.yaml", "/deployment.yml", "/deployment.yaml", "/service.yml", "/service.yaml",
		"/ingress.yml", "/ingress.yaml", "/helm/values.yaml", "/.aws/config", "/.azure/credentials", "/gcp.json",
		"/service-account.json", "/firebase-adminsdk.json", "/credentials.xml", "/application-default-credentials.json",
		"/.npmrc", "/.yarnrc", "/.yarnrc.yml", "/.pip/pip.conf", "/pip.conf", "/nuget.config",
	} {
		add(path, "CI/CD, container, or cloud configuration exposed", "high", "cloud", "full", "htb", "exposure", "cloud")
	}

	for _, path := range []string{
		"/error.log", "/errors.log", "/debug.log", "/app.log", "/application.log", "/access.log", "/server.log", "/web.log",
		"/logs/error.log", "/logs/access.log", "/logs/app.log", "/log/error.log", "/log/access.log", "/storage/logs/laravel.log",
		"/var/log/app.log", "/npm-debug.log", "/yarn-error.log", "/debug.txt", "/trace.log", "/requests.log",
		"/backup.sql.gz", "/database.sql.gz", "/dump.sql.gz", "/mysql.sql.gz", "/db.sqlite", "/database.sqlite", "/app.db",
		"/data.db", "/db.sqlite3", "/database.sqlite3", "/users.db", "/prod.db", "/backup.db",
	} {
		add(path, "log or database artifact exposed", "high", "exposure", "full", "htb", "exposure")
	}

	for _, path := range []string{
		"/.idea/workspace.xml", "/.idea/modules.xml", "/.vscode/settings.json", "/.vscode/launch.json", "/.project", "/.classpath",
		"/README", "/README.txt", "/CHANGELOG", "/CHANGELOG.txt", "/TODO", "/TODO.txt", "/NOTES.txt", "/notes.txt",
		"/humans.txt", "/ads.txt", "/manifest.json", "/asset-manifest.json", "/build-manifest.json", "/routes.json",
		"/webpack-stats.json", "/stats.json", "/version", "/version.txt", "/VERSION", "/build.txt", "/release.txt",
		"/cgi-bin/test-cgi", "/cgi-bin/status", "/cgi-bin/printenv", "/cgi-bin/php", "/cgi-bin/php5", "/cgi-bin/php7",
	} {
		add(path, "interesting development or metadata endpoint", "info", "discovery", "full", "htb")
	}

	return out
}

func extraRuleID(category, path string) string {
	var b strings.Builder
	b.WriteString("extra-")
	b.WriteString(category)
	b.WriteByte('-')
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(path)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
