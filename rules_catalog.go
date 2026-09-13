package main

import (
	"net/http"
	"strings"
	"unicode"
)

type catalogGroup struct {
	prefix     string
	name       string
	severity   string
	category   string
	profile    string
	statuses   []int
	tags       []string
	remediation string
	paths      []string
}

func init() {
	builtinRules = appendUniqueCatalogRules(builtinRules, buildExtendedCatalog())
}

func buildExtendedCatalog() []rule {
	exposure := []int{http.StatusOK, http.StatusPartialContent}
	endpoint := []int{http.StatusOK, http.StatusNoContent, http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusUnauthorized, http.StatusForbidden}
	api := append(append([]int{}, endpoint...), http.StatusBadRequest, http.StatusMethodNotAllowed)

	groups := []catalogGroup{
		{
			prefix: "vcs", name: "version-control metadata exposed", severity: "high", category: "vcs", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Block repository metadata from the web root and rotate any exposed secrets.",
			paths: []string{
				"/.git/COMMIT_EDITMSG", "/.git/FETCH_HEAD", "/.git/ORIG_HEAD", "/.git/packed-refs", "/.git/description", "/.git/info/refs", "/.git/info/exclude", "/.git/refs/heads/main", "/.git/refs/heads/master", "/.git/refs/remotes/origin/HEAD",
				"/.git/logs/refs/heads/main", "/.git/logs/refs/heads/master", "/.git/logs/refs/remotes/origin/HEAD", "/.gitmodules", "/.gitattributes", "/.gitignore", "/.svn/all-wcprops", "/.svn/format", "/.svn/text-base/index.php.svn-base", "/.hg/hgrc",
				"/.hg/store/fncache", "/.hg/store/00manifest.i", "/.bzr/README", "/.bzr/checkout/dirstate", "/CVS/Entries", "/CVS/Root", "/CVS/Repository", "/_darcs/prefs/repos", "/.fossil", "/.jj/repo/store/type",
			},
		},
		{
			prefix: "config", name: "configuration file exposed", severity: "high", category: "config", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Remove configuration files from public web roots and rotate exposed credentials.",
			paths: []string{
				"/.env.test", "/.env.testing", "/.env.staging", "/.env.stage", "/.env.dev", "/.env.development.local", "/.env.production.local", "/.env.example", "/.env.sample", "/.env.save",
				"/.env.old", "/.env.orig", "/.env.backup", "/.env.tmp", "/.env.dist", "/.env.defaults", "/.envrc", "/.direnv/direnv.toml", "/config.ini", "/config.cfg",
				"/config.conf", "/config.toml", "/config.yaml", "/configuration.php", "/configuration.php-dist", "/configuration.yml", "/settings.json", "/settings.yml", "/settings.yaml", "/settings.ini",
				"/settings.cfg", "/settings.conf", "/settings.toml", "/local.settings.php", "/local.php", "/local.yml", "/local.yaml", "/local.json", "/application.json", "/application.conf",
				"/application.ini", "/application.toml", "/application-local.yml", "/application-local.yaml", "/application-prod.yml", "/application-prod.yaml", "/application-dev.yml", "/application-dev.yaml", "/bootstrap.yml", "/bootstrap.yaml",
				"/bootstrap.properties", "/database.yml", "/database.yaml", "/database.json", "/database.ini", "/database.conf", "/db.yml", "/db.yaml", "/db.json", "/db.ini",
				"/db.conf", "/credentials.json", "/credentials.yml", "/credentials.yaml", "/secrets.json", "/secrets.yml", "/secrets.yaml", "/secret.json", "/secret.yml", "/secret.yaml",
				"/auth.json", "/auth.yml", "/auth.yaml", "/oauth.json", "/oauth.yml", "/oauth.yaml", "/saml.json", "/saml.yml", "/saml.yaml", "/jwt.json",
				"/jwt.yml", "/jwt.yaml", "/keys.json", "/keys.yml", "/keys.yaml", "/private.json", "/private.yml", "/private.yaml", "/parameters.yml", "/parameters.yaml",
				"/parameters.json", "/parameters.ini", "/php.ini", "/.user.ini", "/httpd.conf", "/apache2.conf", "/nginx.conf", "/nginx/nginx.conf", "/conf/nginx.conf", "/conf/httpd.conf",
				"/conf/server.xml", "/conf/context.xml", "/WEB-INF/web.xml", "/WEB-INF/classes/application.properties", "/WEB-INF/classes/application.yml", "/WEB-INF/classes/application.yaml", "/META-INF/context.xml", "/server.xml", "/context.xml", "/log4j.properties",
				"/log4j2.xml", "/logback.xml", "/logging.properties", "/prometheus.yml", "/prometheus.yaml", "/grafana.ini", "/kibana.yml", "/elasticsearch.yml", "/redis.conf", "/mongod.conf",
			},
		},
		{
			prefix: "backup", name: "backup or temporary file exposed", severity: "high", category: "backup", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Move backups outside the document root and deny access to temporary/editor files.",
			paths: []string{
				"/backup.rar", "/backup.7z", "/backup.bz2", "/backup.tar.bz2", "/backup.tar.xz", "/backup.xz", "/backup.old", "/backup.bak", "/backup.save", "/backup.tmp",
				"/backup-copy.zip", "/backup_latest.zip", "/backup-latest.zip", "/backup_1.zip", "/backup-1.zip", "/backup_2024.zip", "/backup_2025.zip", "/backup_2026.zip", "/website.zip", "/website.tar.gz",
				"/website.bak", "/web.zip", "/web.tar.gz", "/webroot.zip", "/webroot.tar.gz", "/htdocs.zip", "/htdocs.tar.gz", "/public_html.zip", "/public_html.tar.gz", "/wwwroot.zip",
				"/wwwroot.tar.gz", "/app.tar.gz", "/app.tgz", "/app.bak", "/src.tar.gz", "/src.tgz", "/source.tar.gz", "/source.tgz", "/code.zip", "/code.tar.gz",
				"/project.zip", "/project.tar.gz", "/release.zip", "/release.tar.gz", "/deploy.zip", "/deploy.tar.gz", "/deployment.zip", "/deployment.tar.gz", "/prod.zip", "/prod.tar.gz",
				"/production.zip", "/production.tar.gz", "/staging.zip", "/staging.tar.gz", "/dev.zip", "/development.zip", "/old.zip", "/old.tar.gz", "/archive.zip", "/archive.tar.gz",
				"/db.dump", "/database.dump", "/dump.dump", "/postgres.dump", "/postgres.sql", "/postgresql.sql", "/mariadb.sql", "/sqlite.db", "/database.db", "/app.db",
				"/data.db", "/data.sqlite", "/database.sqlite", "/database.sqlite3", "/db.sqlite", "/db.sqlite3", "/users.sql", "/customers.sql", "/schema.sql", "/seed.sql",
				"/data.sql", "/export.sql", "/latest.sql", "/prod-db.sql", "/production-db.sql", "/staging.sql", "/wordpress.sql", "/wp.sql", "/mysql.dump", "/mongo.dump",
				"/index.php.bak", "/index.php.old", "/index.php.orig", "/index.php.save", "/index.php.swp", "/index.php.swo", "/index.html.bak", "/index.html.old", "/index.html.orig", "/index.html.save",
				"/config.php.old", "/config.php.orig", "/config.php.save", "/config.php.swp", "/settings.py.bak", "/settings.py.old", "/web.config.old", "/web.config.orig", "/application.yml.bak", "/application.properties.bak",
			},
		},
		{
			prefix: "devops", name: "DevOps or deployment metadata exposed", severity: "medium", category: "devops", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Remove build and deployment metadata from the public document root.",
			paths: []string{
				"/.github/workflows/ci.yml", "/.github/workflows/ci.yaml", "/.github/workflows/build.yml", "/.github/workflows/build.yaml", "/.github/workflows/deploy.yml", "/.github/workflows/deploy.yaml", "/.github/dependabot.yml", "/.gitlab-ci.yaml", "/azure-pipelines.yml", "/azure-pipelines.yaml",
				"/.circleci/config.yml", "/.circleci/config.yaml", "/.travis.yml", "/bitbucket-pipelines.yml", "/buildspec.yml", "/cloudbuild.yaml", "/cloudbuild.yml", "/appveyor.yml", "/Jenkinsfile.bak", "/Jenkinsfile.old", "/Dronefile",
				"/.drone.yml", "/.woodpecker.yml", "/.woodpecker.yaml", "/werf.yaml", "/werf.yml", "/skaffold.yaml", "/skaffold.yml", "/Tiltfile", "/Procfile", "/Procfile.dev",
				"/Dockerfile.dev", "/Dockerfile.prod", "/Dockerfile.production", "/Dockerfile.test", "/docker-compose.yaml", "/docker-compose.override.yml", "/docker-compose.override.yaml", "/docker-compose.prod.yml", "/docker-compose.production.yml", "/compose.yml",
				"/compose.yaml", "/.dockerignore", "/.helmignore", "/Chart.yaml", "/Chart.yml", "/values.yaml", "/values.yml", "/values-prod.yaml", "/values-production.yaml", "/kustomization.yaml",
				"/kustomization.yml", "/deployment.yaml", "/deployment.yml", "/service.yaml", "/service.yml", "/ingress.yaml", "/ingress.yml", "/namespace.yaml", "/secret.yaml", "/configmap.yaml",
				"/terraform.tfvars", "/terraform.tfvars.json", "/terraform.tfstate.backup", "/.terraform.lock.hcl", "/main.tf", "/variables.tf", "/outputs.tf", "/providers.tf", "/backend.tf", "/terragrunt.hcl",
				"/ansible.cfg", "/playbook.yml", "/playbook.yaml", "/site.yml", "/site.yaml", "/inventory", "/inventory.ini", "/hosts.ini", "/Vagrantfile", "/Packerfile",
			},
		},
		{
			prefix: "cloud", name: "cloud configuration exposed", severity: "high", category: "cloud", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Remove cloud credentials/configuration from public paths and rotate exposed credentials.",
			paths: []string{
				"/.aws/config", "/aws/credentials", "/aws/config", "/credentials/aws", "/.azure/accessTokens.json", "/.azure/azureProfile.json", "/.azure/clouds.config", "/azure.json", "/azureProfile.json", "/.config/gcloud/credentials.db",
				"/.config/gcloud/access_tokens.db", "/.config/gcloud/configurations/config_default", "/gcloud/credentials.db", "/gcloud/access_tokens.db", "/service-account.json", "/service_account.json", "/google-service-account.json", "/google-credentials.json", "/firebase.json", "/.firebaserc",
				"/firebase-adminsdk.json", "/gcp.json", "/gcp-key.json", "/gcp-service-account.json", "/.oci/config", "/oci/config", "/.kube/config.bak", "/kubeconfig", "/kubeconfig.yaml", "/kubeconfig.yml",
				"/k8s.yaml", "/k8s.yml", "/kubernetes.yaml", "/kubernetes.yml", "/cluster.yaml", "/cluster.yml", "/cluster-config.yaml", "/cluster-config.yml", "/vault.hcl", "/vault.json",
				"/.vault-token", "/consul.hcl", "/nomad.hcl", "/nomad.json", "/pulumi.yaml", "/Pulumi.yaml", "/Pulumi.dev.yaml", "/Pulumi.prod.yaml", "/serverless.yml", "/serverless.yaml",
			},
		},
		{
			prefix: "debug", name: "debug or diagnostic endpoint exposed", severity: "medium", category: "debug", profile: "full", statuses: endpoint,
			tags: []string{"htb", "debug"}, remediation: "Disable debug/diagnostic endpoints in production or restrict them to trusted networks.",
			paths: []string{
				"/__debug__", "/debug", "/debug/", "/debug/status", "/debug/vars", "/debug/requests", "/debug/events", "/debug/config", "/debug/env", "/debug/routes",
				"/debug/metrics", "/debug/health", "/debug/info", "/debug/version", "/_debugbar/open", "/_debugbar/assets/stylesheets", "/_profiler", "/_profiler/", "/_profiler/phpinfo", "/_wdt",
				"/__clockwork", "/clockwork/app", "/telescope", "/horizon", "/ignition/health-check", "/_ignition/health-check", "/rails/info", "/rails/info/routes", "/rails/info/properties", "/__django__",
				"/__debugger__", "/console", "/console/", "/shell", "/repl", "/diagnostics", "/diagnostics/", "/health", "/healthz", "/livez", "/readyz",
				"/readiness", "/liveness", "/status", "/status/", "/info", "/version", "/version.json", "/build", "/build-info", "/buildinfo",
				"/env", "/environment", "/configprops", "/beans", "/mappings", "/heapdump", "/threaddump", "/loggers", "/jolokia", "/jolokia/",
				"/metrics/", "/prometheus", "/stats", "/stats/", "/server-status?auto", "/nginx_status", "/stub_status", "/fpm-status", "/php-fpm-status", "/haproxy?stats",
			},
		},
		{
			prefix: "admin", name: "administrative or management endpoint", severity: "info", category: "admin", profile: "full", statuses: endpoint,
			tags: []string{"htb", "admin"}, remediation: "Restrict administrative interfaces and require strong authentication.",
			paths: []string{
				"/admin.php", "/admin.html", "/admin/index.php", "/admin/index.html", "/admin/dashboard", "/admin/home", "/admin/auth", "/admin/signin", "/admin/sign-in", "/adminpanel",
				"/admin-panel", "/admin_panel", "/administration", "/backend", "/backend/", "/backend/login", "/controlpanel", "/control-panel", "/control_panel", "/cpanel",
				"/panel", "/panel/", "/panel/login", "/manage/", "/management", "/management/", "/management/login", "/manager", "/manager/", "/manager/login",
				"/dashboard/", "/dashboard/login", "/portal", "/portal/", "/portal/login", "/staff", "/staff/", "/staff/login", "/moderator", "/moderator/login",
				"/system", "/system/", "/system/login", "/console/login", "/webadmin", "/webadmin/", "/web-admin", "/siteadmin", "/site-admin", "/superadmin",
				"/super-admin", "/root", "/operator", "/ops", "/ops/", "/internal/admin", "/internal/login", "/private/admin", "/private/login", "/secure/admin",
				"/secure/login", "/auth/login", "/auth/signin", "/users/login", "/account/login", "/accounts/login", "/user/login", "/login.php", "/login.html", "/signin.php",
				"/adminer.php", "/adminer/", "/phpMyAdmin/", "/phpmyadmin/index.php", "/mysql/", "/dbadmin/", "/database/", "/pgadmin/", "/pgadmin4/", "/mongo-express/",
			},
		},
		{
			prefix: "api", name: "API or machine-readable documentation endpoint", severity: "low", category: "api", profile: "full", statuses: api,
			tags: []string{"htb", "api"}, remediation: "Review whether API documentation or metadata should be publicly exposed.",
			paths: []string{
				"/api/docs", "/api/docs/", "/api/swagger", "/api/swagger.json", "/api/openapi.json", "/api/openapi.yaml", "/api/schema", "/api/schema/", "/api/schema.json", "/api/schema.yaml",
				"/api/v1/docs", "/api/v1/swagger.json", "/api/v1/openapi.json", "/api/v2/docs", "/api/v2/swagger.json", "/api/v2/openapi.json", "/swagger-ui.html", "/swagger/index.html", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
				"/swagger-resources", "/swagger-resources/configuration/ui", "/swagger-resources/configuration/security", "/openapi", "/openapi/", "/openapi.yml", "/openapi-v1.json", "/openapi-v2.json", "/openapi-v3.json", "/api-spec.json",
				"/api-spec.yaml", "/schema.json", "/schema.yaml", "/graphql/", "/graphql/schema", "/graphql/schema.graphql", "/graphql/schema.json", "/graphql-playground", "/playground", "/voyager",
				"/api/graphql", "/v1/graphql", "/v2/graphql", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/", "/rest/api", "/rest/v1",
			},
		},
		{
			prefix: "cms", name: "CMS or framework endpoint exposed", severity: "info", category: "cms", profile: "full", statuses: endpoint,
			tags: []string{"htb", "cms"}, remediation: "Review exposed CMS/framework endpoints and restrict administrative surfaces where appropriate.",
			paths: []string{
				"/wp-json/", "/wp-json/wp/v2/users", "/wp-content/debug.log", "/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/", "/wp-includes/", "/xmlrpc.php", "/readme.html", "/license.txt",
				"/administrator/", "/administrator/index.php", "/configuration.php-dist", "/htaccess.txt", "/web.config.txt", "/README.txt", "/core/install.php", "/user/login", "/sites/default/settings.php", "/sites/default/files/",
				"/CHANGELOG.txt", "/INSTALL.txt", "/UPGRADE.txt", "/misc/drupal.js", "/vendor/", "/vendor/autoload.php", "/storage/", "/storage/logs/", "/storage/framework/", "/artisan",
				"/server.php", "/vendor/composer/installed.json", "/composer.phar", "/symfony.lock", "/bin/console", "/app/config/parameters.yml", "/var/log/", "/config/services.yaml", "/config/routes.yaml", "/config/packages/",
				"/manage.py", "/requirements-dev.txt", "/requirements-prod.txt", "/Pipfile", "/pyproject.toml", "/poetry.lock", "/wsgi.py", "/asgi.py", "/manage", "/static/admin/",
				"/Gemfile", "/config/database.yml", "/config/secrets.yml", "/config/master.key", "/config/credentials.yml.enc", "/config/routes.rb", "/Rakefile", "/rails/info/routes", "/package-lock.json", "/yarn.lock",
				"/pnpm-lock.yaml", "/bun.lockb", "/next.config.js", "/next.config.mjs", "/next.config.ts", "/nuxt.config.js", "/nuxt.config.ts", "/vite.config.js", "/vite.config.ts", "/webpack.config.js",
				"/tsconfig.json", "/.next/BUILD_ID", "/.next/routes-manifest.json", "/.next/server/pages-manifest.json", "/dist/", "/build/manifest.json", "/manifest.json", "/asset-manifest.json", "/mix-manifest.json", "/service-worker.js",
			},
		},
		{
			prefix: "source", name: "source, build, or project metadata exposed", severity: "low", category: "source", profile: "full", statuses: exposure,
			tags: []string{"htb", "exposure"}, remediation: "Avoid publishing source/build metadata that reveals internals or dependency information.",
			paths: []string{
				"/go.mod", "/go.sum", "/go.work", "/Cargo.toml", "/Cargo.lock", "/pom.xml", "/build.gradle", "/build.gradle.kts", "/settings.gradle", "/settings.gradle.kts",
				"/gradle.properties", "/mvnw", "/gradlew", "/package.json.bak", "/package-lock.json.bak", "/composer.json.bak", "/composer.lock.bak", "/requirements.txt.bak", "/requirements-dev.txt", "/requirements-test.txt",
				"/setup.py", "/setup.cfg", "/tox.ini", "/pytest.ini", "/.flake8", "/mypy.ini", "/ruff.toml", "/uv.lock", "/environment.yml", "/environment.yaml",
				"/Makefile", "/makefile", "/CMakeLists.txt", "/meson.build", "/Taskfile.yml", "/Taskfile.yaml", "/Justfile", "/Earthfile", "/Brewfile", "/flake.nix",
				"/shell.nix", "/default.nix", "/.editorconfig", "/.prettierrc", "/.prettierrc.json", "/.eslintrc", "/.eslintrc.json", "/eslint.config.js", "/.stylelintrc", "/.babelrc",
				"/babel.config.js", "/jest.config.js", "/jest.config.ts", "/vitest.config.ts", "/karma.conf.js", "/cypress.config.js", "/playwright.config.ts", "/.nycrc", "/sonar-project.properties", "/.coveragerc",
			},
		},
		{
			prefix: "wellknown", name: "interesting metadata endpoint", severity: "info", category: "metadata", profile: "full", statuses: endpoint,
			tags: []string{"htb", "discovery"}, remediation: "Review whether the metadata endpoint exposes unnecessary internal information.",
			paths: []string{
				"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json", "/.well-known/webfinger", "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association", "/.well-known/change-password", "/.well-known/mta-sts.txt", "/.well-known/acme-challenge/", "/.well-known/nodeinfo",
				"/jwks.json", "/oauth/.well-known/openid-configuration", "/auth/.well-known/openid-configuration", "/realms/master/.well-known/openid-configuration", "/robots.txt.bak", "/sitemap.xml.gz", "/sitemap_index.xml", "/humans.txt", "/ads.txt", "/app-ads.txt",
				"/crossdomain.xml", "/clientaccesspolicy.xml", "/browserconfig.xml", "/manifest.webmanifest", "/site.webmanifest", "/favicon.ico", "/apple-touch-icon.png", "/.well-known/traffic-advice", "/.well-known/ai-plugin.json", "/ai-plugin.json",
			},
		},
	}

	var out []rule
	for _, group := range groups {
		for _, path := range group.paths {
			out = append(out, rule{
				ID:          "catalog-" + group.prefix + "-" + catalogSlug(path),
				Path:        path,
				Name:        group.name,
				Severity:    group.severity,
				Category:    group.category,
				Confidence:  "medium",
				Statuses:    group.statuses,
				Profile:     group.profile,
				Tags:        group.tags,
				Remediation: group.remediation,
			})
		}
	}
	return out
}

func appendUniqueCatalogRules(base, extra []rule) []rule {
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, r := range base {
		seen[strings.ToUpper(r.Method)+"\x00"+r.Path] = struct{}{}
	}
	for _, r := range extra {
		key := strings.ToUpper(r.Method) + "\x00" + r.Path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		base = append(base, r)
	}
	return base
}

func catalogSlug(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return "root"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(path) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
