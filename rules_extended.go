package main

import (
	"fmt"
	"net/http"
	"strings"
)

type catalogGroup struct {
	category string
	name string
	severity string
	statuses []int
	paths []string
}

func init() {
	builtinRules = mergeRuleSets(builtinRules, expandedRules())
}

func expandedRules() []rule {
	groups := []catalogGroup{
		{category: "secrets", name: "potential secret or configuration exposure", severity: "high", statuses: []int{200}, paths: []string{
			"/.aws/config", "/.azure/accessTokens.json", "/.azure/azureProfile.json", "/.config/gcloud/application_default_credentials.json", "/.config/gcloud/credentials", "/.docker/config.json.bak", "/.npmrc.bak", "/.pypirc.bak", "/.gem/credentials", "/.bundle/config", "/.composer/auth.json", "/auth.json", "/credentials.json", "/secrets.json", "/secrets.yml", "/secrets.yaml", "/config/secrets.yml", "/config/secrets.yaml", "/config/credentials.yml", "/config/credentials.yaml", "/config/master.key", "/master.key", "/credentials.yml.enc", "/config/credentials.yml.enc", "/.env.test", "/.env.staging", "/.env.qa", "/.env.prod", "/.env.production.local", "/.env.development.local", "/.env.test.local", "/.env.example", "/.env.sample", "/.env.save", "/.env.old", "/.env.orig", "/.env.backup", "/.env~", "/.env.swp", "/.env.swo", "/.htpasswd", "/.htaccess.bak", "/.pgpass", "/.my.cnf", "/.netrc", "/.git-credentials", "/.gitconfig", "/.ssh/config", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys", "/private.key", "/server.key", "/client.key", "/tls.key", "/ssl.key", "/jwt.key", "/jwt-secret.txt", "/secret.key", "/secret.txt", "/config/database.yml", "/config/database.yaml", "/database.yml", "/database.yaml", "/config/db.yml", "/config/db.yaml",
		}},
		{category: "backup", name: "potential backup or data artifact", severity: "high", statuses: []int{200, 206}, paths: []string{
			"/www.tar.gz", "/www.tgz", "/www.tar", "/www.rar", "/www.7z", "/site.tgz", "/site.tar", "/site.rar", "/site.7z", "/source.tar.gz", "/source.tgz", "/source.tar", "/source.rar", "/source.7z", "/src.tar.gz", "/src.tgz", "/src.tar", "/src.rar", "/src.7z", "/app.tar.gz", "/app.tgz", "/app.tar", "/app.rar", "/app.7z", "/public.zip", "/public.tar.gz", "/htdocs.zip", "/htdocs.tar.gz", "/html.zip", "/html.tar.gz", "/web.zip", "/web.tar.gz", "/website.zip", "/website.tar.gz", "/root.zip", "/root.tar.gz", "/files.zip", "/files.tar.gz", "/archive.zip", "/archive.tar.gz", "/backup.rar", "/backup.7z", "/backup.old", "/backup.bak", "/db.dump", "/database.dump", "/postgres.dump", "/pgsql.dump", "/mongo.dump", "/redis.rdb", "/dump.rdb", "/data.sql", "/data.sql.gz", "/latest.sql", "/latest.sql.gz", "/dev.sql", "/test.sql", "/staging.sql", "/users.sql", "/wordpress.sql", "/wp.sql", "/joomla.sql", "/drupal.sql", "/index.php.bak", "/index.php.old", "/index.php.orig", "/index.php.save", "/index.php.swp", "/index.html.bak", "/index.html.old", "/config.php.old", "/config.php.orig", "/config.php.save", "/settings.php.bak", "/settings.php.old", "/settings.py.bak", "/appsettings.json.old", "/application.yml.bak", "/application.properties.bak", "/web.config.old",
		}},
		{category: "devops", name: "development or deployment artifact", severity: "low", statuses: []int{200}, paths: []string{
			"/.github/workflows/ci.yml", "/.github/workflows/ci.yaml", "/.github/workflows/build.yml", "/.github/workflows/build.yaml", "/.github/workflows/deploy.yml", "/.github/workflows/deploy.yaml", "/.github/dependabot.yml", "/.github/CODEOWNERS", "/.circleci/config.yml", "/.circleci/config.yaml", "/.travis.yml", "/.drone.yml", "/.drone.yaml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml", "/.gitlab-ci.yml.bak", "/.buildkite/pipeline.yml", "/.teamcity/settings.kts", "/Jenkinsfile.bak", "/Dockerfile.dev", "/Dockerfile.prod", "/Dockerfile.production", "/docker-compose.yaml", "/docker-compose.override.yml", "/docker-compose.override.yaml", "/docker-compose.prod.yml", "/docker-compose.production.yml", "/.dockerignore", "/k8s.yml", "/k8s.yaml", "/kubernetes.yml", "/kubernetes.yaml", "/deployment.yml", "/deployment.yaml", "/service.yml", "/service.yaml", "/ingress.yml", "/ingress.yaml", "/helm/values.yml", "/helm/values.yaml", "/values.yml", "/values.yaml", "/Chart.yaml", "/terraform.tfvars", "/terraform.tfvars.json", "/.terraform.lock.hcl", "/main.tf", "/variables.tf", "/outputs.tf", "/ansible.cfg", "/inventory.ini", "/hosts.ini", "/playbook.yml", "/playbook.yaml", "/Vagrantfile", "/Procfile",
		}},
		{category: "debug", name: "debug or diagnostic endpoint", severity: "medium", statuses: []int{200, 301, 302, 307, 308, 401, 403}, paths: []string{
			"/debug", "/debug/", "/__debug__", "/_debug", "/debug/default/view", "/_profiler/", "/_wdt/", "/profiler", "/profiler/", "/console", "/console/", "/shell", "/shell/", "/repl", "/repl/", "/health", "/healthz", "/livez", "/readyz", "/status", "/status/", "/version", "/version/", "/info", "/info/", "/env", "/env/", "/config", "/config/", "/configprops", "/beans", "/mappings", "/heapdump", "/threaddump", "/loggers", "/jolokia", "/jolokia/", "/hawtio", "/hawtio/", "/metrics", "/metrics/", "/prometheus", "/prometheus/", "/debug/vars", "/debug/requests", "/debug/events", "/debug/pprof/profile", "/debug/pprof/trace", "/phpinfo", "/phpinfo/", "/server-status?auto", "/server-info?config", "/trace", "/trace/", "/errors", "/errors/", "/error", "/error/",
		}},
		{category: "admin", name: "administrative or authentication surface", severity: "info", statuses: []int{200, 301, 302, 307, 308, 401, 403}, paths: []string{
			"/admin.php", "/admin.html", "/admin/index.php", "/admin/dashboard", "/admin/signin", "/admin/auth", "/adminpanel", "/admin-panel", "/admin_area", "/adminarea", "/backend", "/backend/", "/backoffice", "/backoffice/", "/control", "/control/", "/controlpanel", "/control-panel", "/cpanel", "/cpanel/", "/panel", "/panel/", "/manage/", "/management", "/management/", "/manager", "/manager/", "/system", "/system/", "/sysadmin", "/sysadmin/", "/superadmin", "/superadmin/", "/rootadmin", "/rootadmin/", "/staff", "/staff/", "/moderator", "/moderator/", "/operator", "/operator/", "/auth", "/auth/", "/auth/login", "/account/login", "/user/login", "/users/login", "/session/new", "/signin/", "/sign-in", "/logon", "/logon/", "/portal", "/portal/", "/dashboard/", "/console/login", "/management/login", "/admin-console", "/admin-console/", "/webadmin", "/webadmin/", "/siteadmin", "/siteadmin/", "/cmsadmin", "/cmsadmin/", "/administrator/", "/admincp", "/admincp/", "/modcp", "/modcp/", "/secure/admin", "/private/admin",
		}},
		{category: "api", name: "API or API documentation surface", severity: "low", statuses: []int{200, 301, 302, 307, 308, 400, 401, 403, 405}, paths: []string{
			"/api/", "/api/v2", "/api/v3", "/api/v4", "/api/internal", "/api/admin", "/api/debug", "/api/health", "/api/status", "/api/swagger", "/api/swagger.json", "/api/openapi.json", "/api/openapi.yaml", "/api/docs", "/api-docs/", "/docs/", "/swagger-ui.html", "/swagger-ui/index.html", "/swagger/index.html", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/openapi.yml", "/openapi.yaml", "/openapi.json", "/api-spec.json", "/api-spec.yaml", "/spec.json", "/spec.yaml", "/graphql/", "/graphql/schema", "/graphql/playground", "/playground", "/playground/", "/altair", "/altair/", "/voyager", "/voyager/", "/graphiql/", "/api/graphql", "/v1/graphql", "/v2/graphql", "/rest", "/rest/", "/rest/v1", "/rest/v2", "/rpc", "/rpc/", "/odata", "/odata/", "/api/v1/users", "/api/v1/status", "/api/v1/health", "/.well-known/openapi.json",
		}},
		{category: "cms", name: "CMS-related surface", severity: "info", statuses: []int{200, 301, 302, 307, 308, 401, 403}, paths: []string{
			"/wp-json/", "/wp-json/wp/v2/users", "/wp-content/debug.log", "/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/", "/wp-includes/", "/xmlrpc.php", "/readme.html", "/license.txt", "/wp-cron.php", "/wp-config.php.save", "/wp-config.php.old", "/wp-config.php.orig", "/wp-config.txt", "/wp-admin/install.php", "/wp-admin/setup-config.php", "/sites/default/settings.php", "/sites/default/settings.php.bak", "/sites/default/files/", "/core/install.php", "/CHANGELOG.txt", "/user/login", "/admin/config", "/admin/reports/status", "/update.php", "/install.php", "/core/", "/modules/", "/themes/", "/administrator/index.php", "/configuration.php", "/configuration.php-dist", "/htaccess.txt", "/web.config.txt", "/administrator/manifests/files/joomla.xml", "/components/", "/modules/mod_login/", "/templates/", "/language/en-GB/en-GB.xml", "/typo3/", "/typo3conf/", "/typo3temp/", "/contao/", "/craft/", "/ghost/", "/umbraco/", "/sitecore/", "/sitecore/login", "/admin/content", "/admin/structure", "/cms/", "/cms/admin", "/blog/wp-admin/", "/wordpress/wp-admin/",
		}},
		{category: "cloud", name: "cloud or orchestration artifact", severity: "high", statuses: []int{200, 401, 403}, paths: []string{
			"/.well-known/terraform.json", "/.well-known/azure", "/.well-known/aws", "/metadata", "/metadata/", "/latest/meta-data/", "/latest/user-data", "/computeMetadata/v1/", "/metadata/identity/oauth2/token", "/aws/credentials", "/aws/config", "/azureProfile.json", "/accessTokens.json", "/gcloud/credentials.db", "/gcloud/access_tokens.db", "/service-account.json", "/service_account.json", "/google-credentials.json", "/firebase.json", "/.firebaserc", "/app.yaml", "/app.yml", "/serverless.yml", "/serverless.yaml", "/samconfig.toml", "/template.yaml", "/template.yml", "/cloudformation.yml", "/cloudformation.yaml", "/cdk.json", "/pulumi.yaml", "/Pulumi.yaml", "/Pulumi.dev.yaml", "/Pulumi.prod.yaml", "/kubeconfig", "/kubeconfig.yaml", "/kubeconfig.yml", "/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/token",
		}},
		{category: "discovery", name: "discovery or metadata endpoint", severity: "info", statuses: []int{200, 301, 302, 307, 308, 401, 403}, paths: []string{
			"/humans.txt", "/ads.txt", "/app-ads.txt", "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association", "/.well-known/change-password", "/.well-known/webfinger", "/.well-known/nodeinfo", "/.well-known/host-meta", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json", "/jwks.json", "/manifest.json", "/site.webmanifest", "/browserconfig.xml", "/favicon.ico", "/apple-touch-icon.png", "/manifest.webmanifest", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.txt", "/robots.txt.bak", "/crossdomain.xml.bak", "/README.md", "/README.txt", "/CHANGELOG.md", "/CHANGELOG.txt", "/VERSION", "/VERSION.txt", "/version.txt", "/build.txt", "/release.txt", "/.well-known/security.txt.bak", "/.well-known/acme-challenge/", "/static/", "/assets/", "/public/", "/uploads/",
		}},
	}

	var out []rule
	for _, group := range groups {
		for i, path := range group.paths {
			out = append(out, rule{
				ID: fmt.Sprintf("catalog-%s-%03d", group.category, i+1),
				Path: path,
				Name: group.name,
				Severity: group.severity,
				Category: group.category,
				Confidence: "medium",
				Method: http.MethodGet,
				Statuses: group.statuses,
				Profile: "full",
				Tags: []string{"htb", group.category},
			})
		}
	}
	return out
}

func mergeRuleSets(base, extra []rule) []rule {
	out := make([]rule, 0, len(base)+len(extra))
	seen := make(map[string]struct{}, len(base)+len(extra))
	add := func(r rule) {
		method := r.Method
		if method == "" {
			method = http.MethodGet
		}
		key := strings.ToUpper(method) + " " + r.Path
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	for _, r := range base { add(r) }
	for _, r := range extra { add(r) }
	return out
}
