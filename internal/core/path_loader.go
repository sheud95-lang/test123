package core

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PathLoader struct {
	wordlists map[string][]string
}

func NewPathLoader() *PathLoader {
	return &PathLoader{wordlists: make(map[string][]string)}
}

func (pl *PathLoader) LoadFile(fpath string) (int, error) {
	data, err := os.ReadFile(fpath)
	if err != nil {
		return 0, err
	}
	name := strings.TrimSuffix(filepath.Base(fpath), filepath.Ext(fpath))
	ext := strings.ToLower(filepath.Ext(fpath))
	var raw []string
	switch ext {
	case ".json":
		var list []string
		if json.Unmarshal(data, &list) == nil {
			raw = list
		} else {
			var obj map[string][]string
			if json.Unmarshal(data, &obj) == nil {
				raw = obj["paths"]
			}
		}
	case ".csv":
		r := csv.NewReader(strings.NewReader(string(data)))
		records, _ := r.ReadAll()
		for _, row := range records {
			if len(row) > 0 {
				raw = append(raw, row[0])
			}
		}
	default:
		raw = strings.Split(string(data), "\n")
	}
	cleaned := cleanDedup(raw)
	pl.wordlists[name] = cleaned
	return len(cleaned), nil
}

func (pl *PathLoader) LoadDefault() int {
	paths := []string{
		// Environment files
		"/.env", "/.env.local", "/.env.production", "/.env.backup",
		"/.env.old", "/.env.save", "/.env.bak", "/.env.dev",
		"/.env.staging", "/.env.example", "/.env.test",
		"/.env.development", "/.env.prod",
		"/app/.env", "/src/.env", "/backend/.env",

		// WordPress
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-config.php.save", "/wp-config.txt", "/wp-config.php.swp",
		"/wp-config.php~", "/wp-config.php.orig",

		// PHP configs
		"/config.php", "/config.php.bak", "/config.inc.php",
		"/configuration.php", "/settings.php", "/local.php",
		"/parameters.yml", "/parameters.ini",

		// Git exposure
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/logs/HEAD", "/.git/refs/heads/master", "/.git/refs/heads/main",
		"/.gitignore", "/.git/refs/heads/develop",

		// SVN / Hg
		"/.svn/entries", "/.svn/wc.db",
		"/.hg/hgrc",

		// Debug / Info
		"/phpinfo.php", "/info.php", "/test.php", "/pi.php",
		"/debug", "/debug/vars", "/debug/pprof", "/debug/default/view",
		"/server-status", "/server-info",
		"/_profiler", "/_debugbar",

		// Spring Boot Actuator
		"/actuator", "/actuator/env", "/actuator/health",
		"/actuator/configprops", "/actuator/mappings",
		"/actuator/beans", "/actuator/heapdump", "/actuator/threaddump",
		"/actuator/loggers", "/actuator/info", "/actuator/metrics",
		"/manage/env", "/manage/health",

		// API configs
		"/api/.env", "/api/config", "/api/debug",
		"/api/v1/config", "/api/v2/config",
		"/api/swagger.json", "/api/openapi.json",

		// API docs
		"/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
		"/swagger/v1/swagger.json", "/swagger-resources",
		"/v2/api-docs", "/v3/api-docs",

		// GraphQL
		"/graphql", "/graphiql", "/altair", "/playground",

		// Admin panels
		"/console", "/adminer.php", "/phpmyadmin",
		"/admin", "/admin/config", "/_admin",
		"/wp-admin", "/wp-login.php",

		// .NET
		"/elmah.axd", "/trace.axd",
		"/web.config", "/web.config.bak",
		"/appsettings.json", "/appsettings.Development.json",

		// Meta
		"/robots.txt", "/sitemap.xml", "/security.txt",
		"/.well-known/security.txt", "/.well-known/openid-configuration",
		"/crossdomain.xml",

		// Backups
		"/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
		"/backup.zip", "/backup.tar.gz", "/site.tar.gz",
		"/www.zip", "/public.zip", "/src.zip",
		"/db.sqlite", "/db.sqlite3", "/database.sqlite",

		// Config files
		"/config.yml", "/config.yaml", "/config.json", "/config.toml",
		"/docker-compose.yml", "/Dockerfile", "/.dockerenv",
		"/composer.json", "/package.json", "/yarn.lock", "/.npmrc",
		"/requirements.txt", "/Pipfile", "/Gemfile",
		"/go.mod", "/Cargo.toml",

		// CI/CD
		"/.github/workflows", "/.gitlab-ci.yml", "/.travis.yml",
		"/Jenkinsfile", "/.circleci/config.yml",

		// Cloud / credentials
		"/.aws/credentials", "/.aws/config",
		"/credentials.json", "/serviceAccountKey.json",
		"/service-account.json", "/gcloud-service-key.json",
		"/firebase.json", "/.firebaserc",
		"/terraform.tfstate", "/terraform.tfvars",

		// Kubernetes
		"/kube-config", "/.kube/config",

		// System files
		"/.DS_Store", "/.htaccess", "/.htpasswd",
		"/id_rsa", "/id_dsa", "/id_ed25519",
		"/proc/self/environ", "/proc/self/cmdline",
		"/etc/passwd", "/etc/shadow",

		// Node / Next
		"/next.config.js", "/nuxt.config.js",
		"/.next/server/pages-manifest.json",
		"/.next/build-manifest.json",
		"/node_modules/.package-lock.json",

		// Laravel / Django / Rails
		"/.env.forge", "/storage/logs/laravel.log",
		"/settings.py", "/local_settings.py",
		"/config/database.yml", "/config/secrets.yml",
		"/config/master.key", "/config/credentials.yml.enc",
	}
	cleaned := cleanDedup(paths)
	pl.wordlists["default"] = cleaned
	return len(cleaned)
}

func (pl *PathLoader) GetAllPaths() []string {
	seen := make(map[string]bool)
	var all []string
	for _, paths := range pl.wordlists {
		for _, p := range paths {
			if !seen[p] {
				seen[p] = true
				all = append(all, p)
			}
		}
	}
	sort.Strings(all)
	return all
}

func cleanDedup(paths []string) []string {
	seen := make(map[string]bool)
	var cleaned []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if !seen[p] {
			seen[p] = true
			cleaned = append(cleaned, p)
		}
	}
	sort.Strings(cleaned)
	return cleaned
}
