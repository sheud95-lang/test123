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
		"/.env", "/.env.local", "/.env.production", "/.env.backup",
		"/.env.old", "/.env.save", "/.env.bak", "/.env.dev",
		"/.env.staging", "/.env.example",
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-config.php.save", "/wp-config.txt",
		"/config.php", "/config.php.bak", "/config.inc.php",
		"/configuration.php", "/settings.php",
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/logs/HEAD", "/.git/refs/heads/master", "/.git/refs/heads/main",
		"/.gitignore",
		"/.svn/entries", "/.svn/wc.db",
		"/phpinfo.php", "/info.php", "/test.php",
		"/debug", "/debug/vars", "/debug/pprof",
		"/server-status", "/server-info",
		"/actuator", "/actuator/env", "/actuator/health",
		"/actuator/configprops", "/actuator/mappings",
		"/api/.env", "/api/config", "/api/debug",
		"/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
		"/graphql", "/graphiql",
		"/console", "/adminer.php",
		"/elmah.axd", "/trace.axd",
		"/web.config", "/web.config.bak",
		"/robots.txt", "/sitemap.xml", "/security.txt",
		"/.well-known/security.txt",
		"/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
		"/backup.zip", "/backup.tar.gz",
		"/config.yml", "/config.yaml", "/config.json",
		"/docker-compose.yml", "/Dockerfile", "/.dockerenv",
		"/composer.json", "/package.json", "/yarn.lock", "/.npmrc",
		"/requirements.txt", "/Pipfile",
		"/go.mod", "/Cargo.toml",
		"/.DS_Store", "/.htaccess", "/.htpasswd",
		"/id_rsa", "/id_dsa", "/id_ed25519",
		"/proc/self/environ", "/proc/self/cmdline",
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
