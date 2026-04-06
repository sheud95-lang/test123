package extractors

import (
	"regexp"
	"strings"
)

type Secret struct {
	Type      string
	Value     string
	KeyName   string
	Context   string
	SourceURL string
	Line      int
	Service   string
	RawLine   string
}

type secretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Group      int
	Service    string
	QuickCheck string // fast pre-filter: lowercase line must contain this before regex runs
}

var secretPatterns []secretPattern

func init() {
	type def struct {
		name, pattern, service, quick string
		group                         int
	}
	defs := []def{
		// AWS
		{"AWS_ACCESS_KEY", `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`, "aws", "aki", 0},
		{"AWS_SECRET_KEY", `(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`, "aws", "aws_secret", 1},
		{"AWS_SESSION_TOKEN", `(?i)AWS_SESSION_TOKEN\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?`, "aws", "aws_session", 1},
		{"AWS_MWS_KEY", `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, "aws", "amzn.mws.", 0},

		// Google / GCP
		{"GOOGLE_API_KEY", `AIza[0-9A-Za-z_-]{35}`, "google", "aiza", 0},
		{"GOOGLE_OAUTH", `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, "google", "googleusercontent.com", 0},
		{"GCP_SERVICE_ACCOUNT", `"type"\s*:\s*"service_account"`, "gcp", "service_account", 0},
		{"GCP_OAUTH_SECRET", `GOCSPX-[A-Za-z0-9_-]{28}`, "google", "gocspx-", 0},

		// Azure
		{"AZURE_CLIENT_SECRET", `(?i)(?:AZURE_CLIENT_SECRET|AZURE_AD_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,})['"]?`, "azure", "azure_client_secret", 1},
		{"AZURE_STORAGE_KEY", `(?i)(?:AZURE_STORAGE_KEY|AZURE_STORAGE_ACCOUNT_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?`, "azure", "azure_storage", 1},
		{"AZURE_CONNECTION_STRING", `DefaultEndpointsProtocol=https?;AccountName=[^;]{3,63};AccountKey=[A-Za-z0-9+/]{86}==`, "azure", "defaultendpointsprotocol=", 0},

		// DigitalOcean
		{"DIGITALOCEAN_TOKEN", `\bdop_v1_[a-f0-9]{64}\b`, "digitalocean", "dop_v1_", 0},
		{"DIGITALOCEAN_REFRESH", `\bdor_v1_[a-f0-9]{64}\b`, "digitalocean", "dor_v1_", 0},

		// GitHub
		{"GITHUB_PAT", `\bgithub_pat_[A-Za-z0-9_]{36,255}\b`, "github", "github_pat_", 0},
		{"GITHUB_OAUTH", `\bgho_[A-Za-z0-9]{36,255}\b`, "github", "gho_", 0},
		{"GITHUB_USER_TOKEN", `\bghu_[A-Za-z0-9]{36,255}\b`, "github", "ghu_", 0},
		{"GITHUB_SERVER_TOKEN", `\bghs_[A-Za-z0-9]{36,255}\b`, "github", "ghs_", 0},
		{"GITHUB_REFRESH", `\bghr_[A-Za-z0-9]{36,255}\b`, "github", "ghr_", 0},
		{"GITHUB_CLASSIC", `\bghp_[A-Za-z0-9]{36,255}\b`, "github", "ghp_", 0},

		// GitLab
		{"GITLAB_PAT", `\bglpat-[A-Za-z0-9_-]{20,}\b`, "gitlab", "glpat-", 0},
		{"GITLAB_PIPELINE", `\bglptt-[A-Za-z0-9_-]{20,}\b`, "gitlab", "glptt-", 0},
		{"GITLAB_RUNNER", `\bGR1348941[A-Za-z0-9_-]{20,}\b`, "gitlab", "gr1348941", 0},

		// Slack
		{"SLACK_BOT_TOKEN", `\bxoxb-[A-Za-z0-9-]{10,}\b`, "slack", "xoxb-", 0},
		{"SLACK_USER_TOKEN", `\bxoxp-[A-Za-z0-9-]{10,}\b`, "slack", "xoxp-", 0},
		{"SLACK_APP_TOKEN", `\bxapp-[A-Za-z0-9-]{10,}\b`, "slack", "xapp-", 0},
		{"SLACK_WEBHOOK", `https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`, "slack", "hooks.slack.com", 0},

		// Telegram
		{"TELEGRAM_BOT_TOKEN", `\b\d{8,12}:AA[A-Za-z0-9_-]{33,35}\b`, "telegram", ":aa", 0},

		// Stripe
		{"STRIPE_SECRET_KEY", `\bsk_live_[A-Za-z0-9]{24,}\b`, "stripe", "sk_live_", 0},
		{"STRIPE_RESTRICTED_KEY", `\brk_live_[A-Za-z0-9]{24,}\b`, "stripe", "rk_live_", 0},
		{"STRIPE_WEBHOOK_SECRET", `\bwhsec_[A-Za-z0-9]{32,}\b`, "stripe", "whsec_", 0},
		{"STRIPE_TEST_SECRET", `\bsk_test_[A-Za-z0-9]{24,}\b`, "stripe", "sk_test_", 0},

		// PayPal
		{"PAYPAL_CLIENT_ID", `(?i)PAYPAL_CLIENT_ID\s*[=:]\s*['"]?(A[A-Za-z0-9_-]{60,80})['"]?`, "paypal", "paypal_client_id", 1},
		{"PAYPAL_SECRET", `(?i)(?:PAYPAL_SECRET|PAYPAL_CLIENT_SECRET)\s*[=:]\s*['"]?(E[A-Za-z0-9_-]{60,80})['"]?`, "paypal", "paypal_", 1},

		// Square
		{"SQUARE_ACCESS_TOKEN", `\bsq0atp-[A-Za-z0-9_-]{22}\b`, "square", "sq0atp-", 0},
		{"SQUARE_OAUTH_SECRET", `\bsq0csp-[A-Za-z0-9_-]{43}\b`, "square", "sq0csp-", 0},

		// Twilio
		{"TWILIO_ACCOUNT_SID", `(?i)(?:twilio|account.?sid|ACCOUNT_SID)\s*[=:]\s*['"]?(AC[0-9a-f]{32})['"]?`, "twilio", "", 1},
		{"TWILIO_AUTH_TOKEN", `(?i)(?:TWILIO_AUTH_TOKEN|TWILIO_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`, "twilio", "twilio", 1},

		// SendGrid
		{"SENDGRID_KEY", `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`, "sendgrid", "sg.", 0},

		// Mailgun
		{"MAILGUN_KEY", `\bkey-[a-f0-9]{32}\b`, "mailgun", "key-", 0},

		// Mailchimp
		{"MAILCHIMP_KEY", `\b[a-f0-9]{32}-us\d{1,2}\b`, "mailchimp", "-us", 0},

		// OpenAI
		{"OPENAI_KEY", `\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b`, "openai", "t3blbkfj", 0},
		{"OPENAI_KEY_V2", `\bsk-proj-[A-Za-z0-9_-]{40,}\b`, "openai", "sk-proj-", 0},

		// Anthropic
		{"ANTHROPIC_KEY", `\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{30,}\b`, "anthropic", "sk-ant-api", 0},

		// Grok / xAI
		{"GROK_KEY", `\bxai-[A-Za-z0-9_-]{30,}\b`, "grok", "xai-", 0},

		// HuggingFace
		{"HUGGINGFACE_TOKEN", `\bhf_[A-Za-z0-9]{20,}\b`, "huggingface", "hf_", 0},

		// Replicate
		{"REPLICATE_TOKEN", `\br8_[A-Za-z0-9]{36,}\b`, "replicate", "r8_", 0},

		// Shopify
		{"SHOPIFY_ACCESS_TOKEN", `shpat_[A-Za-z0-9]{32}`, "shopify", "shpat_", 0},
		{"SHOPIFY_PRIVATE_APP", `shpca_[A-Za-z0-9]{32}`, "shopify", "shpca_", 0},
		{"SHOPIFY_CUSTOM_APP", `shpcb_[A-Za-z0-9]{32}`, "shopify", "shpcb_", 0},
		{"SHOPIFY_SHARED_SECRET", `shpss_[A-Za-z0-9]{32}`, "shopify", "shpss_", 0},

		// Heroku
		{"HEROKU_API_KEY", `(?i)heroku[_-]?(?:api[_-]?)?key\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`, "heroku", "heroku", 1},

		// Firebase
		{"FIREBASE_URL", `https://[a-z0-9_-]{3,30}\.firebaseio\.com`, "firebase", "firebaseio.com", 0},
		{"FIREBASE_SERVER_KEY", `(?i)(?:server[_-]?key|fcm[_-]?key)\s*[=:]\s*['"]?(AAAA[A-Za-z0-9_-]{140,300})['"]?`, "firebase", "aaaa", 1},

		// Cloudflare
		{"CLOUDFLARE_API_TOKEN", `(?i)(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?`, "cloudflare", "api_token", 1},

		// Datadog
		{"DATADOG_API_KEY", `(?i)(?:DD_API_KEY|DATADOG_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`, "datadog", "api_key", 1},

		// New Relic
		{"NEWRELIC_API_KEY", `\bNRAK-[A-Z0-9]{27}\b`, "newrelic", "nrak-", 0},

		// Sentry
		{"SENTRY_DSN", `https://[a-f0-9]{32}@(?:o\d+\.)?(?:ingest\.)?sentry\.io/\d+`, "sentry", "sentry.io", 0},

		// Grafana
		{"GRAFANA_API_KEY", `\bglsa_[A-Za-z0-9_-]{32,}_[0-9a-f]{8}\b`, "grafana", "glsa_", 0},
		{"GRAFANA_CLOUD_KEY", `\bglc_[A-Za-z0-9_-]{32,}\b`, "grafana", "glc_", 0},

		// Vault
		{"VAULT_TOKEN", `\bhv[sb]\.[A-Za-z0-9]{24,100}\b`, "vault", "hv", 0},

		// NPM / PyPI
		{"NPM_TOKEN", `\bnpm_[A-Za-z0-9]{36,}\b`, "npm", "npm_", 0},
		{"PYPI_TOKEN", `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`, "pypi", "pypi-", 0},

		// Mapbox
		{"MAPBOX_TOKEN", `\bpk\.[A-Za-z0-9_-]{60,}\b`, "mapbox", "pk.", 0},

		// PlanetScale
		{"PLANETSCALE_TOKEN", `\bpscale_tkn_[A-Za-z0-9_-]{32,}\b`, "planetscale", "pscale_tkn_", 0},
		{"PLANETSCALE_PASSWORD", `\bpscale_pw_[A-Za-z0-9_-]{32,}\b`, "planetscale", "pscale_pw_", 0},

		// Supabase
		{"SUPABASE_KEY", `(?i)(?:SUPABASE_KEY|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_ANON_KEY)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{100,})['"]?`, "supabase", "supabase", 1},

		// Private Key — re-enabled with context-aware FP filtering
		{"PRIVATE_KEY", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`, "private_key", "private key", 0},

		// Vercel
		{"VERCEL_TOKEN", `(?i)(?:VERCEL_TOKEN|VERCEL_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?`, "vercel", "vercel_", 1},

		// Netlify
		{"NETLIFY_TOKEN", `(?i)(?:NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?`, "netlify", "netlify_", 1},

		// Doppler
		{"DOPPLER_TOKEN", `\bdp\.(?:pt|sa|ct)\.[A-Za-z0-9]{40,}\b`, "doppler", "dp.", 0},

		// Linear
		{"LINEAR_API_KEY", `\blin_api_[A-Za-z0-9]{36,}\b`, "linear", "lin_api_", 0},

		// Airtable — require mixed case (real keys: keyXXXXXXXXXXXXXX with mixed alphanumeric)
		{"AIRTABLE_API_KEY", `(?i)(?:AIRTABLE_API_KEY|AIRTABLE_KEY)\s*[=:]\s*['"]?(key[A-Za-z0-9]{14})['"]?`, "airtable", "airtable", 1},

		// Notion — use ntn_ prefix (new format) or require env var context
		{"NOTION_TOKEN", `\bntn_[A-Za-z0-9]{40,}\b`, "notion", "ntn_", 0},
		{"NOTION_TOKEN_V2", `(?i)(?:NOTION_TOKEN|NOTION_API_KEY|NOTION_SECRET)\s*[=:]\s*['"]?(secret_[A-Za-z0-9]{43})['"]?`, "notion", "notion", 1},

		// Coinbase
		{"COINBASE_API_KEY", `(?i)(?:COINBASE_API_KEY|CB_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{16,})['"]?`, "coinbase", "coinbase", 1},

		// JWT
		{"JWT_SECRET", `(?i)(?:JWT_SECRET|JWT_KEY|JWT_PRIVATE_KEY|JWT_SECRET_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_+/=.\-]{16,})['"]?`, "jwt", "jwt_", 1},
		{"JWT_TOKEN", `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`, "jwt", "eyj", 0},

		// Laravel
		{"LARAVEL_APP_KEY", `(?i)APP_KEY\s*[=:]\s*['"]?(base64:[A-Za-z0-9+/=]{20,})['"]?`, "laravel", "app_key", 1},

		// Django
		{"DJANGO_SECRET_KEY", `(?i)(?:DJANGO_SECRET_KEY|SECRET_KEY)\s*[=:]\s*['"]?([A-Za-z0-9!@#$%^&*()\-_=+]{50,})['"]?`, "django", "secret_key", 1},

		// Stripe publishable (less sensitive but reveals integration)
		{"STRIPE_PUBLISHABLE_KEY", `\bpk_live_[A-Za-z0-9]{24,}\b`, "stripe", "pk_live_", 0},
		{"STRIPE_TEST_PUBLISHABLE", `\bpk_test_[A-Za-z0-9]{24,}\b`, "stripe", "pk_test_", 0},

		// Postmark
		{"POSTMARK_SERVER_TOKEN", `(?i)(?:POSTMARK_SERVER_TOKEN|POSTMARK_API_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`, "postmark", "postmark", 1},

		// Brevo (Sendinblue)
		{"BREVO_API_KEY", `\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b`, "brevo", "xkeysib-", 0},

		// Resend
		{"RESEND_API_KEY", `\bre_[A-Za-z0-9]{30,}\b`, "resend", "re_", 0},

		// Elastic Email
		{"ELASTIC_EMAIL_KEY", `(?i)(?:ELASTIC_EMAIL_API_KEY|ELASTICEMAIL_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9-]{36,})['"]?`, "elastic_email", "elastic", 1},

		// Database connection strings (contain embedded credentials)
		{"DATABASE_URL_POSTGRES", `postgres(?:ql)?://[^\s<>"']{10,}`, "database", "postgres", 0},
		{"DATABASE_URL_MYSQL", `mysql://[^\s<>"']{10,}`, "database", "mysql://", 0},
		{"DATABASE_URL_MONGODB", `mongodb(?:\+srv)?://[^\s<>"']{10,}`, "database", "mongodb", 0},
		{"DATABASE_URL_REDIS", `redis(?:s)?://[^\s<>"']{10,}`, "database", "redis://", 0},
		{"DATABASE_URL_AMQP", `amqps?://[^\s<>"']{10,}`, "database", "amqp", 0},

		// SMTP — extended patterns
		{"SMTP_URL", `smtps?://[^\s<>"']+`, "smtp", "smtp://", 0},
		{"SMTP_HOST", `(?i)(?:SMTP|MAIL|EMAIL)_(?:HOST|SERVER)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?`, "smtp", "", 1},
		{"SMTP_USER", `(?i)(?:SMTP|MAIL|EMAIL)_(?:USER(?:NAME)?)\s*[=:]\s*['"]?([^\s'"]{3,})['"]?`, "smtp", "", 1},
		{"SMTP_PASS", `(?i)(?:SMTP|MAIL|EMAIL)_(?:PASS(?:WORD)?)\s*[=:]\s*['"]?([^\s'"]{3,})['"]?`, "smtp", "", 1},
		{"SMTP_PORT", `(?i)(?:SMTP|MAIL|EMAIL)_PORT\s*[=:]\s*['"]?(\d{2,5})['"]?`, "smtp", "", 1},
		{"MAILER_DSN", `(?i)MAILER_(?:DSN|URL)\s*[=:]\s*['"]?((?:smtp|sendmail|ses\+smtp)s?://[^\s'"]+)['"]?`, "smtp", "mailer_", 1},

		// Generic secret (catch-all for SECRET=xxx, TOKEN=xxx, PASSWORD=xxx, API_KEY=xxx)
		{"GENERIC_SECRET", `(?i)(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`, "", "", 1},

		// Basic Auth / Bearer
		{"BASIC_AUTH", `(?i)Basic\s+([A-Za-z0-9+/]{20,}=*)`, "auth", "basic ", 1},
		{"BEARER_TOKEN", `(?i)Bearer\s+([A-Za-z0-9_\-.]{20,}={0,2})`, "auth", "bearer ", 1},
	}

	for _, d := range defs {
		re, err := regexp.Compile(d.pattern)
		if err != nil {
			continue
		}
		secretPatterns = append(secretPatterns, secretPattern{
			Name: d.name, Pattern: re, Group: d.group, Service: d.service,
			QuickCheck: d.quick,
		})
	}
}

var servicePrefixes = []struct {
	Prefix, Service string
}{
	{"sk_live_", "stripe"}, {"rk_live_", "stripe"},
	{"sk_test_", "stripe"}, {"whsec_", "stripe"},
	{"sk-ant-", "anthropic"}, {"sk-proj-", "openai"},
	{"xai-", "grok"}, {"hf_", "huggingface"}, {"r8_", "replicate"},
	{"ghp_", "github"}, {"gho_", "github"}, {"ghu_", "github"},
	{"ghs_", "github"}, {"ghr_", "github"}, {"github_pat_", "github"},
	{"glpat-", "gitlab"}, {"glptt-", "gitlab"},
	{"xoxb-", "slack"}, {"xoxp-", "slack"}, {"xapp-", "slack"},
	{"AKIA", "aws"}, {"ASIA", "aws"},
	{"SG.", "sendgrid"}, {"key-", "mailgun"},
	{"AC", "twilio"},
	{"shpat_", "shopify"}, {"shpca_", "shopify"},
	{"dop_v1_", "digitalocean"}, {"dor_v1_", "digitalocean"},
	{"npm_", "npm"}, {"pypi-", "pypi"},
	{"AIza", "google"}, {"GOCSPX-", "google"},
	{"hvs.", "vault"}, {"hvb.", "vault"},
	{"glsa_", "grafana"}, {"glc_", "grafana"},
	{"NRAK-", "newrelic"},
	{"pscale_tkn_", "planetscale"}, {"pscale_pw_", "planetscale"},
	{"sq0atp-", "square"}, {"sq0csp-", "square"},
	{"base64:", "laravel"},
	{"pk_live_", "stripe"}, {"pk_test_", "stripe"},
	{"xkeysib-", "brevo"},
	{"re_", "resend"},
	{"smtp://", "smtp"}, {"smtps://", "smtp"},
	{"postgres://", "database"}, {"postgresql://", "database"},
	{"mysql://", "database"}, {"mongodb://", "database"}, {"mongodb+srv://", "database"},
	{"redis://", "database"}, {"rediss://", "database"},
	{"amqp://", "database"}, {"amqps://", "database"},
	{"dp.pt.", "doppler"}, {"dp.sa.", "doppler"}, {"dp.ct.", "doppler"},
	{"lin_api_", "linear"},
	{"ntn_", "notion"},
}

func DetectServiceFromValue(value string) string {
	for _, sp := range servicePrefixes {
		if strings.HasPrefix(value, sp.Prefix) {
			return sp.Service
		}
	}
	if strings.HasPrefix(value, "sk-") && len(value) > 30 &&
		!strings.HasPrefix(value, "sk-ant-") &&
		!strings.HasPrefix(value, "sk-proj-") {
		return "openai"
	}
	return ""
}

var fpWords = []string{
	"example", "test", "dummy", "placeholder", "changeme",
	"xxx", "yyy", "zzz", "todo", "fixme", "insert", "replace",
	"0000000000", "1111111111", "abcdef", "123456",
	"your_", "your-", "enter_", "enter-", "put_", "put-",
}

// Exact values that are always false positives (lowercase)
var fpExact = map[string]bool{
	"null": true, "true": true, "false": true,
	"none": true, "undefined": true, "empty": true,
	"mailpit": true, "localhost": true, "127.0.0.1": true,
	"smtp": true, "tls": true, "ssl": true, "starttls": true,
}

// Private key context words that indicate documentation/example, not real keys
var privateKeyFPContext = []string{
	"example", "sample", "documentation", "swagger", "api-docs",
	"redoc", "openapi", "specification", "schema", "tutorial",
	"readme", "how-to", "guide", "demo", "placeholder",
}

// URL paths that indicate test/fixture files
var privateKeyFPPaths = []string{
	"/fixtures/", "/testdata/", "/mock/", "/test/", "/spec/",
	"test.pem", "example.pem", "fake.pem", "dummy.pem",
}

func isPrivateKeyFP(value string, context string) bool {
	ctxLower := strings.ToLower(context)
	for _, w := range privateKeyFPContext {
		if strings.Contains(ctxLower, w) {
			return true
		}
	}
	return false
}

func isPrivateKeyFPByURL(sourceURL string) bool {
	urlLower := strings.ToLower(sourceURL)
	for _, p := range privateKeyFPPaths {
		if strings.Contains(urlLower, p) {
			return true
		}
	}
	return false
}

// isPrivateKeySingleLine checks if the key marker is just a one-line reference
// (documentation) vs a real multiline PEM block
func isPrivateKeySingleLine(lines []string, lineNo int) bool {
	// Check if next line has base64 content (real key body)
	if lineNo+1 < len(lines) {
		nextLine := strings.TrimSpace(lines[lineNo+1])
		// Real PEM keys have base64-encoded data on the next line
		if len(nextLine) > 20 && !strings.HasPrefix(nextLine, "<") && !strings.HasPrefix(nextLine, "//") &&
			!strings.HasPrefix(nextLine, "#") && !strings.HasPrefix(nextLine, "*") {
			return false // likely real key
		}
	}
	return true // single-line marker, likely docs
}

// isCodeLikeValue detects minified JS/code fragments that GENERIC_SECRET catches
// e.g., "e.token,providedIn:", "e,factory:e.\u0275fac})", "!0,image:!0}"
func isCodeLikeValue(value string) bool {
	// Reject values containing code syntax characters
	if strings.ContainsAny(value, "(){};<>|&") {
		return true
	}
	// Arrow functions, commas (object literals)
	if strings.Contains(value, "=>") || strings.Contains(value, ",") {
		return true
	}
	// Comparison operators (JS code)
	if strings.Contains(value, "==") || strings.Contains(value, "!=") {
		return true
	}
	// Contains colon — JS object property like "key:value"
	if strings.Contains(value, ":") {
		return true
	}
	// Starts with code-like chars
	if len(value) > 0 && (value[0] == '!' || value[0] == '=' || value[0] == '~' || value[0] == '?') {
		return true
	}
	// Dot notation: word.word pattern (e.target, renderInputType.number)
	// Allow domain-like dots (smtp.gmail.com has 2+ dots, TLDs)
	if strings.Contains(value, ".") {
		for i := 1; i < len(value)-1; i++ {
			if value[i] == '.' {
				prevIsAlpha := (value[i-1] >= 'a' && value[i-1] <= 'z') || (value[i-1] >= 'A' && value[i-1] <= 'Z')
				nextIsAlpha := (value[i+1] >= 'a' && value[i+1] <= 'z') || (value[i+1] >= 'A' && value[i+1] <= 'Z')
				if prevIsAlpha && nextIsAlpha {
					// Count dots — domains have 2+ dots (smtp.gmail.com), code has 1 (e.target)
					dotCount := strings.Count(value, ".")
					if dotCount < 2 {
						return true
					}
				}
			}
		}
	}
	// Pure alphabetic word under 20 chars → likely a label/keyword, not a secret
	// Real secrets have digits, special chars, or are longer
	allAlpha := true
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127) {
			allAlpha = false
			break
		}
	}
	if allAlpha && len(value) < 20 {
		return true
	}
	return false
}

func isFalsePositive(value string) bool {
	if len(value) < 6 {
		return true
	}
	trimmed := strings.Trim(value, "\"' ")
	lower := strings.ToLower(trimmed)

	// Exact match FP
	if fpExact[lower] {
		return true
	}

	for _, fp := range fpWords {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	unique := make(map[rune]bool)
	for _, r := range trimmed {
		unique[r] = true
	}
	if len(unique) < 3 {
		return true
	}
	if strings.HasPrefix(trimmed, "$") || strings.HasPrefix(trimmed, "%") ||
		strings.Contains(trimmed, "${") || strings.Contains(trimmed, "{{") {
		return true
	}
	return false
}

func ExtractSecrets(text, sourceURL string) []Secret {
	// Skip .example / .sample files — they contain template values
	srcLower := strings.ToLower(sourceURL)
	if strings.Contains(srcLower, ".example") || strings.Contains(srcLower, ".sample") ||
		strings.Contains(srcLower, ".dist") || strings.Contains(srcLower, ".template") {
		return nil
	}

	var results []Secret
	seen := make(map[string]bool)
	lines := strings.Split(text, "\n")

	for lineNo, line := range lines {
		if len(line) < 4 {
			continue
		}
		lineLower := strings.ToLower(line)
		for _, sp := range secretPatterns {
			// Fast pre-filter: skip regex entirely if quick check fails
			if sp.QuickCheck != "" && !strings.Contains(lineLower, sp.QuickCheck) {
				continue
			}
			for _, loc := range sp.Pattern.FindAllStringSubmatchIndex(line, -1) {
				var value string
				if sp.Group > 0 && len(loc) > sp.Group*2+1 {
					start := loc[sp.Group*2]
					end := loc[sp.Group*2+1]
					if start >= 0 && end >= 0 {
						value = line[start:end]
					}
				}
				if value == "" {
					value = line[loc[0]:loc[1]]
				}
				if value == "" || isFalsePositive(value) {
					continue
				}

				// GENERIC_SECRET + SMTP: filter out code-like values (minified JS etc)
				if (sp.Name == "GENERIC_SECRET" || strings.HasPrefix(sp.Name, "SMTP_")) && isCodeLikeValue(value) {
					continue
				}

				// Extra FP checks for private keys
				if sp.Name == "PRIVATE_KEY" {
					// 1. Skip if URL path indicates test/fixture file
					if isPrivateKeyFPByURL(sourceURL) {
						continue
					}
					// 2. Skip if surrounding lines suggest documentation/example
					ctxLines := value
					for d := -3; d <= 3; d++ {
						idx := lineNo + d
						if idx >= 0 && idx < len(lines) {
							ctxLines += " " + lines[idx]
						}
					}
					if isPrivateKeyFP(value, ctxLines) {
						continue
					}
					// 3. Skip single-line markers (docs mention -----BEGIN PRIVATE KEY----- without actual key body)
					if isPrivateKeySingleLine(lines, lineNo) {
						continue
					}
				}

				dedupKey := sp.Name + ":" + value
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				service := sp.Service
				if service == "auth" || service == "" {
					if detected := DetectServiceFromValue(value); detected != "" {
						service = detected
					} else {
						service = sp.Service
					}
				}

				ctxStart := loc[0] - 50
				if ctxStart < 0 {
					ctxStart = 0
				}
				ctxEnd := loc[1] + 50
				if ctxEnd > len(line) {
					ctxEnd = len(line)
				}

				results = append(results, Secret{
					Type:      sp.Name,
					Value:     value,
					Context:   strings.TrimSpace(line[ctxStart:ctxEnd]),
					SourceURL: sourceURL,
					Line:      lineNo + 1,
					Service:   service,
					RawLine:   strings.TrimSpace(line),
				})
			}
		}
	}
	return results
}

var envRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

// envEmptyValues are values that mean "not configured"
var envEmptyValues = map[string]bool{
	"": true, "null": true, "nil": true, "none": true,
	"false": true, "0": true, "undefined": true,
	"changeme": true, "secret": true, "password": true,
}

func ExtractEnvPairs(text, sourceURL string) []Secret {
	// Skip .example / .sample env files — they contain template values
	srcLower := strings.ToLower(sourceURL)
	if strings.Contains(srcLower, ".example") || strings.Contains(srcLower, ".sample") ||
		strings.Contains(srcLower, ".dist") || strings.Contains(srcLower, ".template") {
		return nil
	}

	var results []Secret
	for lineNo, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := envRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		val := strings.Trim(strings.TrimSpace(m[2]), "\"'")
		if val == "" || envEmptyValues[strings.ToLower(val)] {
			continue
		}
		service := DetectServiceFromValue(val)
		if service == "" {
			service = detectServiceFromKey(key)
		}
		results = append(results, Secret{
			Type: key, Value: val, KeyName: key,
			SourceURL: sourceURL, Line: lineNo + 1,
			Service: service, RawLine: line,
		})
	}
	return results
}

func detectServiceFromKey(key string) string {
	upper := strings.ToUpper(key)
	m := []struct {
		pfx []string
		svc string
	}{
		{[]string{"AWS_", "AMAZON_"}, "aws"},
		{[]string{"OPENAI"}, "openai"},
		{[]string{"ANTHROPIC"}, "anthropic"},
		{[]string{"STRIPE"}, "stripe"},
		{[]string{"SENDGRID", "SG_"}, "sendgrid"},
		{[]string{"MAILGUN", "MG_"}, "mailgun"},
		{[]string{"POSTMARK"}, "postmark"},
		{[]string{"BREVO", "SENDINBLUE"}, "brevo"},
		{[]string{"RESEND"}, "resend"},
		{[]string{"ELASTIC_EMAIL"}, "elastic_email"},
		{[]string{"DATABASE_URL", "DB_URL", "DB_CONNECTION", "POSTGRES", "MYSQL_", "MONGO", "REDIS_URL"}, "database"},
		{[]string{"TWILIO"}, "twilio"},
		{[]string{"GITHUB"}, "github"},
		{[]string{"GITLAB"}, "gitlab"},
		{[]string{"SLACK"}, "slack"},
		{[]string{"TELEGRAM"}, "telegram"},
		{[]string{"SMTP_", "MAIL_"}, "smtp"},
		{[]string{"FIREBASE"}, "firebase"},
		{[]string{"CLOUDFLARE", "CF_"}, "cloudflare"},
		{[]string{"HEROKU"}, "heroku"},
		{[]string{"SHOPIFY"}, "shopify"},
		{[]string{"PAYPAL"}, "paypal"},
		{[]string{"DATADOG", "DD_"}, "datadog"},
		{[]string{"SENTRY"}, "sentry"},
		{[]string{"VERCEL"}, "vercel"},
		{[]string{"NETLIFY"}, "netlify"},
		{[]string{"DOPPLER"}, "doppler"},
		{[]string{"LINEAR"}, "linear"},
		{[]string{"AIRTABLE"}, "airtable"},
		{[]string{"NOTION"}, "notion"},
		{[]string{"COINBASE", "CB_"}, "coinbase"},
		{[]string{"DIGITAL_OCEAN", "DO_", "SPACES_"}, "digitalocean"},
		{[]string{"HETZNER", "HCLOUD"}, "hetzner"},
		{[]string{"SUPABASE"}, "supabase"},
		{[]string{"AUTH0"}, "auth0"},
		{[]string{"OKTA"}, "okta"},
		{[]string{"JWT"}, "jwt"},
		{[]string{"LARAVEL", "APP_KEY"}, "laravel"},
		{[]string{"DJANGO"}, "django"},
		{[]string{"GOOGLE_", "GCP_"}, "google"},
		{[]string{"AZURE_"}, "azure"},
	}
	for _, km := range m {
		for _, p := range km.pfx {
			if strings.Contains(upper, p) {
				return km.svc
			}
		}
	}
	return ""
}
