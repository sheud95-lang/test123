package validators

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reaper/internal/core"
	"reaper/internal/extractors"
)

type validationTask struct {
	sourceURL string
	secrets   []extractors.Secret
}

type Validator struct {
	client       *http.Client
	treasure     *core.TreasureWriter
	queue        chan validationTask
	stop         chan struct{}
	wg           sync.WaitGroup
	seen         map[string]bool // dedup: don't validate same key twice
	mu           sync.Mutex
	ValidCount   int64 // atomic: successfully validated
	InvalidCount int64 // atomic: validation failed (key invalid)
	PendingCount int64 // atomic: in queue / in-flight
}

func NewValidator(tw *core.TreasureWriter) *Validator {
	return &Validator{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 5,
			},
		},
		treasure: tw,
		queue:    make(chan validationTask, 1000),
		stop:     make(chan struct{}),
		seen:     make(map[string]bool),
	}
}

func (v *Validator) Run() {
	sem := make(chan struct{}, 5) // max 5 concurrent validations
	for {
		select {
		case task := <-v.queue:
			v.wg.Add(1)
			sem <- struct{}{}
			go func(t validationTask) {
				defer v.wg.Done()
				defer func() { <-sem }()
				v.processTask(t)
			}(task)
		case <-v.stop:
			// Drain remaining tasks
			close(v.queue)
			for task := range v.queue {
				v.processTask(task)
			}
			v.wg.Wait()
			return
		}
	}
}

func (v *Validator) Stop() {
	close(v.stop)
	v.wg.Wait()
}

func (v *Validator) ValidateSecrets(sourceURL string, secrets []extractors.Secret) {
	atomic.AddInt64(&v.PendingCount, 1)
	select {
	case v.queue <- validationTask{sourceURL: sourceURL, secrets: secrets}:
	default:
		atomic.AddInt64(&v.PendingCount, -1) // dropped
	}
}

func (v *Validator) Stats() (valid, invalid, pending int64) {
	return atomic.LoadInt64(&v.ValidCount), atomic.LoadInt64(&v.InvalidCount), atomic.LoadInt64(&v.PendingCount)
}

func (v *Validator) markSeen(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen[key] {
		return true
	}
	v.seen[key] = true
	return false
}

func (v *Validator) processTask(task validationTask) {
	defer atomic.AddInt64(&v.PendingCount, -1)

	// Group secrets by type for pairing (AWS, Twilio)
	byType := make(map[string][]extractors.Secret)
	for _, s := range task.secrets {
		byType[s.Type] = append(byType[s.Type], s)
	}

	for _, s := range task.secrets {
		if v.markSeen(s.Type + ":" + s.Value) {
			continue
		}

		var valid bool
		var detail string

		switch {
		// === AWS: need to pair access key + secret key ===
		case s.Type == "AWS_ACCESS_KEY":
			secretKeys := byType["AWS_SECRET_KEY"]
			if len(secretKeys) > 0 {
				valid, detail = v.validateAWS(s.Value, secretKeys[0].Value)
			}
		case s.Type == "AWS_SECRET_KEY":
			continue // handled when processing ACCESS_KEY

		// === GitHub ===
		case s.Service == "github" && (strings.HasPrefix(s.Value, "ghp_") || strings.HasPrefix(s.Value, "gho_") ||
			strings.HasPrefix(s.Value, "ghu_") || strings.HasPrefix(s.Value, "ghs_") ||
			strings.HasPrefix(s.Value, "ghr_") || strings.HasPrefix(s.Value, "github_pat_")):
			valid, detail = v.validateBearer("https://api.github.com/user", s.Value, "token")

		// === GitLab ===
		case s.Service == "gitlab" && strings.HasPrefix(s.Value, "glpat-"):
			valid, detail = v.validateGitLab(s.Value)

		// === Stripe ===
		case s.Service == "stripe" && (strings.HasPrefix(s.Value, "sk_live_") || strings.HasPrefix(s.Value, "sk_test_")):
			valid, detail = v.validateBasicAuth("https://api.stripe.com/v1/charges?limit=1", s.Value, "")

		// === Slack ===
		case s.Service == "slack" && (strings.HasPrefix(s.Value, "xoxb-") || strings.HasPrefix(s.Value, "xoxp-")):
			valid, detail = v.validateSlack(s.Value)

		// === SendGrid ===
		case s.Service == "sendgrid" && strings.HasPrefix(s.Value, "SG."):
			valid, detail = v.validateBearer("https://api.sendgrid.com/v3/scopes", s.Value, "Bearer")

		// === Telegram ===
		case s.Service == "telegram":
			valid, detail = v.validateTelegram(s.Value)

		// === OpenAI ===
		case s.Service == "openai":
			valid, detail = v.validateBearer("https://api.openai.com/v1/models", s.Value, "Bearer")

		// === Anthropic ===
		case s.Service == "anthropic" && strings.HasPrefix(s.Value, "sk-ant-"):
			valid, detail = v.validateAnthropic(s.Value)

		// === Mailgun ===
		case s.Service == "mailgun" && strings.HasPrefix(s.Value, "key-"):
			valid, detail = v.validateBasicAuth("https://api.mailgun.net/v3/domains", "api", s.Value)

		// === HuggingFace ===
		case s.Service == "huggingface" && strings.HasPrefix(s.Value, "hf_"):
			valid, detail = v.validateBearer("https://huggingface.co/api/whoami-v2", s.Value, "Bearer")

		// === DigitalOcean ===
		case s.Service == "digitalocean" && strings.HasPrefix(s.Value, "dop_v1_"):
			valid, detail = v.validateBearer("https://api.digitalocean.com/v2/account", s.Value, "Bearer")

		// === Postmark ===
		case s.Service == "postmark":
			valid, detail = v.validatePostmark(s.Value)

		// === Brevo (Sendinblue) ===
		case s.Service == "brevo" && strings.HasPrefix(s.Value, "xkeysib-"):
			valid, detail = v.validateBrevo(s.Value)

		// === Twilio ===
		case s.Type == "TWILIO_ACCOUNT_SID":
			authTokens := byType["TWILIO_AUTH_TOKEN"]
			if len(authTokens) > 0 {
				url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s.json", s.Value)
				valid, detail = v.validateBasicAuth(url, s.Value, authTokens[0].Value)
			}
		case s.Type == "TWILIO_AUTH_TOKEN":
			continue // handled when processing ACCOUNT_SID

		// === NPM ===
		case s.Service == "npm" && strings.HasPrefix(s.Value, "npm_"):
			valid, detail = v.validateBearer("https://registry.npmjs.org/-/whoami", s.Value, "Bearer")

		// === Heroku ===
		case s.Service == "heroku":
			valid, detail = v.validateHeroku(s.Value)

		// === Shopify ===
		case s.Service == "shopify" && strings.HasPrefix(s.Value, "shpat_"):
			// Can't validate without store URL
			continue

		default:
			continue // skip non-validatable secrets
		}

		if valid {
			atomic.AddInt64(&v.ValidCount, 1)
			log.Printf("[VALID] %s %s: %s (%s)", s.Service, s.Type, s.Value[:min(len(s.Value), 20)]+"...", detail)
			v.treasure.WriteValid(task.sourceURL, s.Service, s.Value, fmt.Sprintf("%s — %s", s.Type, detail))
		} else {
			atomic.AddInt64(&v.InvalidCount, 1)
			log.Printf("[INVALID] %s %s: %s", s.Service, s.Type, s.Value[:min(len(s.Value), 20)]+"...")
		}
	}
}

// === Validation methods ===

func (v *Validator) validateBearer(url, token, scheme string) (bool, string) {
	req, _ := http.NewRequest("GET", url, nil)
	if scheme == "token" {
		req.Header.Set("Authorization", "token "+token)
	} else {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		// Try to extract username/email from response
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			for _, field := range []string{"login", "username", "email", "name", "id"} {
				if val, ok := data[field]; ok && val != nil {
					return true, fmt.Sprintf("%s: %v", field, val)
				}
			}
		}
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validateBasicAuth(url, user, pass string) (bool, string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pass)
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 1024))

	if resp.StatusCode == 200 {
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validateGitLab(token string) (bool, string) {
	req, _ := http.NewRequest("GET", "https://gitlab.com/api/v4/user", nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if user, ok := data["username"]; ok {
				return true, fmt.Sprintf("user: %v", user)
			}
		}
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validateSlack(token string) (bool, string) {
	req, _ := http.NewRequest("POST", "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var data struct {
		OK   bool   `json:"ok"`
		Team string `json:"team"`
		User string `json:"user"`
	}
	if json.Unmarshal(body, &data) == nil && data.OK {
		return true, fmt.Sprintf("team: %s, user: %s", data.Team, data.User)
	}
	return false, ""
}

func (v *Validator) validateTelegram(token string) (bool, string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", token)
	resp, err := v.client.Get(url)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var data struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &data) == nil && data.OK {
		return true, fmt.Sprintf("bot: @%s", data.Result.Username)
	}
	return false, ""
}

func (v *Validator) validateAnthropic(key string) (bool, string) {
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 1024))

	if resp.StatusCode == 200 {
		return true, "API key valid"
	}
	return false, ""
}

func (v *Validator) validateHeroku(token string) (bool, string) {
	req, _ := http.NewRequest("GET", "https://api.heroku.com/account", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	req.Header.Set("User-Agent", "Reaper-Validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if email, ok := data["email"]; ok {
				return true, fmt.Sprintf("email: %v", email)
			}
		}
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validatePostmark(token string) (bool, string) {
	req, _ := http.NewRequest("GET", "https://api.postmarkapp.com/server", nil)
	req.Header.Set("X-Postmark-Server-Token", token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if name, ok := data["Name"]; ok {
				return true, fmt.Sprintf("server: %v", name)
			}
		}
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validateBrevo(apiKey string) (bool, string) {
	req, _ := http.NewRequest("GET", "https://api.brevo.com/v3/account", nil)
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if email, ok := data["email"]; ok {
				return true, fmt.Sprintf("email: %v", email)
			}
		}
		return true, "HTTP 200"
	}
	return false, ""
}

func (v *Validator) validateAWS(accessKey, secretKey string) (bool, string) {
	// AWS STS GetCallerIdentity with Signature V4
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")
	region := "us-east-1"
	service := "sts"
	host := "sts.amazonaws.com"

	// Create canonical request
	method := "POST"
	canonicalURI := "/"
	canonicalQuerystring := ""
	payload := "Action=GetCallerIdentity&Version=2011-06-15"
	payloadHash := sha256Hex(payload)

	canonicalHeaders := fmt.Sprintf("content-type:application/x-www-form-urlencoded\nhost:%s\nx-amz-date:%s\n", host, amzdate)
	signedHeaders := "content-type;host;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalURI, canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash)

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm, amzdate, credentialScope, sha256Hex(canonicalRequest))

	// Calculate signature
	signingKey := getSignatureKey(secretKey, datestamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, accessKey, credentialScope, signedHeaders, signature)

	req, _ := http.NewRequest("POST", "https://"+host, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzdate)
	req.Header.Set("Authorization", authHeader)

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 {
		bodyStr := string(body)
		// Extract account ID from XML response
		if idx := strings.Index(bodyStr, "<Account>"); idx >= 0 {
			end := strings.Index(bodyStr[idx:], "</Account>")
			if end > 0 {
				account := bodyStr[idx+9 : idx+end]
				return true, fmt.Sprintf("account: %s", account)
			}
		}
		return true, "credentials valid"
	}
	return false, ""
}

// AWS Signature V4 helpers
func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func getSignatureKey(key, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+key), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
