package core

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Backup file extensions to probe
var BackupExtensions = []string{
	".bak", ".backup", ".old", ".orig", ".original",
	".save", ".saved", ".tmp", ".temp", ".copy",
	".1", ".2", "~", ".swp", ".swo",
	".bkp", ".bk", ".bakup", ".back",
}

// Backup file suffixes to try
var BackupSuffixes = []string{
	"_backup", "_bak", "_old", "_copy", "_orig",
	"-backup", "-bak", "-old", "-copy", "-orig",
	".backup", ".bak", ".old", ".copy", ".orig",
}

// API key patterns to detect
var APIKeyPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	// AWS
	{"AWS Access Key", regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`)},
	// Google
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Google OAuth", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	// GitHub
	{"GitHub Token", regexp.MustCompile(`(?i)(gh[ps]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})`)},
	{"GitHub OAuth", regexp.MustCompile(`(?i)github(.{0,20})?['\"][0-9a-zA-Z]{35,40}['\"]`)},
	// Slack
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)},
	// Stripe
	{"Stripe Key", regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`)},
	{"Stripe Key", regexp.MustCompile(`(?i)rk_live_[0-9a-zA-Z]{24}`)},
	// Twilio
	{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	// Mailgun
	{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	// Heroku
	{"Heroku API Key", regexp.MustCompile(`(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]`)},
	// Generic patterns
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?`)},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'"]{8,})['\"]?`)},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.=]+`)},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)},
	{"Base64 Encoded", regexp.MustCompile(`(?i)(auth|token|key|secret|password).*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]`)},
}

// AJAX/XHR patterns to extract from JavaScript
var AJAXPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Fetch API", regexp.MustCompile(`fetch\s*\(\s*['"](https?://[^'"]+|/[^'"]+)['"]`)},
	{"XMLHttpRequest", regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"](https?://[^'"]+|/[^'"]+)['"]`)},
	{"Axios", regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*['"](https?://[^'"]+|/[^'"]+)['"]`)},
	{"jQuery AJAX", regexp.MustCompile(`\$\.(ajax|get|post)\s*\(\s*['"](https?://[^'"]+|/[^'"]+)['"]`)},
	{"jQuery AJAX URL", regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"](https?://[^'"]+|/[^'"]+)['"]`)},
	{"API Endpoint", regexp.MustCompile(`['"](https?://[^'"]*api[^'"]*|/api/[^'"]+)['"]`)},
	{"GraphQL", regexp.MustCompile(`['"](/graphql[^'"]*|https?://[^'"]*graphql[^'"]*)['"]`)},
}

// WAF signatures for detection
var WAFSignatures = map[string][]string{
	"Cloudflare": {"cf-ray", "cf-cache-status", "__cfduid", "cloudflare"},
	"AWS WAF":    {"x-amzn-requestid", "x-amz-cf-id", "awselb"},
	"Akamai":     {"akamai", "x-akamai-transformed", "akamai-origin-hop"},
	"Imperva":    {"x-iinfo", "incap_ses", "visid_incap"},
	"Sucuri":     {"x-sucuri-id", "sucuri", "x-sucuri-cache"},
	"F5 BIG-IP":  {"x-wa-info", "bigipserver", "f5"},
	"ModSecurity": {"mod_security", "modsecurity"},
	"Barracuda":  {"barra_counter_session", "barracuda"},
	"Fortinet":   {"fortigate", "fortiweb"},
}

// DeepAnalyzer performs deep content analysis
type DeepAnalyzer struct {
	output       *Output
	client       *http.Client
	foundSecrets *StringSet
	foundAjax    *StringSet
	detectedWAF  string
}

// NewDeepAnalyzer creates a new DeepAnalyzer
func NewDeepAnalyzer(output *Output) *DeepAnalyzer {
	return &DeepAnalyzer{
		output: output,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		foundSecrets: NewStringSet(),
		foundAjax:    NewStringSet(),
	}
}

// ExtractAPIKeys extracts API keys and tokens from response body
func (d *DeepAnalyzer) ExtractAPIKeys(urlStr string, body []byte) []Result {
	var results []Result
	bodyStr := string(body)

	for _, pattern := range APIKeyPatterns {
		matches := pattern.Pattern.FindAllStringSubmatch(bodyStr, -1)
		for _, match := range matches {
			secret := match[0]
			if len(match) > 1 {
				secret = match[1]
			}
			
			// Avoid duplicates and too short matches
			if len(secret) < 10 || !d.foundSecrets.Add(secret[:min(30, len(secret))]) {
				continue
			}

			// Mask the middle of the secret for safety
			masked := maskSecret(secret)
			
			results = append(results, Result{
				Type:       "api-key",
				URL:        urlStr,
				Parameter:  pattern.Name,
				Value:      masked,
				Confidence: "High",
				Source:     "response-body",
			})
		}
	}

	return results
}

// ExtractAJAXEndpoints extracts AJAX/XHR endpoints from JavaScript
func (d *DeepAnalyzer) ExtractAJAXEndpoints(urlStr string, body []byte) []Result {
	var results []Result
	bodyStr := string(body)

	for _, pattern := range AJAXPatterns {
		matches := pattern.Pattern.FindAllStringSubmatch(bodyStr, -1)
		for _, match := range matches {
			endpoint := ""
			if len(match) > 1 {
				endpoint = match[len(match)-1] // Get the URL group
			} else {
				endpoint = match[0]
			}
			
			endpoint = strings.Trim(endpoint, `'"`)
			if endpoint == "" || !d.foundAjax.Add(endpoint) {
				continue
			}

			results = append(results, Result{
				Type:       "ajax-endpoint",
				URL:        endpoint,
				Parameter:  pattern.Name,
				Confidence: "Medium",
				Source:     urlStr,
			})
		}
	}

	return results
}

// GenerateBackupPaths generates potential backup file paths from a URL
func (d *DeepAnalyzer) GenerateBackupPaths(urlStr string) []string {
	var paths []string
	
	// Remove query string
	if idx := strings.Index(urlStr, "?"); idx != -1 {
		urlStr = urlStr[:idx]
	}

	// Add backup extensions
	for _, ext := range BackupExtensions {
		paths = append(paths, urlStr+ext)
	}

	// If URL has an extension, try replacing it
	if lastDot := strings.LastIndex(urlStr, "."); lastDot != -1 {
		base := urlStr[:lastDot]
		origExt := urlStr[lastDot:]
		
		for _, ext := range BackupExtensions {
			paths = append(paths, base+ext)
			paths = append(paths, base+ext+origExt)
		}
		
		for _, suffix := range BackupSuffixes {
			paths = append(paths, base+suffix+origExt)
		}
	}

	return paths
}

// DetectWAF detects WAF/CDN from response headers
func (d *DeepAnalyzer) DetectWAF(headers http.Header) (string, []Result) {
	var results []Result
	headersLower := make(map[string]string)
	
	for key, values := range headers {
		for _, v := range values {
			headersLower[strings.ToLower(key)] = strings.ToLower(v)
		}
	}

	for wafName, signatures := range WAFSignatures {
		for _, sig := range signatures {
			sigLower := strings.ToLower(sig)
			for hKey, hVal := range headersLower {
				if strings.Contains(hKey, sigLower) || strings.Contains(hVal, sigLower) {
					d.detectedWAF = wafName
					results = append(results, Result{
						Type:       "waf-detected",
						URL:        wafName,
						Parameter:  "signature",
						Value:      sig,
						Confidence: "High",
						Source:     "headers",
					})
					return wafName, results
				}
			}
		}
	}

	return "", results
}

// ParseSourceMap extracts endpoints from JavaScript source maps
func (d *DeepAnalyzer) ParseSourceMap(urlStr string, body []byte) []Result {
	var results []Result
	bodyStr := string(body)

	// Look for source map URL
	sourceMapPattern := regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s]+)`)
	matches := sourceMapPattern.FindAllStringSubmatch(bodyStr, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			sourceMapURL := match[1]
			results = append(results, Result{
				Type:       "source-map",
				URL:        sourceMapURL,
				Parameter:  "sourceMappingURL",
				Confidence: "High",
				Source:     urlStr,
			})
		}
	}

	// Look for source files in the source map JSON
	sourcesPattern := regexp.MustCompile(`"sources"\s*:\s*\[([^\]]+)\]`)
	sourcesMatches := sourcesPattern.FindAllStringSubmatch(bodyStr, -1)
	
	for _, match := range sourcesMatches {
		if len(match) > 1 {
			// Extract individual source files
			sourceFiles := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(match[1], -1)
			for _, sf := range sourceFiles {
				if len(sf) > 1 {
					results = append(results, Result{
						Type:       "source-file",
						URL:        sf[1],
						Confidence: "Medium",
						Source:     urlStr,
					})
				}
			}
		}
	}

	return results
}

// FindServiceWorker looks for service worker registrations
func (d *DeepAnalyzer) FindServiceWorker(urlStr string, body []byte) []Result {
	var results []Result
	bodyStr := string(body)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`navigator\.serviceWorker\.register\s*\(\s*['"](.[^'"]+)['"]`),
		regexp.MustCompile(`serviceWorker\.register\s*\(\s*['"](.[^'"]+)['"]`),
		regexp.MustCompile(`new\s+Worker\s*\(\s*['"](.[^'"]+)['"]`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(bodyStr, -1)
		for _, match := range matches {
			if len(match) > 1 {
				results = append(results, Result{
					Type:       "service-worker",
					URL:        match[1],
					Confidence: "High",
					Source:     urlStr,
				})
			}
		}
	}

	return results
}

// AnalyzeResponseTime checks if response time indicates hidden endpoints
func (d *DeepAnalyzer) AnalyzeResponseTime(urlStr string, responseTime time.Duration, statusCode int) []Result {
	var results []Result

	// Unusually slow responses might indicate processing/database access
	if responseTime > 3*time.Second && statusCode == 200 {
		results = append(results, Result{
			Type:       "slow-endpoint",
			URL:        urlStr,
			Parameter:  "response_time",
			Value:      responseTime.String(),
			Confidence: "Low",
			Source:     "timing",
		})
	}

	return results
}

// maskSecret masks the middle of a secret string
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return secret[:2] + "****" + secret[len(secret)-2:]
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}
