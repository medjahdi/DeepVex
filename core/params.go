package core

import (
	"net/url"
	"regexp"
	"strings"
)

// Common sensitive parameters to detect
var SensitiveParams = []string{
	// Logging parameters
	"log", "logger", "logging", "loglevel", "log_level", "logLevel",
	"debug", "verbose", "trace", "diagnostics",
	"console", "stdout", "stderr",
	// Monitoring/Admin parameters
	"admin", "administrator", "sysadmin", "root",
	"monitor", "monitoring", "metrics", "stats", "statistics",
	"status", "health", "ping", "heartbeat",
	// Debug parameters
	"debug", "debug_mode", "debugMode", "test", "testing",
	"dev", "development", "stage", "staging",
	// API/Backend parameters
	"api", "api_key", "apikey", "secret", "token", "access_token",
	"key", "password", "passwd", "credential", "auth",
	// Configuration parameters
	"config", "configuration", "setting", "env", "environment",
	"profile", "mode",
	// Database parameters
	"db", "database", "sql", "connection", "conn",
	// File parameters
	"file", "path", "dir", "directory", "location",
	// Session parameters
	"session", "sid", "jsessionid", "phpsessid",
	// Output control
	"output", "format", "type", "callback", "jsonp",
	// Cache parameters
	"cache", "nocache", "timestamp",
	// Redirect parameters
	"redirect", "return", "returnurl", "return_url", "next", "url", "goto", "target",
	// SSRF/LFI parameters
	"page", "include", "inc", "file", "template", "load",
}

// ParamAnalyzer analyzes URLs and responses for sensitive parameters
type ParamAnalyzer struct {
	sensitiveParams []string
	output          *Output
	foundParams     *StringSet
}

// NewParamAnalyzer creates a new ParamAnalyzer
func NewParamAnalyzer(output *Output) *ParamAnalyzer {
	return &ParamAnalyzer{
		sensitiveParams: SensitiveParams,
		output:          output,
		foundParams:     NewStringSet(),
	}
}

// AnalyzeURL checks a URL for sensitive parameters
func (p *ParamAnalyzer) AnalyzeURL(urlStr string) []Result {
	var results []Result

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return results
	}

	query := parsed.Query()
	for param, values := range query {
		lowerParam := strings.ToLower(param)
		
		// Check if parameter matches sensitive patterns
		for _, sensitiveParam := range p.sensitiveParams {
			if strings.Contains(lowerParam, strings.ToLower(sensitiveParam)) {
				for _, value := range values {
					key := urlStr + "|" + param + "|" + value
					if p.foundParams.Add(key) {
						results = append(results, Result{
							Type:       "sensitive-param",
							URL:        urlStr,
							Parameter:  param,
							Value:      value,
							Confidence: p.getConfidence(param, value),
							Source:     "query",
						})
					}
				}
				break
			}
		}

		// Check for debug-like values
		for _, value := range values {
			if p.isDebugValue(value) {
				key := urlStr + "|debug|" + param + "|" + value
				if p.foundParams.Add(key) {
					results = append(results, Result{
						Type:       "sensitive-param",
						URL:        urlStr,
						Parameter:  param,
						Value:      value,
						Confidence: "Low",
						Source:     "debug-value",
					})
				}
			}
		}
	}

	return results
}

// AnalyzeBody checks response body for hidden fields and debug patterns
func (p *ParamAnalyzer) AnalyzeBody(urlStr string, body []byte) []Result {
	var results []Result
	bodyStr := string(body)

	// Look for hidden form fields
	hiddenFieldRegex := regexp.MustCompile(`<input[^>]*type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*(?:value=["']([^"']+)["'])?[^>]*>`)
	matches := hiddenFieldRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			fieldName := match[1]
			fieldValue := ""
			if len(match) >= 3 {
				fieldValue = match[2]
			}

			for _, sensitiveParam := range p.sensitiveParams {
				if strings.Contains(strings.ToLower(fieldName), strings.ToLower(sensitiveParam)) {
					key := urlStr + "|hidden|" + fieldName
					if p.foundParams.Add(key) {
						results = append(results, Result{
							Type:       "hidden-field",
							URL:        urlStr,
							Parameter:  fieldName,
							Value:      fieldValue,
							Confidence: "Medium",
							Source:     "form",
						})
					}
					break
				}
			}
		}
	}

	// Look for debug patterns in JavaScript
	jsPatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)(debug|log|verbose)\s*[:=]\s*(true|1|"true")`), "debug-flag"},
		{regexp.MustCompile(`(?i)console\.(log|debug|info|warn|error)\s*\(`), "console-log"},
		{regexp.MustCompile(`(?i)debugger`), "debugger"},
		{regexp.MustCompile(`(?i)localStorage\.getItem\(["'](debug|log|token|api_?key)["']\)`), "localStorage"},
	}

	for _, jp := range jsPatterns {
		if jp.pattern.MatchString(bodyStr) {
			key := urlStr + "|js|" + jp.name
			if p.foundParams.Add(key) {
				results = append(results, Result{
					Type:       "debug-code",
					URL:        urlStr,
					Parameter:  jp.name,
					Value:      jp.pattern.String(),
					Confidence: "Low",
					Source:     "javascript",
				})
			}
		}
	}

	// Look for sensitive HTML comments
	commentRegex := regexp.MustCompile(`<!--\s*(.*?)\s*-->`)
	comments := commentRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, comment := range comments {
		if len(comment) > 1 {
			commentText := comment[1]
			lowerComment := strings.ToLower(commentText)
			
			// Check for sensitive keywords in comments
			sensitiveKeywords := []string{"password", "secret", "api", "key", "token", "debug", "admin", "todo", "fixme", "hack"}
			for _, keyword := range sensitiveKeywords {
				if strings.Contains(lowerComment, keyword) && len(commentText) < 500 {
					key := urlStr + "|comment|" + commentText[:min(50, len(commentText))]
					if p.foundParams.Add(key) {
						results = append(results, Result{
							Type:       "sensitive-comment",
							URL:        urlStr,
							Parameter:  "comment",
							Value:      truncate(commentText, 100),
							Confidence: "Medium",
							Source:     "html",
						})
					}
					break
				}
			}
		}
	}

	return results
}

// getConfidence returns confidence level based on parameter and value
func (p *ParamAnalyzer) getConfidence(param, value string) string {
	lowerParam := strings.ToLower(param)
	highConfidence := []string{"api_key", "apikey", "secret", "password", "token", "auth", "credential"}
	for _, h := range highConfidence {
		if strings.Contains(lowerParam, h) {
			return "High"
		}
	}
	if p.isDebugValue(value) {
		return "Medium"
	}
	return "Low"
}

// isDebugValue checks if a value looks like a debug flag
func (p *ParamAnalyzer) isDebugValue(value string) bool {
	lowerValue := strings.ToLower(value)
	debugValues := []string{"true", "1", "on", "yes", "enable", "enabled", "debug"}
	for _, dv := range debugValues {
		if lowerValue == dv {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
