package core

import (
	"net/http"
	"strings"
)

// SensitivePaths are paths that may expose sensitive functionality
var SensitivePaths = []string{
	// Admin panels
	"/admin", "/administrator", "/manager", "/login", "/logout",
	"/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer", "/webadmin",
	// APIs
	"/api", "/graphql", "/rest", "/soap", "/xmlrpc", "/swagger", "/openapi",
	"/api/v1", "/api/v2", "/api/v3",
	// Debug/Development
	"/debug", "/console", "/terminal", "/shell", "/test", "/testing",
	"/dev", "/development", "/staging", "/phpinfo.php", "/info.php",
	// Logs and configs
	"/logs", "/log", "/logging", "/trace", "/error_log",
	"/config", "/configuration", "/settings", ".env", "/config.json",
	// Backups
	"/backup", "/backups", "/dump", "/export", "/import",
	"/db", "/database", "/sql",
	// Monitoring
	"/monitor", "/status", "/health", "/metrics", "/ping",
	"/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
	// Git/Version control
	"/.git", "/.git/config", "/.svn", "/.cvs", "/.hg",
	// Elasticsearch
	"/_search", "/_cat", "/_nodes", "/_cluster",
	// Jenkins
	"/jenkins", "/jenkins/script",
	// Config files
	"/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
	"/.htaccess", "/.htpasswd", "/web.config",
}

// SensitiveHeaders are response headers that may leak sensitive info
var SensitiveHeaders = []string{
	"X-Debug", "X-Debug-Mode", "X-Debug-Enabled",
	"X-API-Key", "X-Api-Key", "X-Secret",
	"X-Token", "X-Access-Token",
	"Debug", "Debug-Mode",
	"X-Log-Level", "X-Logging",
	"X-Admin", "X-Administrator",
	"X-Powered-By", "Server",
	"X-AspNet-Version", "X-AspNetMvc-Version",
}

// SensitiveChecker checks for sensitive paths and headers
type SensitiveChecker struct {
	output     *Output
	foundPaths *StringSet
}

// NewSensitiveChecker creates a new SensitiveChecker
func NewSensitiveChecker(output *Output) *SensitiveChecker {
	return &SensitiveChecker{
		output:     output,
		foundPaths: NewStringSet(),
	}
}

// CheckPath checks if a URL path contains sensitive paths
func (s *SensitiveChecker) CheckPath(urlStr string) []Result {
	var results []Result

	lowerURL := strings.ToLower(urlStr)
	for _, sensitivePath := range SensitivePaths {
		if strings.Contains(lowerURL, strings.ToLower(sensitivePath)) {
			if s.foundPaths.Add(urlStr + "|" + sensitivePath) {
				results = append(results, Result{
					Type:       "sensitive-path",
					URL:        urlStr,
					Parameter:  "path",
					Value:      sensitivePath,
					Confidence: s.getPathConfidence(sensitivePath),
					Source:     "url",
				})
			}
		}
	}

	return results
}

// CheckHeaders checks response headers for sensitive information
func (s *SensitiveChecker) CheckHeaders(urlStr string, headers http.Header) []Result {
	var results []Result

	for _, sensitiveHeader := range SensitiveHeaders {
		for headerName, values := range headers {
			if strings.EqualFold(headerName, sensitiveHeader) {
				for _, value := range values {
					key := urlStr + "|header|" + headerName
					if s.foundPaths.Add(key) {
						results = append(results, Result{
							Type:       "sensitive-header",
							URL:        urlStr,
							Parameter:  headerName,
							Value:      value,
							Confidence: "Medium",
							Source:     "header",
						})
					}
				}
			}
		}
	}

	return results
}

// getPathConfidence returns confidence based on path type
func (s *SensitiveChecker) getPathConfidence(path string) string {
	highConfidence := []string{
		"/.git", "/.env", "/config", "/admin", "/phpmyadmin",
		"/actuator", "/swagger", "/.htpasswd", "/backup",
	}
	for _, h := range highConfidence {
		if strings.Contains(strings.ToLower(path), strings.ToLower(h)) {
			return "High"
		}
	}
	return "Medium"
}
