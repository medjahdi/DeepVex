package core

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// StringSet is a thread-safe set for string deduplication
type StringSet struct {
	items map[string]bool
	mu    sync.RWMutex
}

// NewStringSet creates a new StringSet
func NewStringSet() *StringSet {
	return &StringSet{
		items: make(map[string]bool),
	}
}

// Add adds a string to the set, returns true if it was new
func (s *StringSet) Add(item string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[item] {
		return false
	}
	s.items[item] = true
	return true
}

// Contains checks if an item exists in the set
func (s *StringSet) Contains(item string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[item]
}

// GetDomain extracts the domain from a URL
func GetDomain(site *url.URL) string {
	host := site.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// NormalizeURL cleans and normalizes a URL
func NormalizeURL(baseURL *url.URL, href string) string {
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := baseURL.ResolveReference(parsed)
	resolved.Fragment = "" // Remove fragment

	return resolved.String()
}

// GetExtension extracts the file extension from a URL
func GetExtension(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	path := parsed.Path
	if idx := strings.LastIndex(path, "."); idx != -1 {
		return strings.ToLower(path[idx:])
	}
	return ""
}

// IsValidURL checks if a URL is valid HTTP/HTTPS
func IsValidURL(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

// GetSubdomains extracts subdomains from response body
func GetSubdomains(body, domain string) []string {
	var subdomains []string
	re := regexp.MustCompile(`(?i)[a-zA-Z0-9][-a-zA-Z0-9]*\.` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(body, -1)
	
	seen := make(map[string]bool)
	for _, match := range matches {
		sub := strings.ToLower(match)
		if !seen[sub] {
			seen[sub] = true
			subdomains = append(subdomains, sub)
		}
	}
	return subdomains
}

// GetAWSS3Buckets extracts AWS S3 bucket names from response body
func GetAWSS3Buckets(body string) []string {
	var buckets []string
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com`),
		regexp.MustCompile(`s3://[a-zA-Z0-9.\-_]+`),
		regexp.MustCompile(`s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexp.MustCompile(`s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
	}
	
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			if !seen[match] {
				seen[match] = true
				buckets = append(buckets, match)
			}
		}
	}
	return buckets
}

// Unique returns unique strings from a slice
func Unique(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// IsSameDomain checks if a URL belongs to the same domain (or subdomain)
func IsSameDomain(urlStr, targetDomain string, includeSubs bool) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	host := strings.ToLower(parsed.Hostname())
	targetDomain = strings.ToLower(targetDomain)
	
	if includeSubs {
		// Check if host ends with .domain or is exactly domain
		return host == targetDomain || strings.HasSuffix(host, "."+targetDomain)
	}
	
	// Exact domain match only
	return host == targetDomain
}

// IsInterestingPath checks if a URL path is worth probing for backups
// (skip static assets, common third-party paths, etc.)
func IsInterestingPath(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	path := strings.ToLower(parsed.Path)
	
	// Skip static file extensions
	staticExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", 
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webp", ".webm"}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	
	// Skip common uninteresting paths
	skipPaths := []string{"/static/", "/assets/", "/images/", "/img/", "/css/", 
		"/js/", "/fonts/", "/media/", "/_next/", "/webpack/", "/node_modules/"}
	for _, skip := range skipPaths {
		if strings.Contains(path, skip) {
			return false
		}
	}
	
	// Should have some depth (not just root)
	if path == "" || path == "/" {
		return false
	}
	
	return true
}
