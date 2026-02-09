package core

import (
	"regexp"
	"strings"
)

// LinkFinder regex patterns for extracting URLs from JavaScript
var linkFinderPatterns = []*regexp.Regexp{
	// Relative and absolute URLs
	regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`),
	// API endpoints
	regexp.MustCompile(`["']/(api|v[0-9]+|rest|graphql)/[^"']+["']`),
	// Paths starting with /
	regexp.MustCompile(`["'](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*(?:\.[a-zA-Z]+)?(?:\?[^"']+)?)["']`),
}

// excludePatterns to filter out false positives
var excludePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:image|text|application)/`), // MIME types
	regexp.MustCompile(`^\d+px$`),                       // CSS sizes
	regexp.MustCompile(`^#[a-fA-F0-9]{3,6}$`),          // Color codes
	regexp.MustCompile(`^data:`),                        // Data URIs
}

// LinkFinderExtractor extracts links from JavaScript
type LinkFinderExtractor struct {
	foundLinks *StringSet
}

// NewLinkFinderExtractor creates a new LinkFinderExtractor
func NewLinkFinderExtractor() *LinkFinderExtractor {
	return &LinkFinderExtractor{
		foundLinks: NewStringSet(),
	}
}

// ExtractLinks extracts potential URLs/paths from JavaScript content
func (l *LinkFinderExtractor) ExtractLinks(content string) []string {
	var links []string
	seen := make(map[string]bool)

	for _, pattern := range linkFinderPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				link := l.cleanLink(match[1])
				if link != "" && !seen[link] && l.isValidLink(link) {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// cleanLink removes quotes and cleans up the link
func (l *LinkFinderExtractor) cleanLink(link string) string {
	link = strings.Trim(link, `"'`)
	link = strings.TrimSpace(link)
	
	// Skip empty or too short links
	if len(link) < 2 {
		return ""
	}
	
	// Skip common false positives
	skipPrefixes := []string{
		"#", "javascript:", "mailto:", "tel:", "data:",
		"void(", "return ", "function(", "if(", "else{",
	}
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(strings.ToLower(link), prefix) {
			return ""
		}
	}

	return link
}

// isValidLink checks if a link is valid
func (l *LinkFinderExtractor) isValidLink(link string) bool {
	// Check against exclude patterns
	for _, pattern := range excludePatterns {
		if pattern.MatchString(link) {
			return false
		}
	}

	// Must have at least one alphanumeric character
	hasAlphaNum := false
	for _, r := range link {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasAlphaNum = true
			break
		}
	}

	return hasAlphaNum
}

// ExtractFromJS extracts links from JavaScript content and returns unique ones
func ExtractFromJS(content string) []string {
	extractor := NewLinkFinderExtractor()
	return extractor.ExtractLinks(content)
}
