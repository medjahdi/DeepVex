package core

import (
	"math/rand"
	"time"
)

// Random User-Agent list for rotation
var UserAgents = []string{
	// Chrome on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Chrome on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Firefox on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
	// Firefox on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	// Safari on Mac
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	// Edge on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
	// Chrome on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Firefox on Linux
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
}

// Accept headers for different "browsers"
var AcceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

// Accept-Language headers
var AcceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"en-US,en;q=0.5",
	"en-US,en;q=0.9,es;q=0.8",
	"en,en-US;q=0.9",
}

// Referer patterns
var Referers = []string{
	"https://www.google.com/",
	"https://www.bing.com/",
	"https://duckduckgo.com/",
	"https://www.google.com/search?q=",
	"",
}

// StealthConfig holds anti-bot configuration
type StealthConfig struct {
	MinDelay      int  // Minimum delay in ms
	MaxDelay      int  // Maximum delay in ms (for jitter)
	RandomUA      bool // Use random User-Agents
	RandomHeaders bool // Randomize header order & values
	StealthMode   bool // Enable all stealth features
}

// Stealth provides anti-bot detection features
type Stealth struct {
	config StealthConfig
	rng    *rand.Rand
}

// NewStealth creates a new Stealth instance
func NewStealth(config StealthConfig) *Stealth {
	return &Stealth{
		config: config,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GetRandomUserAgent returns a random User-Agent string
func (s *Stealth) GetRandomUserAgent() string {
	return UserAgents[s.rng.Intn(len(UserAgents))]
}

// GetRandomAccept returns a random Accept header
func (s *Stealth) GetRandomAccept() string {
	return AcceptHeaders[s.rng.Intn(len(AcceptHeaders))]
}

// GetRandomAcceptLanguage returns a random Accept-Language header
func (s *Stealth) GetRandomAcceptLanguage() string {
	return AcceptLanguages[s.rng.Intn(len(AcceptLanguages))]
}

// GetRandomReferer returns a random Referer (or empty)
func (s *Stealth) GetRandomReferer(targetDomain string) string {
	ref := Referers[s.rng.Intn(len(Referers))]
	if ref == "https://www.google.com/search?q=" {
		return ref + targetDomain
	}
	return ref
}

// GetRandomDelay returns a random delay duration with jitter
func (s *Stealth) GetRandomDelay() time.Duration {
	if s.config.MaxDelay <= s.config.MinDelay {
		return time.Duration(s.config.MinDelay) * time.Millisecond
	}
	jitter := s.rng.Intn(s.config.MaxDelay - s.config.MinDelay)
	delay := s.config.MinDelay + jitter
	return time.Duration(delay) * time.Millisecond
}

// GetHeaders returns randomized headers that look like a real browser
func (s *Stealth) GetHeaders(targetDomain string) map[string]string {
	headers := map[string]string{
		"Accept":          s.GetRandomAccept(),
		"Accept-Language": s.GetRandomAcceptLanguage(),
		"Accept-Encoding": "gzip, deflate, br",
		"Connection":      "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":  "document",
		"Sec-Fetch-Mode":  "navigate",
		"Sec-Fetch-Site":  "none",
		"Sec-Fetch-User":  "?1",
		"Cache-Control":   "max-age=0",
	}

	// Randomly add DNT header
	if s.rng.Intn(2) == 0 {
		headers["DNT"] = "1"
	}

	// Randomly add referer
	if s.rng.Intn(3) != 0 { // 66% chance to have referer
		ref := s.GetRandomReferer(targetDomain)
		if ref != "" {
			headers["Referer"] = ref
		}
	}

	return headers
}

// Sleep applies a random delay with jitter
func (s *Stealth) Sleep() {
	time.Sleep(s.GetRandomDelay())
}

// ShouldSkipRequest occasionally skips requests to appear more human
func (s *Stealth) ShouldSkipRequest() bool {
	// 2% chance to skip (simulates user abandoning page load)
	return s.rng.Intn(100) < 2
}
