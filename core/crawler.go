package core

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// Config holds crawler configuration
type Config struct {
	URL             string
	MaxDepth        int
	Concurrent      int
	Timeout         int
	Delay           int
	RandomDelay     int  // Max random delay for jitter
	UserAgent       string
	Proxy           string
	Cookie          string
	Headers         []string
	OutputFile      string
	JSONOutput      bool
	Quiet           bool
	Verbose         bool
	IncludeSubs     bool
	UseWayback      bool
	UseCommonCrawl  bool
	UseOTX          bool
	DisableRedirect bool
	StealthMode     bool // Enable anti-bot detection evasion
	RandomUA        bool // Use random User-Agents
	DeepAnalysis    bool // Enable deep analysis (API keys, backups, WAF detection)
}

// Crawler is the main web crawler
type Crawler struct {
	config            Config
	collector         *colly.Collector
	jsCollector       *colly.Collector
	output            *Output
	paramAnalyzer     *ParamAnalyzer
	sensitiveChecker  *SensitiveChecker
	linkFinder        *LinkFinderExtractor
	externalSources   *ExternalSources
	stealth           *Stealth
	deepAnalyzer      *DeepAnalyzer
	urlSet            *StringSet
	jsSet             *StringSet
	formSet           *StringSet
	backupSet         *StringSet
	domain            string
	baseURL           *url.URL
	wg                sync.WaitGroup
}

// NewCrawler creates a new crawler instance
func NewCrawler(config Config) (*Crawler, error) {
	// Parse base URL
	baseURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}

	// Create output handler
	output, err := NewOutput(config.OutputFile, config.JSONOutput, config.Quiet)
	if err != nil {
		return nil, err
	}

	// Create main collector
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(config.MaxDepth),
		colly.IgnoreRobotsTxt(),
	)

	// Setup HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		MaxConnsPerHost: 100,
	}

	// Set proxy if provided
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	// Disable redirects if requested
	if config.DisableRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	c.SetClient(client)

	// Set limits with random delay support
	randomDelay := time.Duration(config.RandomDelay) * time.Millisecond
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: config.Concurrent,
		Delay:       time.Duration(config.Delay) * time.Second,
		RandomDelay: randomDelay,
	})

	// Initialize stealth mode
	stealth := NewStealth(StealthConfig{
		MinDelay:      config.Delay * 1000, // Convert to ms
		MaxDelay:      config.Delay*1000 + config.RandomDelay,
		RandomUA:      config.RandomUA || config.StealthMode,
		RandomHeaders: config.StealthMode,
		StealthMode:   config.StealthMode,
	})

	// Set user agent (will be overridden per-request if RandomUA is enabled)
	if config.UserAgent != "" {
		c.UserAgent = config.UserAgent
	} else if config.RandomUA || config.StealthMode {
		c.UserAgent = stealth.GetRandomUserAgent()
	} else {
		c.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	// URL filters - stay within domain
	domain := GetDomain(baseURL)
	if config.IncludeSubs {
		c.AllowedDomains = nil // Allow all subdomains
	} else {
		c.AllowedDomains = []string{baseURL.Hostname()}
	}

	// Disallow static resources
	disallowedRegex := regexp.MustCompile(`(?i)\.(png|apng|bmp|gif|ico|jpg|jpeg|svg|tif|tiff|webp|mp3|mp4|wav|webm|woff|woff2|ttf|otf|eot|css)(?:\?|#|$)`)
	c.DisallowedURLFilters = append(c.DisallowedURLFilters, disallowedRegex)

	// Clone for JS processing
	jsCollector := c.Clone()
	jsCollector.AllowedDomains = nil // Allow external JS files

	// Create crawler
	crawler := &Crawler{
		config:           config,
		collector:        c,
		jsCollector:      jsCollector,
		output:           output,
		paramAnalyzer:    NewParamAnalyzer(output),
		sensitiveChecker: NewSensitiveChecker(output),
		linkFinder:       NewLinkFinderExtractor(),
		externalSources:  NewExternalSources(output, config.IncludeSubs),
		stealth:          stealth,
		deepAnalyzer:     NewDeepAnalyzer(output),
		urlSet:           NewStringSet(),
		jsSet:            NewStringSet(),
		formSet:          NewStringSet(),
		backupSet:        NewStringSet(),
		domain:           domain,
		baseURL:          baseURL,
	}

	// Setup handlers
	crawler.setupHandlers()

	return crawler, nil
}

// setupHandlers sets up all colly handlers
func (c *Crawler) setupHandlers() {
	// Stealth mode: set random headers per request
	if c.config.StealthMode || c.config.RandomUA {
		c.collector.OnRequest(func(r *colly.Request) {
			// Set random User-Agent per request
			r.Headers.Set("User-Agent", c.stealth.GetRandomUserAgent())
			
			// Set browser-like headers in stealth mode
			if c.config.StealthMode {
				headers := c.stealth.GetHeaders(c.domain)
				for key, value := range headers {
					r.Headers.Set(key, value)
				}
			}
		})
		
		// Also for JS collector
		c.jsCollector.OnRequest(func(r *colly.Request) {
			r.Headers.Set("User-Agent", c.stealth.GetRandomUserAgent())
			if c.config.StealthMode {
				headers := c.stealth.GetHeaders(c.domain)
				for key, value := range headers {
					r.Headers.Set(key, value)
				}
			}
		})
	}

	// Set custom cookie
	if c.config.Cookie != "" {
		c.collector.OnRequest(func(r *colly.Request) {
			r.Headers.Set("Cookie", c.config.Cookie)
		})
	}

	// Set custom headers
	for _, header := range c.config.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			c.collector.OnRequest(func(r *colly.Request) {
				r.Headers.Set(key, value)
			})
		}
	}

	// Handle href links
	c.collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		link = NormalizeURL(c.baseURL, e.Attr("href"))
		if link == "" {
			return
		}

		if c.urlSet.Add(link) {
			c.output.WriteResult(Result{
				Type:       "href",
				URL:        link,
				Source:     e.Request.URL.String(),
				StatusCode: 0,
			})
			e.Request.Visit(link)
		}
	})

	// Handle forms
	c.collector.OnHTML("form[action]", func(e *colly.HTMLElement) {
		formURL := e.Request.AbsoluteURL(e.Attr("action"))
		if formURL == "" {
			formURL = e.Request.URL.String()
		}

		if c.formSet.Add(formURL) {
			c.output.WriteResult(Result{
				Type:   "form",
				URL:    formURL,
				Source: e.Request.URL.String(),
			})
		}
	})

	// Handle file upload forms
	c.collector.OnHTML(`input[type="file"]`, func(e *colly.HTMLElement) {
		uploadURL := e.Request.URL.String()
		if c.formSet.Add("upload:" + uploadURL) {
			c.output.WriteResult(Result{
				Type:   "upload-form",
				URL:    uploadURL,
				Source: e.Request.URL.String(),
			})
		}
	})

	// Handle script sources
	c.collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		jsURL := e.Request.AbsoluteURL(e.Attr("src"))
		if jsURL != "" && c.jsSet.Add(jsURL) {
			c.output.WriteResult(Result{
				Type:   "js",
				URL:    jsURL,
				Source: e.Request.URL.String(),
			})
			c.jsCollector.Visit(jsURL)
		}
	})

	// Handle response
	c.collector.OnResponse(func(r *colly.Response) {
		urlStr := r.Request.URL.String()

		// Output the URL
		if c.config.Verbose {
			c.output.WriteResult(Result{
				Type:       "url",
				URL:        urlStr,
				StatusCode: r.StatusCode,
			})
		}

		// Check for sensitive paths
		for _, result := range c.sensitiveChecker.CheckPath(urlStr) {
			c.output.WriteResult(result)
		}

		// Check response headers
		for _, result := range c.sensitiveChecker.CheckHeaders(urlStr, *r.Headers) {
			c.output.WriteResult(result)
		}

		// Analyze URL parameters
		for _, result := range c.paramAnalyzer.AnalyzeURL(urlStr) {
			c.output.WriteResult(result)
		}

		// Analyze response body
		for _, result := range c.paramAnalyzer.AnalyzeBody(urlStr, r.Body) {
			c.output.WriteResult(result)
		}

		// Deep analysis (if enabled)
		if c.config.DeepAnalysis {
			// Extract API keys and secrets
			for _, result := range c.deepAnalyzer.ExtractAPIKeys(urlStr, r.Body) {
				c.output.WriteResult(result)
			}
			
			// Detect WAF/CDN
			wafName, wafResults := c.deepAnalyzer.DetectWAF(*r.Headers)
			for _, result := range wafResults {
				c.output.WriteResult(result)
			}
			if wafName != "" && c.config.Verbose {
				Warning("WAF Detected: %s - adapting crawl behavior", wafName)
			}
			
			// Extract AJAX endpoints from HTML/JS content
			for _, result := range c.deepAnalyzer.ExtractAJAXEndpoints(urlStr, r.Body) {
				c.output.WriteResult(result)
				// Try to visit the AJAX endpoint
				if result.URL != "" && !strings.HasPrefix(result.URL, "http") {
					resolved := NormalizeURL(r.Request.URL, result.URL)
					if resolved != "" {
						c.collector.Visit(resolved)
					}
				}
			}
			
			// Find service workers
			for _, result := range c.deepAnalyzer.FindServiceWorker(urlStr, r.Body) {
				c.output.WriteResult(result)
				// Visit service worker scripts
				resolved := NormalizeURL(r.Request.URL, result.URL)
				if resolved != "" {
					c.jsCollector.Visit(resolved)
				}
			}
			
			// Smart backup file detection - only probe interesting paths
			if IsInterestingPath(urlStr) && IsSameDomain(urlStr, c.domain, false) {
				// Only probe high-value backup extensions
				smartBackupExts := []string{".bak", ".backup", ".old", ".orig", "~", ".swp"}
				for _, ext := range smartBackupExts {
					backupPath := urlStr + ext
					if c.backupSet.Add(backupPath) {
						c.output.WriteResult(Result{
							Type:   "backup-probe",
							URL:    backupPath,
							Source: urlStr,
						})
					}
				}
			}
		}

		// Find subdomains in response
		subdomains := GetSubdomains(string(r.Body), c.domain)
		for _, sub := range subdomains {
			if c.urlSet.Add("subdomain:" + sub) {
				c.output.WriteResult(Result{
					Type:   "subdomain",
					URL:    sub,
					Source: urlStr,
				})
			}
		}

		// Find AWS S3 buckets
		buckets := GetAWSS3Buckets(string(r.Body))
		for _, bucket := range buckets {
			if c.urlSet.Add("aws:" + bucket) {
				c.output.WriteResult(Result{
					Type:   "aws-s3",
					URL:    bucket,
					Source: urlStr,
				})
			}
		}
	})

	// Handle JS response for link finding
	c.jsCollector.OnResponse(func(r *colly.Response) {
		if r.StatusCode >= 400 {
			return
		}

		urlStr := r.Request.URL.String()
		
		// Extract links from JavaScript
		links := c.linkFinder.ExtractLinks(string(r.Body))
		for _, link := range links {
			resolvedURL := NormalizeURL(r.Request.URL, link)
			if resolvedURL == "" || !c.urlSet.Add(resolvedURL) {
				continue
			}
			
			// Only output links that match the target domain
			if !IsSameDomain(resolvedURL, c.domain, c.config.IncludeSubs) {
				continue
			}
			
			c.output.WriteResult(Result{
				Type:   "linkfinder",
				URL:    resolvedURL,
				Source: urlStr,
			})
			
			// Visit if it's a JS file
			ext := GetExtension(resolvedURL)
			if ext == ".js" || ext == ".json" {
				c.jsCollector.Visit(resolvedURL)
			} else {
				c.collector.Visit(resolvedURL)
			}
		}

		// Deep analysis for JS files
		if c.config.DeepAnalysis {
			// Extract API keys from JS
			for _, result := range c.deepAnalyzer.ExtractAPIKeys(urlStr, r.Body) {
				c.output.WriteResult(result)
			}
			
			// Extract AJAX endpoints from JS
			for _, result := range c.deepAnalyzer.ExtractAJAXEndpoints(urlStr, r.Body) {
				c.output.WriteResult(result)
			}
			
			// Parse source maps
			for _, result := range c.deepAnalyzer.ParseSourceMap(urlStr, r.Body) {
				c.output.WriteResult(result)
				// Visit source map files
				if result.Type == "source-map" && !strings.HasPrefix(result.URL, "data:") {
					resolved := NormalizeURL(r.Request.URL, result.URL)
					if resolved != "" {
						c.jsCollector.Visit(resolved)
					}
				}
			}
		}
	})

	// Error handler
	c.collector.OnError(func(r *colly.Response, err error) {
		if c.config.Verbose {
			Warning("Error visiting %s: %v", r.Request.URL.String(), err)
		}
	})
}

// Run starts the crawler
func (c *Crawler) Run() {
	PrintBanner()

	Info("Target: %s", c.config.URL)
	Info("Depth: %d | Threads: %d | Timeout: %ds", c.config.MaxDepth, c.config.Concurrent, c.config.Timeout)

	// Fetch from external sources if enabled
	var externalURLs []string
	if c.config.UseWayback || c.config.UseCommonCrawl || c.config.UseOTX {
		Info("Fetching from external sources...")
		externalURLs = c.externalSources.FetchAll(c.domain)
		Success("Fetched %d unique URLs from external sources", len(externalURLs))

		// Output and visit external URLs
		for _, extURL := range externalURLs {
			if c.urlSet.Add(extURL) {
				c.output.WriteResult(Result{
					Type:   "external",
					URL:    extURL,
					Source: "external-sources",
				})
				c.collector.Visit(extURL)
			}
		}
	}

	// Start crawling
	Info("Starting web crawler...")
	c.collector.Visit(c.config.URL)
	
	// Wait for completion
	c.collector.Wait()
	c.jsCollector.Wait()

	Success("Crawling complete!")
	c.output.Close()
}


