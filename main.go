package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/medjahdi/deepvex/core"
)

const (
	Version = "1.0.0"
	Author  = "medjahdi"
)

var rootCmd = &cobra.Command{
	Use:   "deepvex",
	Short: "DeepVex - Advanced Web Reconnaissance Tool",
	Long: `
    ____                 _    __         
   / __ \___  ___  ____ | |  / /__  _  __
  / / / / _ \/ _ \/ __ \| | / / _ \| |/_/
 / /_/ /  __/  __/ /_/ /| |/ /  __/>  <  
/_____/\___/\___/ .___/ |___/\___/_/|_|  
               /_/                        

DeepVex v1.0.0 - Advanced Web Reconnaissance Tool
Developed by medjahdi

A fast, comprehensive web reconnaissance tool for security professionals.
Designed for bug bounty hunters and penetration testers who need 
efficient endpoint discovery, parameter analysis, and deep content inspection.

`,
	Run: run,
}

func init() {
	// Target options
	rootCmd.Flags().StringP("url", "u", "", "Target URL (required)")
	rootCmd.MarkFlagRequired("url")

	// Crawling options
	rootCmd.Flags().IntP("depth", "d", 2, "Maximum crawl depth")
	rootCmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
	rootCmd.Flags().IntP("timeout", "m", 30, "Request timeout in seconds")
	rootCmd.Flags().IntP("delay", "k", 0, "Delay between requests in seconds")
	rootCmd.Flags().Int("random-delay", 0, "Random delay jitter in milliseconds (added to delay)")

	// HTTP options
	rootCmd.Flags().StringP("proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	rootCmd.Flags().StringP("cookie", "c", "", "Cookie string (e.g., session=abc)")
	rootCmd.Flags().StringArrayP("header", "H", []string{}, "Custom header (can be used multiple times)")
	rootCmd.Flags().StringP("user-agent", "a", "", "Custom User-Agent string")
	rootCmd.Flags().Bool("no-redirect", false, "Disable following redirects")

	// Stealth mode options
	rootCmd.Flags().Bool("stealth", false, "Enable stealth mode (random UA, headers, delays)")
	rootCmd.Flags().Bool("random-ua", false, "Use random User-Agent per request")

	// Deep analysis options
	rootCmd.Flags().Bool("deep", false, "Enable deep analysis (API keys, backups, WAF detection)")

	// Scope options
	rootCmd.Flags().Bool("subs", false, "Include subdomains in crawl scope")

	// External sources
	rootCmd.Flags().Bool("wayback", false, "Fetch URLs from Wayback Machine")
	rootCmd.Flags().Bool("commoncrawl", false, "Fetch URLs from CommonCrawl")
	rootCmd.Flags().Bool("otx", false, "Fetch URLs from AlienVault OTX")
	rootCmd.Flags().Bool("all-sources", false, "Fetch from all external sources")

	// Output options
	rootCmd.Flags().StringP("output", "o", "", "Output file path")
	rootCmd.Flags().Bool("json", false, "Output results as JSON")
	rootCmd.Flags().BoolP("quiet", "q", false, "Suppress console output (only write to file)")
	rootCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Version
	rootCmd.Flags().Bool("version", false, "Print version and exit")
}

func run(cmd *cobra.Command, args []string) {
	// Check version flag
	version, _ := cmd.Flags().GetBool("version")
	if version {
		fmt.Printf("DeepVex v%s by %s\n", Version, Author)
		os.Exit(0)
	}

	// Get flags
	targetURL, _ := cmd.Flags().GetString("url")
	depth, _ := cmd.Flags().GetInt("depth")
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetInt("timeout")
	delay, _ := cmd.Flags().GetInt("delay")
	randomDelay, _ := cmd.Flags().GetInt("random-delay")
	proxy, _ := cmd.Flags().GetString("proxy")
	cookie, _ := cmd.Flags().GetString("cookie")
	headers, _ := cmd.Flags().GetStringArray("header")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	noRedirect, _ := cmd.Flags().GetBool("no-redirect")
	stealthMode, _ := cmd.Flags().GetBool("stealth")
	randomUA, _ := cmd.Flags().GetBool("random-ua")
	deepAnalysis, _ := cmd.Flags().GetBool("deep")
	includeSubs, _ := cmd.Flags().GetBool("subs")
	useWayback, _ := cmd.Flags().GetBool("wayback")
	useCommonCrawl, _ := cmd.Flags().GetBool("commoncrawl")
	useOTX, _ := cmd.Flags().GetBool("otx")
	allSources, _ := cmd.Flags().GetBool("all-sources")
	outputFile, _ := cmd.Flags().GetString("output")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Enable all sources if flag is set
	if allSources {
		useWayback = true
		useCommonCrawl = true
		useOTX = true
	}

	// Stealth mode enables random delays if not set
	if stealthMode && randomDelay == 0 {
		randomDelay = 2000 // 2 second max jitter in stealth mode
	}

	// Create config
	config := core.Config{
		URL:             targetURL,
		MaxDepth:        depth,
		Concurrent:      threads,
		Timeout:         timeout,
		Delay:           delay,
		RandomDelay:     randomDelay,
		UserAgent:       userAgent,
		Proxy:           proxy,
		Cookie:          cookie,
		Headers:         headers,
		OutputFile:      outputFile,
		JSONOutput:      jsonOutput,
		Quiet:           quiet,
		Verbose:         verbose,
		IncludeSubs:     includeSubs,
		UseWayback:      useWayback,
		UseCommonCrawl:  useCommonCrawl,
		UseOTX:          useOTX,
		DisableRedirect: noRedirect,
		StealthMode:     stealthMode,
		RandomUA:        randomUA,
		DeepAnalysis:    deepAnalysis,
	}

	// Create and run crawler
	crawler, err := core.NewCrawler(config)
	if err != nil {
		color.Red("[-] Error creating crawler: %v", err)
		os.Exit(1)
	}

	crawler.Run()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("[-] Error: %v", err)
		os.Exit(1)
	}
}
