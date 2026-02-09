package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ExternalSources fetches URLs from external sources
type ExternalSources struct {
	client      *http.Client
	output      *Output
	includeSubs bool
}

// NewExternalSources creates a new ExternalSources handler
func NewExternalSources(output *Output, includeSubs bool) *ExternalSources {
	return &ExternalSources{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		output:      output,
		includeSubs: includeSubs,
	}
}

// FetchAll fetches URLs from all external sources
func (e *ExternalSources) FetchAll(domain string) []string {
	var allURLs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sources := []struct {
		name string
		fn   func(string) ([]string, error)
	}{
		{"wayback", e.FetchWayback},
		{"commoncrawl", e.FetchCommonCrawl},
		{"otx", e.FetchOTX},
	}

	for _, source := range sources {
		wg.Add(1)
		go func(name string, fetch func(string) ([]string, error)) {
			defer wg.Done()
			Info("Fetching from %s...", name)
			
			urls, err := fetch(domain)
			if err != nil {
				Warning("Error fetching from %s: %v", name, err)
				return
			}

			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()

			Success("Found %d URLs from %s", len(urls), name)
		}(source.name, source.fn)
	}

	wg.Wait()
	return Unique(allURLs)
}

// FetchWayback fetches URLs from Wayback Machine
func (e *ExternalSources) FetchWayback(domain string) ([]string, error) {
	subsWildcard := "*."
	if !e.includeSubs {
		subsWildcard = ""
	}

	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain)
	resp, err := e.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	var urls []string
	for i, row := range wrapper {
		if i == 0 { // Skip header row
			continue
		}
		if len(row) >= 3 {
			urls = append(urls, row[2])
		}
	}

	return urls, nil
}

// FetchCommonCrawl fetches URLs from CommonCrawl
func (e *ExternalSources) FetchCommonCrawl(domain string) ([]string, error) {
	subsWildcard := "*."
	if !e.includeSubs {
		subsWildcard = ""
	}

	url := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s%s/*&output=json", subsWildcard, domain)
	resp, err := e.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var urls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var item struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &item); err == nil && item.URL != "" {
			urls = append(urls, item.URL)
		}
	}

	return urls, nil
}

// FetchOTX fetches URLs from AlienVault OTX
func (e *ExternalSources) FetchOTX(domain string) ([]string, error) {
	var allURLs []string
	page := 0

	for {
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=50&page=%d", domain, page)
		resp, err := e.client.Get(url)
		if err != nil {
			return allURLs, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return allURLs, err
		}

		var wrapper struct {
			HasNext bool `json:"has_next"`
			URLList []struct {
				URL string `json:"url"`
			} `json:"url_list"`
		}

		if err := json.Unmarshal(body, &wrapper); err != nil {
			return allURLs, err
		}

		for _, item := range wrapper.URLList {
			allURLs = append(allURLs, item.URL)
		}

		if !wrapper.HasNext {
			break
		}
		page++

		if page > 10 { // Limit pages to avoid long waits
			break
		}
	}

	return allURLs, nil
}
