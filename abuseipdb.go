package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

func reportIP(cfg *Config, ip string, walkaways, banCount int, paths []string) {
	if !cfg.AbuseIPDB.Enabled || cfg.AbuseIPDB.APIKey == "" {
		return
	}
	go func() {
		comment := cfg.AbuseIPDB.Comment
		if len(paths) > 0 {
			shown := paths
			if len(shown) > 10 {
				shown = shown[len(shown)-10:]
			}
			comment = strings.TrimSpace(comment + " | paths: " + strings.Join(shown, ", "))
		}
		client := &http.Client{Timeout: 8 * time.Second}
		form := url.Values{
			"ip":         {ip},
			"categories": {cfg.AbuseIPDB.Categories},
			"comment":    {comment},
		}
		req, err := http.NewRequest("POST", "https://api.abuseipdb.com/api/v2/report", nil)
		if err != nil {
			log.Printf("abuseipdb: build request: %v", err)
			return
		}
		req.URL.RawQuery = form.Encode()
		req.Header.Set("Key", cfg.AbuseIPDB.APIKey)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("abuseipdb: report failed for %s: %v", ip, err)
			return
		}
		defer resp.Body.Close()
		log.Printf("reported %s to AbuseIPDB after %d walk-aways, ban #%d (status %d)", ip, walkaways, banCount, resp.StatusCode)
	}()
}

func fetchAbuseIPDBBlacklist(cfg *Config) (*ipTrie, int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", "https://api.abuseipdb.com/api/v2/blacklist", nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Key", cfg.AbuseIPDB.APIKey)
	req.Header.Set("Accept", "text/csv")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("blacklist: unexpected status %d", resp.StatusCode)
	}

	return parseAbuseIPDBBlacklist(resp.Body)
}

func parseAbuseIPDBBlacklist(r io.Reader) (*ipTrie, int, error) {
	trie := newIPTrie()
	count := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, ','); i > 0 {
			line = line[:i]
		}
		ipNet, err := parseCIDROrIP(line)
		if err != nil {
			continue
		}
		trie.Insert(ipNet)
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("blacklist: no IPs parsed from response")
	}
	return trie, count, nil
}

func startBlacklistFetcher(cfg *Config, box *atomic.Value) {
	fetch := func() {
		trie, count, err := fetchAbuseIPDBBlacklist(cfg)
		if err != nil {
			log.Printf("abuseipdb blacklist: fetch failed: %v", err)
			return
		}
		box.Store(trie)
		log.Printf("abuseipdb blacklist: loaded %d IPs", count)
	}
	fetch()
	if cfg.AbuseIPDB.Blacklist.Refresh.Duration > 0 {
		ticker := time.NewTicker(cfg.AbuseIPDB.Blacklist.Refresh.Duration)
		for range ticker.C {
			fetch()
		}
	}
}
