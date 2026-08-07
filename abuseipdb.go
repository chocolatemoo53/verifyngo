package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"
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
