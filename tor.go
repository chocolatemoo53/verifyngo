package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const torExitListURL = "https://check.torproject.org/torbulkexitlist"

var torCircuitNet = &net.IPNet{IP: net.ParseIP("fc00:dead:beef:4dad::"), Mask: net.CIDRMask(64, 128)}

func torKind(r *http.Request, cfg *Config, ip net.IP) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if torCircuitNet.Contains(ip) {
		return "onion"
	}
	if (ip.IsLoopback() || ip.IsPrivate()) && strings.HasSuffix(strings.ToLower(host), ".onion") {
		return "onion"
	}
	if trie, ok := cfg.torExits.Load().(*ipTrie); ok && trie.Contains(ip) {
		return "exit"
	}
	return ""
}

func sharedTorIP(kind string, ip net.IP) bool {
	return kind == "exit" || (kind == "onion" && !torCircuitNet.Contains(ip))
}

func clientNetwork(ip net.IP) string {
	if torCircuitNet.Contains(ip) {
		return ip.String()
	}
	return anonymizeIP(ip).String()
}

func fetchTorExits(client *http.Client) (*ipTrie, int, error) {
	resp, err := client.Get(torExitListURL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return parseIPList(resp.Body)
}

func startTorExitFetcher(cfg *Config) {
	client := &http.Client{Timeout: 30 * time.Second}
	for {
		trie, count, err := fetchTorExits(client)
		if err != nil {
			log.Printf("tor exit list: fetch failed: %v", err)
		} else {
			cfg.torExits.Store(trie)
			metricTorExits.Set(float64(count))
			log.Printf("tor exit list: loaded %d exits", count)
		}
		time.Sleep(cfg.Tor.Refresh.Duration)
	}
}
