package main

import (
	"net"
	"strings"
	"testing"
)

func TestParseAbuseIPDBBlacklist(t *testing.T) {
	csv := "IP Address,Country Code,ISO Code,Internet Service Provider,Domain,Usage Type,ASN,Last Reported\n" +
		"203.0.113.9,US,US,Test ISP,example.com,Data Center,13335,2026-08-16T10:00:00Z\n" +
		"2001:db8::1,US,US,Test ISP,example.com,Data Center,13335,2026-08-16T10:00:00Z\n" +
		"not-an-ip,garbage\n"
	trie, count, err := parseAbuseIPDBBlacklist(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 IPs, got %d", count)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.9", true},
		{"2001:db8::1", true},
		{"8.8.8.8", false},
		{"198.51.100.1", false},
	}
	for _, c := range cases {
		got := trie.Contains(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestParseAbuseIPDBBlacklistEmpty(t *testing.T) {
	if _, _, err := parseAbuseIPDBBlacklist(strings.NewReader("# no ips here\n")); err == nil {
		t.Fatal("expected error for empty blacklist")
	}
}
