package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type whoisRADb struct {
	Addr    string
	Timeout time.Duration
}

func (w *whoisRADb) FetchASNets(asn int) ([]net.IPNet, error) {
	conn, err := net.DialTimeout("tcp", w.Addr, w.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(w.Timeout))

	query := fmt.Sprintf("-i origin AS%d\n", asn)
	if _, err := conn.Write([]byte(query)); err != nil {
		return nil, err
	}

	s := bufio.NewScanner(conn)
	seen := map[string]struct{}{}
	var out []net.IPNet
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "route:") || strings.HasPrefix(line, "route6:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			prefix := strings.TrimSpace(parts[1])
			_, n, err := net.ParseCIDR(prefix)
			if err != nil || n == nil {
				continue
			}
			key := n.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, *n)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no prefixes returned for AS%d", asn)
	}
	return out, nil
}
