package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type compiledRule struct {
	action string
	match  func(*http.Request, net.IP) bool
}

func compileLegacyRules(rawRules []Rule) ([]compiledRule, error) {
	var out []compiledRule
	for _, r := range rawRules {
		action := normalizeAction(r.Action)
		pathExpr := strings.TrimSpace(r.Match.Path)
		uaExpr := strings.TrimSpace(r.Match.UA)
		cidrList := append([]string(nil), r.Match.CIDR...)

		var pathRe *regexp.Regexp
		if pathExpr != "" {
			re, err := regexp.Compile(pathExpr)
			if err != nil {
				return nil, err
			}
			pathRe = re
		}

		var uaRe *regexp.Regexp
		if uaExpr != "" {
			re, err := regexp.Compile(uaExpr)
			if err != nil {
				return nil, err
			}
			uaRe = re
		}

		var nets []*net.IPNet
		for _, c := range cidrList {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, err
			}
			nets = append(nets, n)
		}

		out = append(out, compiledRule{
			action: action,
			match: func(req *http.Request, ip net.IP) bool {
				if pathRe != nil && !pathRe.MatchString(req.URL.Path) {
					return false
				}
				if uaRe != nil && !uaRe.MatchString(req.UserAgent()) {
					return false
				}
				if len(nets) > 0 {
					for _, n := range nets {
						if n.Contains(ip) {
							return true
						}
					}
					return false
				}
				return true
			},
		})
	}
	return out, nil
}

func evaluate(rules []compiledRule, defaultAction string, r *http.Request, ip net.IP) string {
	for _, rule := range rules {
		if rule.match != nil && !rule.match(r, ip) {
			continue
		}
		return rule.action
	}
	return normalizeAction(defaultAction)
}

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "pass":
		return "allow"
	case "deny", "drop":
		return "deny"
	case "challenge", "check", "none":
		return "challenge"
	default:
		return "challenge"
	}
}

var validActions = map[string]bool{
	"allow": true, "pass": true,
	"deny": true, "drop": true,
	"challenge": true, "check": true, "none": true,
}

type compiledWhitelist struct {
	ips   []net.IP
	cidrs []*net.IPNet
}

func compileWhitelist(raw []string) compiledWhitelist {
	var cw compiledWhitelist
	for _, w := range raw {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(w); err == nil {
			cw.cidrs = append(cw.cidrs, n)
		} else if ip := net.ParseIP(w); ip != nil {
			cw.ips = append(cw.ips, ip)
		}
	}
	return cw
}

func (cw compiledWhitelist) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, single := range cw.ips {
		if single.Equal(ip) {
			return true
		}
	}
	for _, n := range cw.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ipAllowlisted(cfg *Config, ip net.IP) bool {
	return cfg.compiledWhitelist.contains(ip)
}

func loadRulesFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) < 3 {
			return nil, fmt.Errorf("%s:%d: expected '<action> <type> <pattern>', got %q", path, lineNo, line)
		}
		action := strings.ToLower(fields[0])
		matchType := strings.ToLower(fields[1])
		pattern := strings.TrimSpace(fields[2])

		if !validActions[action] {
			return nil, fmt.Errorf("%s:%d: unknown action %q", path, lineNo, action)
		}

		var r Rule
		r.Action = action
		switch matchType {
		case "path":
			r.Match.Path = pattern
		case "ua":
			r.Match.UA = pattern
		case "cidr":
			r.Match.CIDR = []string{pattern}
		default:
			return nil, fmt.Errorf("%s:%d: unknown match type %q (want path/ua/cidr)", path, lineNo, matchType)
		}
		rules = append(rules, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func loadCompiledRules(cfg *Config) ([]compiledRule, error) {
	if cfg.PolicyFile != "" {
		return compilePolicyFile(cfg)
	}
	if cfg.RulesFile != "" {
		rules, err := loadRulesFile(cfg.RulesFile)
		if err != nil {
			return nil, err
		}
		return compileLegacyRules(rules)
	}
	return compileLegacyRules(cfg.Rules)
}
