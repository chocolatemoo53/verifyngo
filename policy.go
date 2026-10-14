package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/oschwald/geoip2-golang"
	"gopkg.in/yaml.v3"
)

type policyFile struct {
	Networks   map[string][]policyNetworkEntry `yaml:"networks"`
	Conditions map[string][]string             `yaml:"conditions"`
	Rules      []policyRule                    `yaml:"rules"`
}

type policyNetworkEntry struct {
	URL      *string  `yaml:"url,omitempty"`
	File     *string  `yaml:"file,omitempty"`
	ASN      *int     `yaml:"asn,omitempty"`
	JQPath   *string  `yaml:"jq-path,omitempty"`
	Regex    *string  `yaml:"regex,omitempty"`
	Prefixes []string `yaml:"prefixes,omitempty"`
	CIDR     string   `yaml:"cidr,omitempty"`
}

type policyRule struct {
	Name       string   `yaml:"name"`
	Action     string   `yaml:"action"`
	Condition  string   `yaml:"condition"`
	Conditions []string `yaml:"conditions"`
}

type networkGroup struct {
	trie *ipTrie
	asns map[uint]struct{}
}

type policyMatcher struct {
	networks map[string]networkGroup

	asnDB    *geoip2.Reader
	asnCache *lruCache
}

type ipTrieNode struct {
	children [2]*ipTrieNode
	isMatch  bool
}

type ipTrie struct {
	root4 *ipTrieNode
	root6 *ipTrieNode
}

func newIPTrie() *ipTrie {
	return &ipTrie{
		root4: &ipTrieNode{},
		root6: &ipTrieNode{},
	}
}

func (t *ipTrie) Insert(ipNet net.IPNet) {
	ip := ipNet.IP
	ones, _ := ipNet.Mask.Size()

	ip4 := ip.To4()
	var bytes []byte
	var curr *ipTrieNode
	if ip4 != nil {
		bytes = ip4
		curr = t.root4
	} else {
		ip6 := ip.To16()
		if ip6 == nil {
			return
		}
		bytes = ip6
		curr = t.root6
	}

	for bitIdx := 0; bitIdx < ones; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bit := (bytes[byteIdx] >> bitOffset) & 1

		if curr.children[bit] == nil {
			curr.children[bit] = &ipTrieNode{}
		}
		curr = curr.children[bit]
		if curr.isMatch {
			return
		}
	}
	curr.isMatch = true
}

func (t *ipTrie) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	var bytes []byte
	var curr *ipTrieNode
	if ip4 != nil {
		bytes = ip4
		curr = t.root4
	} else {
		ip6 := ip.To16()
		if ip6 == nil {
			return false
		}
		bytes = ip6
		curr = t.root6
	}

	if curr.isMatch {
		return true
	}

	totalBits := len(bytes) * 8
	for bitIdx := 0; bitIdx < totalBits; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bit := (bytes[byteIdx] >> bitOffset) & 1

		curr = curr.children[bit]
		if curr == nil {
			return false
		}
		if curr.isMatch {
			return true
		}
	}
	return false
}

type compiledCondition struct {
	expr       *govaluate.EvaluableExpression
	headerVars map[string]string
}

func compilePolicyFile(cfg *Config) ([]compiledRule, error) {
	raw, err := os.ReadFile(cfg.PolicyFile)
	if err != nil {
		return nil, err
	}
	var p policyFile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, err
	}

	matcher, err := buildPolicyMatcher(cfg, p.Networks)
	if err != nil {
		return nil, err
	}

	resolvedNames := map[string]string{}
	resolving := map[string]bool{}
	for name := range p.Conditions {
		if _, err := resolveConditionName(name, p.Conditions, resolvedNames, resolving); err != nil {
			return nil, err
		}
	}

	funcs := map[string]govaluate.ExpressionFunction{
		"contains": func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return false, nil
			}
			return strings.Contains(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
		},
		"startsWith": func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return false, nil
			}
			return strings.HasPrefix(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
		},
		"network": func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return false, nil
			}
			ip := net.ParseIP(fmt.Sprint(args[0]))
			if ip == nil {
				return false, nil
			}
			name := fmt.Sprint(args[1])
			return matcher.networkContains(ip, name), nil
		},
	}

	out := make([]compiledRule, 0, len(p.Rules))
	for i, r := range p.Rules {
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule-%d", i+1)
		}
		conds := append([]string(nil), r.Conditions...)
		if strings.TrimSpace(r.Condition) != "" {
			conds = append(conds, r.Condition)
		}

		compiledConds := make([]compiledCondition, 0, len(conds))
		for _, c := range conds {
			resolved, err := resolveConditionRefs(c, p.Conditions, resolvedNames, resolving)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
			prepared, headerVars, err := rewritePolicyExpression(resolved)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
			expr, err := govaluate.NewEvaluableExpressionWithFunctions(prepared, funcs)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid condition %q: %w", r.Name, c, err)
			}
			compiledConds = append(compiledConds, compiledCondition{expr: expr, headerVars: headerVars})
		}

		matchFn := func(_ *http.Request, _ net.IP) bool { return true }
		if len(compiledConds) > 0 {
			local := append([]compiledCondition(nil), compiledConds...)
			matchFn = func(req *http.Request, ip net.IP) bool {
				params := evalParamsPool.Get().(map[string]interface{})
				defer func() {
					for k := range params {
						delete(params, k)
					}
					evalParamsPool.Put(params)
				}()

				params["path"] = req.URL.Path
				params["userAgent"] = req.UserAgent()
				params["method"] = req.Method
				params["ip"] = ip.String()
				params["browserMismatch"] = browserMismatch(req, cfg)
				params["tor"] = torKind(req, cfg, ip)

				for _, cc := range local {
					for varName, headerName := range cc.headerVars {
						params[varName] = req.Header.Get(headerName)
					}
					if !cc.evalParams(params) {
						return false
					}
				}
				return true
			}
		}

		out = append(out, compiledRule{
			name:   name,
			action: normalizeAction(r.Action),
			match:  matchFn,
		})
	}

	return out, nil
}

var evalParamsPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 8)
	},
}

func buildPolicyMatcher(cfg *Config, groups map[string][]policyNetworkEntry) (*policyMatcher, error) {
	m := &policyMatcher{
		networks: make(map[string]networkGroup, len(groups)),
		asnCache: newLRUCache(maxASNCacheSize),
	}
	if cfg.ASN.GeoIPDBPath != "" {
		r, err := geoip2.Open(cfg.ASN.GeoIPDBPath)
		if err != nil {
			return nil, fmt.Errorf("asn.geoip_db_path: %w", err)
		}
		m.asnDB = r
		log.Printf("policy: loaded ASN GeoIP database from %s", cfg.ASN.GeoIPDBPath)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	whoisEnabled := cfg.ASN.WhoisEnabled
	whoisAddr := cfg.ASN.WhoisAddr
	if whoisAddr == "" {
		whoisAddr = "whois.radb.net:43"
	}
	whoisTimeout := cfg.ASN.WhoisTimeout.Duration
	if whoisTimeout == 0 {
		whoisTimeout = 30 * time.Second
	}
	whoisClient := &whoisRADb{Addr: whoisAddr, Timeout: whoisTimeout}

	for name, entries := range groups {
		g := networkGroup{
			trie: newIPTrie(),
			asns: map[uint]struct{}{},
		}
		prefixCount := 0
		for _, e := range entries {
			if e.ASN != nil {
				g.asns[uint(*e.ASN)] = struct{}{}
				if whoisEnabled {
					result, err := whoisClient.FetchASNets(*e.ASN)
					if err != nil {
						if cfg.ASN.WhoisStrict {
							return nil, fmt.Errorf("network %q: failed to fetch ASN %d: %w", name, *e.ASN, err)
						}
						log.Printf("policy: warning: failed to fetch ASN %d for %q: %v", *e.ASN, name, err)
					} else {
						for _, c := range result {
							g.trie.Insert(c)
							prefixCount++
						}
					}
				}
			}

			cidrs, err := e.FetchPrefixes(httpClient)
			if err != nil {
				return nil, fmt.Errorf("network %q: %w", name, err)
			}
			for _, c := range cidrs {
				g.trie.Insert(c)
				prefixCount++
			}
		}
		m.networks[name] = g
		log.Printf("policy: loaded network %q with %d prefixes and %d ASN ids", name, prefixCount, len(g.asns))
	}

	return m, nil
}

func (n policyNetworkEntry) FetchPrefixes(c *http.Client) (output []net.IPNet, err error) {
	if n.CIDR != "" {
		ipNet, err := parseCIDROrIP(n.CIDR)
		if err != nil {
			return nil, err
		}
		output = append(output, ipNet)
	}
	if len(n.Prefixes) > 0 {
		for _, prefix := range n.Prefixes {
			ipNet, err := parseCIDROrIP(prefix)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
	}

	var reader io.Reader
	if n.URL != nil {
		response, err := c.Get(*n.URL)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
		}
		reader = response.Body
	} else if n.File != nil {
		file, err := os.Open(*n.File)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}

	if reader == nil {
		if len(output) > 0 || n.ASN != nil {
			return output, nil
		}
		return nil, errors.New("no url, file, asn, cidr or prefixes specified")
	}

	data, err := io.ReadAll(io.LimitReader(reader, 64<<20))
	if err != nil {
		return nil, err
	}

	if n.JQPath != nil {
		var jsonData any
		err = json.Unmarshal(data, &jsonData)
		if err != nil {
			return nil, err
		}

		query, err := gojq.Parse(*n.JQPath)
		if err != nil {
			return nil, err
		}
		iter := query.Run(jsonData)
		for {
			value, more := iter.Next()
			if !more {
				break
			}
			if iterErr, ok := value.(error); ok {
				return nil, iterErr
			}
			if strValue, ok := value.(string); ok {
				ipNet, err := parseCIDROrIP(strValue)
				if err != nil {
					return nil, err
				}
				output = append(output, ipNet)
			} else {
				return nil, fmt.Errorf("invalid value from jq-query: %v", value)
			}
		}
		return output, nil
	}

	if n.Regex != nil {
		expr, err := regexp.Compile(*n.Regex)
		if err != nil {
			return nil, err
		}
		prefixName := expr.SubexpIndex("prefix")
		if prefixName == -1 {
			return nil, fmt.Errorf("invalid regex %q: could not find prefix named match", *n.Regex)
		}
		matches := expr.FindAllSubmatch(data, -1)
		for _, match := range matches {
			if prefixName >= len(match) {
				continue
			}
			matchName := string(match[prefixName])
			ipNet, err := parseCIDROrIP(matchName)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
		return output, nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ipNet, err := parseCIDROrIP(line)
		if err != nil {
			continue
		}
		output = append(output, ipNet)
	}
	if len(output) == 0 {
		return nil, errors.New("no jq-path or regex specified and no plain CIDR lines found")
	}
	return output, nil
}

func parseCIDROrIP(value string) (net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			return net.IPNet{}, fmt.Errorf("failed to parse CIDR: %s", err)
		}
		if ip4 := ip.To4(); ip4 != nil {
			return net.IPNet{IP: ip4, Mask: net.CIDRMask(len(ip4)*8, len(ip4)*8)}, nil
		}
		return net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)}, nil
	} else if ipNet != nil {
		return *ipNet, nil
	}
	return net.IPNet{}, errors.New("invalid CIDR")
}

func (c compiledCondition) evalParams(params map[string]interface{}) bool {
	v, err := c.expr.Evaluate(params)
	if err != nil {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

func (m *policyMatcher) networkContains(ip net.IP, name string) bool {
	g, ok := m.networks[name]
	if !ok {
		return false
	}
	if g.trie != nil && g.trie.Contains(ip) {
		return true
	}
	if len(g.asns) > 0 && m.asnDB != nil {
		asn := m.lookupASN(ip)
		if asn != 0 {
			_, ok := g.asns[asn]
			if ok {
				return true
			}
		}
	}
	return false
}

const maxASNCacheSize = 10000

func (m *policyMatcher) lookupASN(ip net.IP) uint {
	ipStr := ip.String()
	if cached := m.asnCache.Get(ipStr); cached != nil {
		return cached.(uint)
	}

	asn := uint(0)
	if m.asnDB != nil {
		rec, err := m.asnDB.ASN(ip)
		if err == nil {
			asn = rec.AutonomousSystemNumber
		}
	}
	m.asnCache.Put(ipStr, asn)
	return asn
}

var condRefRe = regexp.MustCompile(`\(\$([a-zA-Z0-9_-]+)\)`)
var headerRefRe = regexp.MustCompile(`headers\["([^"]+)"\]`)
var containsRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.contains\(`)
var startsWithRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.startsWith\(`)
var matchesRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.matches\(\s*`)

func resolveConditionName(name string, conds map[string][]string, cache map[string]string, resolving map[string]bool) (string, error) {
	if v, ok := cache[name]; ok {
		return v, nil
	}
	if resolving[name] {
		return "", fmt.Errorf("cyclic condition reference detected at %q", name)
	}
	exprs, ok := conds[name]
	if !ok {
		return "", fmt.Errorf("unknown condition reference %q", name)
	}
	resolving[name] = true
	parts := make([]string, 0, len(exprs))
	for _, expr := range exprs {
		resolved, err := resolveConditionRefs(expr, conds, cache, resolving)
		if err != nil {
			return "", err
		}
		parts = append(parts, "("+resolved+")")
	}
	resolving[name] = false
	joined := strings.Join(parts, " || ")
	cache[name] = joined
	return joined, nil
}

func resolveConditionRefs(expr string, conds map[string][]string, cache map[string]string, resolving map[string]bool) (string, error) {
	var resolveErr error
	resolved := condRefRe.ReplaceAllStringFunc(expr, func(token string) string {
		if resolveErr != nil {
			return token
		}
		matches := condRefRe.FindStringSubmatch(token)
		if len(matches) != 2 {
			return token
		}
		v, err := resolveConditionName(matches[1], conds, cache, resolving)
		if err != nil {
			resolveErr = err
			return token
		}
		return "(" + v + ")"
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	return resolved, nil
}

func rewritePolicyExpression(expr string) (string, map[string]string, error) {
	headerVars := map[string]string{}
	rewritten := headerRefRe.ReplaceAllStringFunc(expr, func(token string) string {
		matches := headerRefRe.FindStringSubmatch(token)
		if len(matches) != 2 {
			return token
		}
		h := matches[1]
		varName := "header_" + sanitizeIdentifier(h)
		headerVars[varName] = h
		return varName
	})

	rewritten = strings.ReplaceAll(rewritten, "remoteAddress.network(", "network(ip,")
	rewritten = containsRe.ReplaceAllString(rewritten, "contains($1,")
	rewritten = startsWithRe.ReplaceAllString(rewritten, "startsWith($1,")
	rewritten, err := rewriteMatches(rewritten)
	return rewritten, headerVars, err
}

func rewriteMatches(expr string) (string, error) {
	var b strings.Builder
	for {
		loc := matchesRe.FindStringSubmatchIndex(expr)
		if loc == nil {
			b.WriteString(expr)
			return b.String(), nil
		}
		lit, rest, ok := cutStringLiteral(expr[loc[1]:])
		rest = strings.TrimLeft(rest, " \t")
		if !ok || !strings.HasPrefix(rest, ")") {
			return "", fmt.Errorf("%s.matches() needs a quoted pattern", expr[loc[2]:loc[3]])
		}
		b.WriteString(expr[:loc[0]])
		b.WriteString("(" + expr[loc[2]:loc[3]] + " =~ " + lit + ")")
		expr = rest[1:]
	}
}

func cutStringLiteral(s string) (string, string, bool) {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return "", s, false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"', '\'':
			return s[:i+1], s[i+1:], true
		}
	}
	return "", s, false
}

func sanitizeIdentifier(v string) string {
	v = strings.ToLower(v)
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
