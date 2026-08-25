package main

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"strings"
)

//go:embed tarpit_corpus.txt
var embeddedCorpus embed.FS

type tarpitGenerator struct {
	chain     map[string][]string
	pairIndex map[string]int
	pairs     []string
	start     []int
}

func newTarpitGenerator(corpus string) *tarpitGenerator {
	g := &tarpitGenerator{
		chain:     make(map[string][]string),
		pairIndex: make(map[string]int),
	}
	fields := strings.Fields(strings.ToLower(corpus))
	clean := make([]string, 0, len(fields))
	sentStart := make([]bool, 0, len(fields))
	begin := true
	for _, w := range fields {
		endsSentence := strings.ContainsAny(w[len(w)-1:], ".!?")
		w = strings.Trim(w, "\"'“”‘’()[]{}*,.;:!?—–-")
		if len(w) > 1 && isAlphaWord(w) {
			clean = append(clean, w)
			sentStart = append(sentStart, begin)
			begin = endsSentence
		} else if endsSentence {
			begin = true
		}
	}
	for i := 0; i+2 < len(clean); i++ {
		key := clean[i] + " " + clean[i+1]
		idx, ok := g.pairIndex[key]
		if !ok {
			idx = len(g.pairs)
			g.pairIndex[key] = idx
			g.pairs = append(g.pairs, key)
		}
		g.chain[key] = append(g.chain[key], clean[i+2])
		if sentStart[i] {
			g.start = append(g.start, idx)
		}
	}
	return g
}

func isAlphaWord(w string) bool {
	for _, r := range w {
		if (r < 'a' || r > 'z') && r != '-' {
			return false
		}
	}
	return true
}

type tarpitPage struct {
	Title      string
	Paragraphs []string
	MazeLinks  []string
}

func (g *tarpitGenerator) generate(seed uint64) tarpitPage {
	rng := rand.New(rand.NewSource(int64(seed)))
	page := tarpitPage{}
	first := true

	paras := 3 + rng.Intn(4)
	for p := 0; p < paras; p++ {
		var b strings.Builder
		words := 40 + rng.Intn(80)
		sentenceLeft := 6 + rng.Intn(12)
		written := 0

		key := g.randomStart(rng)
		var prev1, prev2 string
		if key != "" {
			parts := strings.SplitN(key, " ", 2)
			prev2, prev1 = parts[0], parts[1]
			b.WriteString(strings.ToUpper(prev2[:1]) + prev2[1:])
			b.WriteString(" ")
			b.WriteString(prev1)
			b.WriteString(" ")
			written = 2
			sentenceLeft -= 2
		}
		for written < words && key != "" {
			nexts := g.chain[prev2+" "+prev1]
			if len(nexts) == 0 {
				break
			}
			word := nexts[rng.Intn(len(nexts))]
			sentenceLeft--
			if sentenceLeft <= 0 {
				b.WriteString(word + ". ")
				sentenceLeft = 6 + rng.Intn(12)
				key = g.randomStart(rng)
				if key != "" {
					parts := strings.SplitN(key, " ", 2)
					prev2, prev1 = parts[0], parts[1]
				}
			} else {
				b.WriteString(word + " ")
				prev2, prev1 = prev1, word
			}
			written++
		}
		text := strings.TrimSpace(b.String())
		if text == "" {
			continue
		}
		if !strings.HasSuffix(text, ".") {
			text += "."
		}
		if first {
			page.Title = firstSentence(text, 8)
			first = false
		}
		page.Paragraphs = append(page.Paragraphs, text)
	}

	slugs := 4 + rng.Intn(4)
	for i := 0; i < slugs; i++ {
		key := g.pairs[rng.Intn(len(g.pairs))]
		page.MazeLinks = append(page.MazeLinks, strings.ReplaceAll(key, " ", "-"))
	}
	return page
}

func (g *tarpitGenerator) randomStart(rng *rand.Rand) string {
	if len(g.start) > 0 {
		return g.pairs[g.start[rng.Intn(len(g.start))]]
	}
	if len(g.pairs) == 0 {
		return ""
	}
	return g.pairs[rng.Intn(len(g.pairs))]
}

func firstSentence(s string, maxWords int) string {
	if i := strings.Index(s, "."); i > 0 {
		s = s[:i]
	}
	words := strings.Fields(s)
	if len(words) > maxWords {
		words = words[:maxWords]
	}
	return strings.Join(words, " ")
}

func tarpitSeed(secret, reqPath string) uint64 {
	h := sha256.Sum256([]byte(secret + "|" + reqPath))
	return binary.BigEndian.Uint64(h[:8])
}

const tarpitTplSrc = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title></head>
<body>
<article>
<h1>{{.Title}}</h1>
{{range .Paragraphs}}<p>{{.}}</p>
{{end}}<h2>Related reading</h2>
<ul>{{range .MazeLinks}}
<li><a href="{{.}}">{{.}}</a></li>
{{end}}</ul>
</article>
</body></html>`

var tarpitTpl = template.Must(template.New("tarpit").Parse(tarpitTplSrc))

func serveTarpit(w http.ResponseWriter, r *http.Request, cfg *Config) {
	g := cfg.tarpitGen
	if g == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	page := g.generate(tarpitSeed(cfg.tarpitSeedStr, r.URL.Path))

	base := path.Dir(r.URL.Path)
	links := make([]string, 0, len(page.MazeLinks))
	for i, slug := range page.MazeLinks {
		if i%2 == 0 {
			links = append(links, path.Join(base, slug))
		} else {
			links = append(links, path.Join(r.URL.Path, slug))
		}
	}
	page.MazeLinks = links

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = tarpitTpl.Execute(w, page)
}

func loadTarpitGenerator(cfg *Config) {
	corpus := readEmbeddedCorpus()
	if cfg.Tarpit.Corpus != "" {
		raw, err := os.ReadFile(cfg.Tarpit.Corpus)
		if err != nil {
			log.Printf("tarpit: failed reading corpus %s (%v); using built-in corpus", cfg.Tarpit.Corpus, err)
		} else if len(strings.Fields(string(raw))) > 200 {
			corpus = string(raw)
		} else {
			log.Printf("tarpit: corpus %s too small; using built-in corpus", cfg.Tarpit.Corpus)
		}
	}
	cfg.tarpitGen = newTarpitGenerator(corpus)
}

func readEmbeddedCorpus() string {
	raw, err := embeddedCorpus.ReadFile("tarpit_corpus.txt")
	if err != nil {
		log.Printf("tarpit: embedded corpus missing: %v", err)
		return ""
	}
	return string(raw)
}
