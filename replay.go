package main

import (
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	replayPrefix   = "__replay_"
	maxReplayBytes = 16 << 10
)

type replayField struct {
	Name, Value string
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	o, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && o.Host != "" && o.Host == r.Host
}

func replayValues(r *http.Request) url.Values {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		return nil
	}
	if r.URL.Path == "/__verify" {
		out := url.Values{}
		for k, v := range r.PostForm {
			if name, ok := strings.CutPrefix(k, replayPrefix); ok && name != "" {
				out[name] = v
			}
		}
		return out
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/x-www-form-urlencoded" || r.ContentLength <= 0 || r.ContentLength > maxReplayBytes {
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return nil
	}
	return r.PostForm
}

func replayFields(v url.Values) []replayField {
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []replayField
	for _, name := range names {
		for _, value := range v[name] {
			out = append(out, replayField{name, value})
		}
	}
	return out
}

var resubmitTpl = template.Must(template.New("resubmit").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Continuing</title>
<style nonce="{{.Nonce}}">body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0}button{font:inherit;padding:.6em 1.4em;cursor:pointer}</style>
</head><body>
<form id="resubmit" method="POST" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<p>Verified. Sending your request again.</p>
<button type="submit">Continue</button>
</form>
<script nonce="{{.Nonce}}">document.getElementById('resubmit').submit();</script>
</body></html>`))

func finishVerify(w http.ResponseWriter, r *http.Request, returnTo string) {
	fields := replayFields(replayValues(r))
	nonce, err := cspNonce()
	if len(fields) == 0 || err != nil {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; form-action 'self'; frame-ancestors 'none'")
	_ = resubmitTpl.Execute(w, map[string]interface{}{"Action": returnTo, "Fields": fields, "Nonce": nonce})
}
