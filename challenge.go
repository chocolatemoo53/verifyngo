package main

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"verifyngo/providers"
)

func requestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

const challengeTpl = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Title}}{{.Title}}{{else}}Verifying...{{end}}</title>
<script src="{{.ScriptURL}}" async defer></script>
{{if eq .Provider "hcaptcha"}}
<script>
  window.hcaptchaOnLoad = function () {
    var renderIfReady = function() {
      if (window.hcaptcha && typeof hcaptcha.render === 'function') {
        hcaptcha.render('hcaptcha-el', { sitekey: '{{.SiteKey}}', callback: onSolve, theme: '{{.WidgetTheme}}' });
        return true;
      }
      return false;
    };
    if (!renderIfReady()) {
      var tries = 0;
      var t = setInterval(function() {
        if (renderIfReady() || ++tries > 50) {
          clearInterval(t);
        }
      }, 100);
    }
  };
  function onSolve(token) {
    var f = document.getElementById('hcaptcha-form');
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = 'token'; i.value = token;
    f.appendChild(i);
    f.submit();
  }
</script>
{{end}}
{{if .FontURL}}<link rel="stylesheet" href="{{.FontURL}}">{{end}}
<style>
  :root {
    --cp-accent: {{.AccentColor}};
    --cp-bg: {{.BackgroundColor}};
    --cp-text: {{.TextColor}};
    --cp-font: {{.FontFamily}};
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: var(--cp-bg);
    color: var(--cp-text);
    font-family: var(--cp-font);
  }
  body.verifyngo-challenge {
    min-height: 100vh;
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 1.25rem;
  }
  main.verifyngo-card {
    width: 100%;
    max-width: 30rem;
    text-align: center;
    padding: 2rem 1.75rem;
    border-radius: 14px;
    background: color-mix(in srgb, var(--cp-bg) 85%, white 6%);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);
  }
  .verifyngo-logo {
    max-width: 4rem;
    width: 25%;
    height: auto;
    margin-bottom: 1rem;
  }
  .verifyngo-title {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--cp-accent);
    margin: 0 0 0.75rem;
  }
  .verifyngo-status {
    font-size: 0.95rem;
    line-height: 1.5;
    color: color-mix(in srgb, var(--cp-text) 85%, transparent);
    margin: 0 0 1rem;
  }
  .verifyngo-status em { color: var(--cp-accent); font-style: normal; }
  .verifyngo-widget {
    margin: 1.25rem 0;
  }
  cap-widget, .cf-turnstile {
    display: inline-block;
    max-width: 100%;
  }
  details.verifyngo-details {
    text-align: left;
    margin: 1.25rem 0 0.5rem;
    font-size: 0.85rem;
    color: color-mix(in srgb, var(--cp-text) 70%, transparent);
  }
  details.verifyngo-details summary {
    cursor: pointer;
    color: var(--cp-accent);
    font-weight: 600;
    margin-bottom: 0.5rem;
  }
  footer.verifyngo-footer {
    text-align: center;
    margin-top: 1rem;
    font-size: 0.8rem;
    color: color-mix(in srgb, var(--cp-text) 55%, transparent);
  }
  footer.verifyngo-footer a,
  footer.verifyngo-footer a:visited {
    color: var(--cp-accent);
    text-decoration: underline;
  }
  @media (max-width: 380px) {
    main.verifyngo-card { padding: 1.5rem 1.25rem; border-radius: 10px; }
    .verifyngo-title { font-size: 1.2rem; }
    .verifyngo-status { font-size: 0.9rem; }
  }
</style>
{{if .CSSURL}}<link rel="stylesheet" href="{{.CSSURL}}">{{end}}
</head><body class="verifyngo-challenge">
<main class="verifyngo-card">
  {{if .LogoURL}}<img class="verifyngo-logo" src="{{.LogoURL}}" alt="{{.Title}}">{{end}}
  <h1 class="verifyngo-title">{{if .Title}}{{.Title}}{{else}}Checking you are not a bot{{end}}</h1>
  <p class="verifyngo-status">Please complete the <em>{{.ChallengeName}}</em> challenge below to verify you are not a bot...</p>

  <div class="verifyngo-widget">
  <input type="hidden" id="verifyngo-return-to" value="{{.ReturnTo}}">
  {{if eq .Provider "cap"}}
  <cap-widget id="widget" data-cap-api-endpoint="{{.APIURL}}/{{.SiteKey}}/"></cap-widget>
  <script>
    document.getElementById('widget').addEventListener('solve', function(e){
      var f = document.createElement('form');
      f.method = 'POST'; f.action = '/__verify';
      var i = document.createElement('input');
      i.type='hidden'; i.name='token'; i.value = e.detail.token;
      f.appendChild(i);
      var rt = document.getElementById('verifyngo-return-to');
      var r = document.createElement('input');
      r.type='hidden'; r.name='return_to'; r.value = rt ? rt.value : '/';
      f.appendChild(r);
      document.body.appendChild(f); f.submit();
    });
  </script>
  {{else if eq .Provider "hcaptcha"}}
  <form id="hcaptcha-form" method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <div id="hcaptcha-el"></div>
  </form>
  {{else}}
  <form method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="onSolve" data-theme="{{.WidgetTheme}}"></div>
    <script>function onSolve(token){
      var i=document.createElement('input'); i.type='hidden'; i.name='token'; i.value=token;
      document.currentScript.parentElement.parentElement.appendChild(i);
      document.currentScript.parentElement.parentElement.submit();
    }</script>
  </form>
  {{end}}

  <!-- provider switcher injected when multiple providers available -->
  {{if .ProviderSwitcher}}
    <div style="margin-top:0.5rem">{{.ProviderSwitcher}}</div>
  {{end}}

  </div>

  <details class="verifyngo-details">
    <summary>Why am I seeing this?</summary>
    <p>{{.DetailsText}}</p>
  </details>
</main>
<footer class="verifyngo-footer">
  Request Id <em>{{.RequestID}}</em>{{if .ContactURL}} | <a href="{{.ContactURL}}">Contact</a>{{end}}
</footer>
</body></html>`

var tpl = template.Must(template.New("challenge").Parse(challengeTpl))

func serveChallenge(w http.ResponseWriter, r *http.Request, cfg *Config, apiURL, ip, requestURI string, logServed bool) {
	id := requestID()
	if logServed {
		log.Printf("challenge served id=%s ip=%s path=%s", id, ip, requestURI)
	}

	provider := providerForRequest(cfg, r)

	var switcher template.HTML
	available := availableProviders(cfg)
	if len(available) > 1 {
		var b strings.Builder
		b.WriteString("<div style='margin-top:0.75rem;font-size:0.9rem;color:var(--cp-text);opacity:0.85'>Switch captcha: ")
		for i, p := range available {
			if p == provider {
				b.WriteString("<strong style='color:var(--cp-accent)'>")
				b.WriteString(p)
				b.WriteString("</strong>")
			} else {
				u := url.URL{
					Path:     "/__set_provider",
					RawQuery: "provider=" + url.QueryEscape(p) + "&return_to=" + url.QueryEscape(requestURI),
				}

				b.WriteString("<a href=\"")
				b.WriteString(u.String())
				b.WriteString("\" style='color:var(--cp-accent);text-decoration:underline;margin:0 0.25rem;'>")
				b.WriteString(p)
				b.WriteString("</a>")
			}
			if i < len(available)-1 {
				b.WriteString(" ")
			}
		}
		b.WriteString("</div>")
		switcher = template.HTML(b.String())
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_ = tpl.Execute(w, map[string]interface{}{
		"Provider":         provider,
		"ScriptURL":        scriptURLForRequest(cfg, r),
		"APIURL":           apiURL,
		"SiteKey":          siteKeyForRequest(cfg, r),
		"LogoURL":          cfg.Branding.LogoURL,
		"CSSURL":           cfg.Branding.CSSURL,
		"Title":            cfg.Branding.Title,
		"AccentColor":      cfg.Branding.AccentColor,
		"BackgroundColor":  cfg.Branding.BackgroundColor,
		"TextColor":        cfg.Branding.TextColor,
		"FontFamily":       cfg.Branding.FontFamily,
		"FontURL":          cfg.Branding.FontURL,
		"DetailsText":      cfg.Branding.DetailsText,
		"ContactURL":       cfg.Branding.ContactURL,
		"RequestID":        id,
		"ChallengeName":    provider,
		"ReturnTo":         requestURI,
		"ProviderSwitcher": switcher,
		"WidgetTheme":      widgetTheme(cfg.Branding.BackgroundColor),
	})
}

func widgetTheme(bgHex string) string {
	bgHex = strings.TrimPrefix(bgHex, "#")
	if len(bgHex) != 6 {
		return "light"
	}
	r, err1 := strconv.ParseInt(bgHex[0:2], 16, 0)
	g, err2 := strconv.ParseInt(bgHex[2:4], 16, 0)
	b, err3 := strconv.ParseInt(bgHex[4:6], 16, 0)
	if err1 != nil || err2 != nil || err3 != nil {
		return "light"
	}
	luminance := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 255
	if luminance < 0.5 {
		return "dark"
	}
	return "light"
}

func sanitizeReturnPath(path string) string {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "/"
	}
	if strings.ContainsAny(path, "\r\n") {
		return "/"
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return path
}

func providerForRequest(cfg *Config, r *http.Request) string {
	if ck, err := r.Cookie("cp_provider"); err == nil && ck.Value != "" {
		p := ck.Value
		switch p {
		case "cap":
			if cfg.Cap.SiteKey != "" {
				return "cap"
			}
		case "turnstile":
			if cfg.Turnstile.SiteKey != "" {
				return "turnstile"
			}
		case "hcaptcha":
			if cfg.HCaptcha.SiteKey != "" {
				return "hcaptcha"
			}
		}
	}
	if cfg.Provider != "" {
		return cfg.Provider
	}
	if cfg.Cap.SiteKey != "" {
		return "cap"
	}
	if cfg.HCaptcha.SiteKey != "" {
		return "hcaptcha"
	}
	return "turnstile"
}

func availableProviders(cfg *Config) []string {
	out := []string{}
	if cfg.Cap.SiteKey != "" {
		out = append(out, "cap")
	}
	if cfg.Turnstile.SiteKey != "" {
		out = append(out, "turnstile")
	}
	if cfg.HCaptcha.SiteKey != "" {
		out = append(out, "hcaptcha")
	}
	return out
}

func scriptURLForRequest(cfg *Config, r *http.Request) string {
	switch providerForRequest(cfg, r) {
	case "cap":
		if cfg.Cap.WidgetScriptURL != "" {
			return cfg.Cap.WidgetScriptURL
		}
		return "https://cdn.jsdelivr.net/npm/@cap.js/widget"
	case "hcaptcha":
		h := &providers.HCaptcha{}
		return h.WidgetScriptURL()
	default:
		t := &providers.Turnstile{}
		return t.WidgetScriptURL()
	}
}

func siteKeyForRequest(cfg *Config, r *http.Request) string {
	switch providerForRequest(cfg, r) {
	case "cap":
		return cfg.Cap.SiteKey
	case "hcaptcha":
		return cfg.HCaptcha.SiteKey
	default:
		return cfg.Turnstile.SiteKey
	}
}

func buildVerifierForProvider(cfg *Config, provider string) providers.Verifier {
	switch provider {
	case "cap":
		return &providers.Cap{
			APIURL:    cfg.Cap.APIURL,
			VerifyURL: cfg.Cap.VerifyURL,
			SiteKeyV:  cfg.Cap.SiteKey,
			SecretKey: cfg.Cap.SecretKey,
		}
	case "hcaptcha":
		return &providers.HCaptcha{
			SiteKeyV:  cfg.HCaptcha.SiteKey,
			SecretKey: cfg.HCaptcha.SecretKey,
		}
	default:
		return &providers.Turnstile{
			SiteKeyV:  cfg.Turnstile.SiteKey,
			SecretKey: cfg.Turnstile.SecretKey,
		}
	}
}

func buildVerifier(cfg *Config) providers.Verifier {
	return buildVerifierForProvider(cfg, cfg.Provider)
}
