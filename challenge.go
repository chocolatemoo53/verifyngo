package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"verifyngo/providers"
)

func requestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

const tryAgainMessage = "Try again."

var sliderSpotWidths = []int{220, 280, 420}

const trapHTML = `<div hidden aria-hidden="true"><a href="/__cp_trap" rel="nofollow" tabindex="-1">Directory Index</a></div>`

const challengeTpl = `<!DOCTYPE html>
<html lang="{{.Lang}}"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .ErrorMsg}}Error: {{end}}{{if .Title}}{{.Title}}{{else}}Verifying...{{end}}</title>
{{if .SliderSwitchURL}}<noscript><meta http-equiv="refresh" content="2;url={{.SliderSwitchURL}}"></noscript>{{end}}
{{if .WaitRefreshURL}}<meta http-equiv="refresh" content="{{.TimedRemaining}};url={{.WaitRefreshURL}}">{{end}}
{{if .Nonce}}
<script nonce="{{.Nonce}}">
  window.CAP_CSS_NONCE = '{{.Nonce}}';
  window.CAP_SCRIPT_NONCE = window.CAP_CSS_NONCE;
{{- if .CapAssetsURL}}
  window.CAP_CUSTOM_WASM_URL = '{{.CapAssetsURL}}/cap_wasm_bg.wasm';
  window.CAP_CUSTOM_HASHWX_URL = '{{.CapAssetsURL}}/hashwx.wasm';
  window.CAP_PAKO_URL = '{{.CapAssetsURL}}/pako_inflate.min.js';
{{- end}}
</script>
{{end}}
{{if .ScriptURL}}<script src="{{.ScriptURL}}" async defer nonce="{{.Nonce}}"></script>{{end}}
{{if eq .Provider "hcaptcha"}}
<script nonce="{{.Nonce}}">
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
<style nonce="{{.Nonce}}">
  :root {
    --cp-accent: {{.AccentColor}};
    --cp-bg: {{.BackgroundColor}};
    --cp-text: {{.TextColor}};
    --cp-font: {{.FontFamily}};
  }
  * { box-sizing: border-box; }
  button, input, select, textarea { font-family: inherit; }
  :focus-visible {
    outline: 2px solid var(--cp-accent);
    outline-offset: 2px;
  }
  html, body {
    margin: 0;
    padding: 0;
    background: {{.BackgroundColor}};
    background: var(--cp-bg);
    color: {{.TextColor}};
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
    position: relative;
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
    color: var(--cp-text);
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
    color: var(--cp-text);
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
    color: var(--cp-text);
  }
  footer.verifyngo-footer a,
  footer.verifyngo-footer a:visited {
    color: var(--cp-accent);
    text-decoration: underline;
  }
  .verifyngo-switch-wrap {
    margin-top: 0.5rem;
  }
  .verifyngo-switch {
    margin-top: 0.75rem;
    font-size: 0.9rem;
    color: var(--cp-text);
  }
  .verifyngo-switch-label {
    display: block;
    margin-bottom: 0.5rem;
    text-align: center;
  }
  .verifyngo-switch-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(4.5rem, 1fr));
    gap: 0.5rem;
  }
  .verifyngo-switch-current,
  .verifyngo-switch a,
  .verifyngo-switch a:visited {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0.35rem 0.3rem;
    border-radius: 12px;
    text-align: center;
    text-transform: uppercase;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    text-decoration: none;
  }
  .verifyngo-switch-current {
    color: {{.AccentTextColor}};
    background: {{.AccentColor}};
    background: var(--cp-accent);
  }
  .verifyngo-switch a,
  .verifyngo-switch a:visited {
    color: {{.AccentColor}};
    color: var(--cp-accent);
    border: 1px solid {{.AccentColor}};
    border: 1px solid var(--cp-accent);
  }
  .verifyngo-submit {
    margin-top: 1rem;
    padding: 0.7rem 1.6rem;
    font-size: 1rem;
    font-weight: 600;
    color: {{.AccentTextColor}};
    background: {{.AccentColor}};
    background: var(--cp-accent);
    border: none;
    border-radius: 8px;
    cursor: pointer;
  }
  .verifyngo-submit:hover { filter: brightness(1.1); }
  .verifyngo-jigsaw {
    position: relative;
    width: 100%;
    max-width: 24rem;
    margin: 0 auto;
  }
  .verifyngo-jigsaw img {
    display: block;
    width: 100%;
    height: auto;
    border-radius: 8px;
  }
  .verifyngo-jigsaw-grid {
    position: absolute;
    inset: 0;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    grid-template-rows: repeat(3, 1fr);
  }
  .verifyngo-tile-input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
  }
  .verifyngo-tile {
    position: relative;
    cursor: pointer;
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.35);
  }
  .verifyngo-tile-input:checked + .verifyngo-tile {
    box-shadow: inset 0 0 0 5px #fff, inset 0 0 0 8px #000;
  }
  .verifyngo-tile-input:checked + .verifyngo-tile::after {
    content: "\2713";
    position: absolute;
    top: 0.6rem;
    right: 0.6rem;
    width: 1.8rem;
    height: 1.8rem;
    line-height: 1.8rem;
    border-radius: 50%;
    text-align: center;
    font-weight: 700;
    color: #000;
    background: #fff;
  }
  .verifyngo-tile-input:focus-visible + .verifyngo-tile {
    outline: 3px solid var(--cp-accent);
    outline-offset: -8px;
  }
  .verifyngo-sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  @keyframes verifyngo-reveal {
    to { visibility: visible; }
  }
  @supports (animation-name: verifyngo-reveal) {
    .verifyngo-trouble-delayed {
      visibility: hidden;
      animation: verifyngo-reveal 0s linear {{.TroubleDelaySeconds}}s forwards;
    }
  }
  .verifyngo-alert {
    background: rgba(220, 53, 69, 0.15);
    border: 1px solid #dc3545;
    color: var(--cp-text);
    padding: 0.6rem 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    font-size: 0.95rem;
    font-weight: 500;
  }
  cap-widget {
    --cap-background: color-mix(in srgb, var(--cp-bg) 85%, white 6%);
    --cap-border-color: color-mix(in srgb, var(--cp-text) 25%, transparent);
    --cap-border-radius: 14px;
    --cap-color: var(--cp-text);
    --cap-font: var(--cp-font);
    --cap-checkbox-border: 1px solid color-mix(in srgb, var(--cp-text) 35%, transparent);
    --cap-checkbox-background: color-mix(in srgb, var(--cp-bg) 88%, white 5%);
    --cap-spinner-color: var(--cp-accent);
    --cap-spinner-background-color: color-mix(in srgb, var(--cp-bg) 85%, white 8%);
    --cap-focus-ring: var(--cp-accent);
    --cap-troubleshoot-color: var(--cp-accent);
    {{if .CapCheckmark}}--cap-checkmark: {{.CapCheckmark}};{{end}}
  }
  @media (max-width: 380px) {
    .verifyngo-switch-current,
    .verifyngo-switch a,
    .verifyngo-switch a:visited { font-size: 0.68rem; letter-spacing: 0; }
    main.verifyngo-card { padding: 1.5rem 1.25rem; border-radius: 10px; }
    .verifyngo-title { font-size: 1.2rem; }
    .verifyngo-status { font-size: 0.9rem; }
  }
</style>
{{if .CSSURL}}<link rel="stylesheet" href="{{.CSSURL}}">{{end}}
</head><body class="verifyngo-challenge">
<main class="verifyngo-card">
  {{if .LogoURL}}<img class="verifyngo-logo" src="{{.LogoURL}}" alt="">{{end}}
  <h1 class="verifyngo-title">{{if .Title}}{{.Title}}{{else}}Checking you are not a bot{{end}}</h1>
  {{if .ErrorMsg}}<div role="alert" class="verifyngo-alert">{{.ErrorMsg}}</div>{{end}}
  {{if .Sound}}<audio autoplay src="{{.Sound}}"></audio>{{end}}
  <p class="verifyngo-status">Please complete this check to confirm you are not a bot.</p>

  <div class="verifyngo-widget" role="group" aria-label="Captcha challenge">
  <input type="hidden" id="verifyngo-return-to" value="{{.ReturnTo}}">
  {{if eq .Provider "cap"}}
  <div id="verifyngo-replay" hidden>{{template "replay" .}}</div>
  <cap-widget id="widget" data-cap-api-endpoint="{{.APIURL}}/{{.SiteKey}}/"></cap-widget>
  {{if .SliderSwitchURL}}<script nonce="{{.Nonce}}">
    (function(){
      if (window.customElements && window.WebAssembly && window.Element && Element.prototype.attachShadow) return;
      try {
        if (!navigator.cookieEnabled || sessionStorage.getItem('verifyngo-slider')) return;
        sessionStorage.setItem('verifyngo-slider', '1');
      } catch (e) { return; }
      location.replace({{.SliderSwitchURL}});
    })();
  </script>{{end}}
  <script nonce="{{.Nonce}}">
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
      f.appendChild(document.getElementById('verifyngo-replay'));
      document.body.appendChild(f); f.submit();
    });
  </script>
  {{else if eq .Provider "hcaptcha"}}
  <form id="hcaptcha-form" method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    {{template "replay" .}}
    <div id="hcaptcha-el"></div>
  </form>
  {{else if eq .Provider "slider"}}
  <style nonce="{{.Nonce}}">
    .verifyngo-slider {
      --spot-width: 280px;
      width: var(--spot-width);
      margin: 0 auto;
    }
    .verifyngo-piece-panel {
      display: flex;
      align-items: center;
      gap: 0.9rem;
      padding: 0.6rem;
      margin-bottom: 0.75rem;
      border: 2px solid var(--cp-accent);
      border-radius: 10px;
    }
    .verifyngo-piece {
      display: block;
      flex: none;
      width: calc(var(--spot-width) * {{.SliderPiecePct}} / 100);
      height: auto;
    }
    .verifyngo-piece-drag {
      position: relative;
      z-index: 2;
      touch-action: none;
      cursor: grab;
    }
    .verifyngo-piece-drag:active { cursor: grabbing; }
    .verifyngo-piece-panel .verifyngo-status {
      margin: 0;
      font-size: 1.05rem;
      text-align: left;
    }
    .verifyngo-spot {
      display: none;
      width: 100%;
      height: auto;
      padding: 0;
      border-radius: 10px;
      cursor: pointer;
    }
    .verifyngo-spot-280 { display: block; }
    @media (max-width: 359px) {
      .verifyngo-slider { --spot-width: 220px; }
      .verifyngo-spot-280 { display: none; }
      .verifyngo-spot-220 { display: block; }
    }
    @media (min-width: 520px) {
      .verifyngo-slider { --spot-width: 420px; }
      .verifyngo-spot-280 { display: none; }
      .verifyngo-spot-420 { display: block; }
    }
  </style>
  <form id="slider-form" method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <input type="hidden" name="captcha_id" value="{{.SliderChallengeID}}">
    {{template "replay" .}}
    <div class="verifyngo-slider">
      <div class="verifyngo-piece-panel">
        <img class="verifyngo-piece" src="{{.SliderPiece}}" alt="Puzzle piece">
        <p id="slider-desc" class="verifyngo-status">Click the slot this piece fits.</p>
      </div>
      {{range .SliderSpots}}<input type="image" class="verifyngo-spot verifyngo-spot-{{.}}" name="spot{{.}}" src="{{$.SliderBg}}" alt="Picture with marked slots" aria-describedby="slider-desc">
      {{end}}
    </div>
  </form>
  <script nonce="{{.Nonce}}">
    (function () {
      var piece = document.querySelector('.verifyngo-piece');
      var form = document.getElementById('slider-form');
      if (!piece || !form || !window.PointerEvent) return;
      var startX = 0, startY = 0, dragging = false;
      piece.classList.add('verifyngo-piece-drag');
      document.getElementById('slider-desc').textContent = 'Click the slot this piece fits, or drag the piece onto it.';
      piece.addEventListener('dragstart', function (e) { e.preventDefault(); });
      piece.addEventListener('pointerdown', function (e) {
        dragging = true;
        startX = e.clientX;
        startY = e.clientY;
        piece.setPointerCapture(e.pointerId);
      });
      piece.addEventListener('pointermove', function (e) {
        if (dragging) piece.style.transform = 'translate(' + (e.clientX - startX) + 'px,' + (e.clientY - startY) + 'px)';
      });
      piece.addEventListener('pointercancel', function () {
        dragging = false;
        piece.style.transform = '';
      });
      piece.addEventListener('pointerup', function () {
        if (!dragging) return;
        dragging = false;
        var spot = Array.prototype.filter.call(form.querySelectorAll('input[type=image]'), function (i) { return i.offsetParent !== null; })[0];
        var p = piece.getBoundingClientRect();
        var b = spot.getBoundingClientRect();
        var x = Math.round(p.left + p.width / 3 - b.left);
        var y = Math.round(p.top + p.height / 2 - b.top);
        piece.style.transform = '';
        if (x <= 0 || y < 0 || x > b.width || y > b.height) return;
        [['x', x], ['y', y]].forEach(function (pair) {
          var input = document.createElement('input');
          input.type = 'hidden';
          input.name = spot.name + '.' + pair[0];
          input.value = pair[1];
          form.appendChild(input);
        });
        form.submit();
      });
    })();
  </script>
  {{else if eq .Provider "jigsaw"}}
  <form id="jigsaw-form" method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <input type="hidden" name="captcha_id" value="{{.SliderChallengeID}}">
    {{template "replay" .}}
    <p id="jigsaw-desc" class="verifyngo-status">Two tiles are swapped. Select them.</p>
    <div class="verifyngo-jigsaw" role="group" aria-labelledby="jigsaw-desc">
      <img src="{{.JigsawImage}}" alt="Picture cut into nine tiles">
      <div class="verifyngo-jigsaw-grid">
        {{range .JigsawTiles}}<input type="checkbox" id="tile-{{.Index}}" class="verifyngo-tile-input" name="tile" value="{{.Index}}"{{if .Checked}} checked{{end}}><label for="tile-{{.Index}}" class="verifyngo-tile"><span class="verifyngo-sr">Row {{.Row}}, column {{.Column}}</span></label>
        {{end}}
      </div>
    </div>
    <button type="submit" class="verifyngo-submit">Verify</button>
  </form>
  {{else if eq .Provider "timed"}}
  <form id="timed-form" method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <input type="hidden" name="captcha_id" value="{{.SliderChallengeID}}">
    <input type="hidden" name="wait" value="1">
    <input type="hidden" name="trouble" value="{{.TroubleToken}}">
    {{template "replay" .}}
    <p id="timed-status" class="verifyngo-status" role="status">{{if .WaitRefreshURL}}Please wait {{.TimedRemaining}} seconds. You will continue automatically. If nothing happens, select Continue.{{else}}Please wait {{.TimedRemaining}} seconds, then select Continue.{{end}}</p>
    <button type="submit" class="verifyngo-submit">Continue</button>
  </form>
  <script nonce="{{.Nonce}}">
    setTimeout(function () {
      {{if .WaitRefreshURL}}document.getElementById('timed-status').textContent = 'You can continue now.';{{else}}document.getElementById('timed-form').submit();{{end}}
    }, {{.TimedRemaining}} * 1000);
  </script>
  {{else}}
  <form method="POST" action="/__verify">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    {{template "replay" .}}
    <div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="onSolve" data-theme="{{.WidgetTheme}}"></div>
    <script nonce="{{.Nonce}}">function onSolve(token){
      var i=document.createElement('input'); i.type='hidden'; i.name='token'; i.value=token;
      document.currentScript.parentElement.appendChild(i);
      document.currentScript.parentElement.submit();
    }</script>
  </form>
  {{end}}

  <!-- provider switcher injected when multiple providers available -->
  {{if .ProviderSwitcher}}
    <div class="verifyngo-switch-wrap">{{.ProviderSwitcher}}</div>
  {{end}}

  </div>

  <details class="verifyngo-details">
    <summary>Why am I seeing this?</summary>
    <p>{{.DetailsText}}</p>
    {{if ne .Provider "timed"}}<p>If this check doesn't work for you, another option appears here after a minute.</p>{{end}}
  </details>
  {{if ne .Provider "timed"}}
  <details class="verifyngo-details verifyngo-trouble{{if not .TroubleNow}} verifyngo-trouble-delayed{{end}}">
    <summary>Having trouble?</summary>
    <p>If this check doesn't work for you, you can wait {{.TimedRemaining}} seconds instead.</p>
    <form method="POST" action="/__verify">
      <input type="hidden" name="return_to" value="{{.ReturnTo}}">
      <input type="hidden" name="wait" value="1">
      <input type="hidden" name="trouble" value="{{.TroubleToken}}">
      {{template "replay" .}}
      <button type="submit" class="verifyngo-submit">Wait instead</button>
    </form>
  </details>
  {{end}}
</main>
<footer class="verifyngo-footer">
  Request Id <em>{{.RequestID}}</em>{{if .ContactURL}} | <a href="{{.ContactURL}}">Contact</a>{{end}}
  {{if eq .Provider "turnstile"}}<br>Protected by Cloudflare Turnstile · <a href="https://www.cloudflare.com/privacypolicy/">Privacy</a> · <a href="https://www.cloudflare.com/terms/">Terms</a>{{end}}
  {{if eq .Provider "hcaptcha"}}<br>Protected by hCaptcha · <a href="https://www.hcaptcha.com/privacy">Privacy</a> · <a href="https://www.hcaptcha.com/terms">Terms</a>{{end}}
</footer>
{{.TrapHTML}}
</body></html>
{{define "replay"}}{{range .Replay}}<input type="hidden" name="__replay_{{.Name}}" value="{{.Value}}">{{end}}{{end}}`

var tpl = template.Must(template.New("challenge").Parse(challengeTpl))

type jigsawTile struct {
	Index, Row, Column int
	Checked            bool
}

func waitRequested(r *http.Request) bool {
	return r.URL.Path == "/__wait" || (r.URL.Path == "/__verify" && r.PostFormValue("wait") != "")
}

func providerDisplayName(p string) string {
	switch p {
	case "cap":
		return "Automatic check"
	case "slider":
		return "Visual puzzle"
	case "jigsaw":
		return "Tile puzzle"
	case "turnstile":
		return "Cloudflare Turnstile"
	case "hcaptcha":
		return "hCaptcha"
	case "recaptcha":
		return "reCAPTCHA"
	default:
		return p
	}
}

func serveChallenge(w http.ResponseWriter, r *http.Request, cfg *Config, apiURL, ip, requestURI, errorMsg string, logServed bool) {
	id := requestID()
	if logServed {
		log.Printf("challenge served id=%s ip=%s path=%s", id, ip, requestURI)
	}

	replay := replayFields(replayValues(r))
	provider := providerForRequest(cfg, r)
	if waitRequested(r) {
		provider = "timed"
	}
	metricChallenges.WithLabelValues(provider, "issued").Inc()

	var switcher template.HTML
	available := availableProviders(cfg)
	if len(available) > 1 {
		var b strings.Builder
		b.WriteString("<div class=\"verifyngo-switch\"><span class=\"verifyngo-switch-label\">Choose how to verify:</span><div class=\"verifyngo-switch-options\">")
		for _, p := range available {
			label := providerDisplayName(p)
			if p == provider {
				b.WriteString("<strong class=\"verifyngo-switch-current\" aria-current=\"page\">")
				b.WriteString(label)
				b.WriteString("</strong>")
			} else {
				u := url.URL{
					Path:     "/__set_provider",
					RawQuery: "provider=" + url.QueryEscape(p) + "&return_to=" + url.QueryEscape(requestURI),
				}

				b.WriteString(" <a href=\"")
				b.WriteString(u.String())
				b.WriteString("\">")
				b.WriteString(label)
				b.WriteString("</a>")
			}
		}
		b.WriteString("</div></div>")
		switcher = template.HTML(b.String())
	}

	sliderSwitchURL := ""
	if provider == "cap" && cfg.Slider.Enabled {
		sliderSwitchURL = (&url.URL{
			Path:     "/__set_provider",
			RawQuery: "provider=slider&return_to=" + url.QueryEscape(requestURI),
		}).String()
	}

	scriptURL := scriptURLForRequest(cfg, r)
	if provider == "timed" {
		scriptURL = ""
	}

	sliderID := ""
	sliderBg := ""
	sliderPiece := ""
	sliderPiecePct := ""
	timedRemaining := int(timedWait / time.Second)
	if provider == "timed" {
		id := r.FormValue("captcha_id")
		if remaining, ok := cfg.sliderChallenges.timedRemaining(id, timedWait); ok {
			sliderID = id
			timedRemaining = max(int(math.Ceil(remaining.Seconds())), 1)
		} else if challengeID, err := cfg.sliderChallenges.issueTimed(); err != nil {
			log.Printf("timed: issue challenge: %v", err)
		} else {
			sliderID = challengeID
		}
	}
	jigsawImage := ""
	var jigsawTiles []jigsawTile
	if provider == "jigsaw" {
		var data *jigsawChallenge
		var err error
		id := ""
		if r.URL.Path == "/__verify" {
			id = r.PostFormValue("captcha_id")
		}
		seed, same := cfg.sliderChallenges.jigsawSeed(id)
		if same {
			data, err = buildJigsawFromSeed(seed)
		} else {
			data, err = buildJigsawChallenge()
			if err == nil {
				id, err = cfg.sliderChallenges.issueJigsaw(data.A, data.B, data.Seed)
			}
		}
		if err != nil {
			log.Printf("jigsaw: build challenge: %v", err)
		} else {
			sliderID = id
			jigsawImage = data.ImageURI
			for i := 0; i < 9; i++ {
				checked := same && slices.Contains(r.PostForm["tile"], strconv.Itoa(i))
				jigsawTiles = append(jigsawTiles, jigsawTile{Index: i, Row: i/3 + 1, Column: i%3 + 1, Checked: checked})
			}
		}
	}
	troubleNow := false
	if cfg.store != nil {
		if addr, _ := clientIP(r, cfg); addr != nil {
			troubleNow = troubleAttemptCount(cfg.store, addr) >= troubleAttempts
		}
	}
	sound := ""
	if errorMsg == tryAgainMessage {
		sound = soundWrong
	}
	waitRefreshURL := ""
	if provider == "timed" && sliderID != "" && len(replay) == 0 {
		waitRefreshURL = (&url.URL{
			Path:     "/__wait",
			RawQuery: url.Values{"captcha_id": {sliderID}, "return_to": {requestURI}}.Encode(),
		}).String()
	}
	if provider == "slider" {
		data, err := buildSliderChallenge(cfg)
		if err != nil {
			log.Printf("slider: build challenge: %v", err)
		} else {
			challengeID, err := cfg.sliderChallenges.issueSpot(data.Answer, data.PieceWidth, data.Width)
			if err != nil {
				log.Printf("slider: issue challenge: %v", err)
			} else {
				sliderID = challengeID
				sliderBg = data.BgDataURI
				sliderPiece = data.PieceDataURI
				sliderPiecePct = data.PiecePct
			}
		}
	}

	nonce := ""
	if n, err := cspNonce(); err != nil {
		log.Printf("nonce: %v", err)
	} else {
		nonce = n
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	if nonce != "" {
		w.Header().Set("Content-Security-Policy", buildCSP(cfg, nonce, scriptURL))
	}
	w.WriteHeader(http.StatusOK)
	_ = tpl.Execute(w, map[string]interface{}{
		"Provider":            provider,
		"ErrorMsg":            errorMsg,
		"ScriptURL":           scriptURL,
		"CapAssetsURL":        cfg.Cap.AssetsURL,
		"APIURL":              apiURL,
		"SiteKey":             siteKeyForRequest(cfg, r),
		"LogoURL":             cfg.Branding.LogoURL,
		"CSSURL":              cfg.Branding.CSSURL,
		"Title":               cfg.Branding.Title,
		"AccentColor":         cfg.Branding.AccentColor,
		"BackgroundColor":     cfg.Branding.BackgroundColor,
		"TextColor":           cfg.Branding.TextColor,
		"FontFamily":          cfg.Branding.FontFamily,
		"FontURL":             cfg.Branding.FontURL,
		"DetailsText":         cfg.Branding.DetailsText,
		"ContactURL":          cfg.Branding.ContactURL,
		"Lang":                cfg.Branding.Lang,
		"RequestID":           id,
		"TimedRemaining":      timedRemaining,
		"TroubleNow":          troubleNow,
		"TroubleToken":        troubleTokenAt(r, cfg, time.Now()),
		"TroubleDelaySeconds": int(troubleDelay / time.Second),
		"TrapHTML":            template.HTML(trapHTML),
		"WaitRefreshURL":      waitRefreshURL,
		"ReturnTo":            requestURI,
		"Replay":              replay,
		"ProviderSwitcher":    switcher,
		"WidgetTheme":         widgetTheme(cfg.Branding.BackgroundColor),
		"AccentTextColor":     accentTextColor(cfg.Branding.AccentColor),
		"CapCheckmark":        capCheckmark(cfg.Branding.AccentColor),
		"Nonce":               nonce,
		"SliderChallengeID":   sliderID,
		"SliderSpots":         sliderSpotWidths,
		"Sound":               template.URL(sound),
		"JigsawImage":         template.URL(jigsawImage),
		"JigsawTiles":         jigsawTiles,
		"SliderBg":            template.URL(sliderBg),
		"SliderPiece":         template.URL(sliderPiece),
		"SliderPiecePct":      sliderPiecePct,
		"SliderSwitchURL":     sliderSwitchURL,
	})
}

func cspNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func addOrigin(srcs []string, u string) []string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return srcs
	}
	o := parsed.Scheme + "://" + parsed.Host
	for _, s := range srcs {
		if s == o {
			return srcs
		}
	}
	return append(srcs, o)
}

func buildCSP(cfg *Config, nonce, scriptURL string) string {
	if cfg.Cap.CSP != "" {
		return strings.ReplaceAll(cfg.Cap.CSP, "{nonce}", nonce)
	}

	script := []string{"'nonce-" + nonce + "'", "'strict-dynamic'", "'wasm-unsafe-eval'", "'unsafe-eval'"}
	style := []string{"'self'", "'nonce-" + nonce + "'"}
	img := []string{"'self'", "data:", "blob:"}
	font := []string{"'self'", "data:"}
	connect := []string{"'self'", "https://cdn.jsdelivr.net"}

	script = addOrigin(script, scriptURL)
	connect = addOrigin(connect, scriptURL)
	connect = addOrigin(connect, cfg.Cap.APIURL)
	connect = addOrigin(connect, cfg.Cap.VerifyURL)
	style = addOrigin(style, cfg.Branding.CSSURL)
	font = addOrigin(font, cfg.Branding.FontURL)
	img = addOrigin(img, cfg.Branding.LogoURL)

	frame := []string{"'self'", "blob:", "data:", "https://challenges.cloudflare.com", "https://hcaptcha.com", "https://newassets.hcaptcha.com"}
	frame = addOrigin(frame, scriptURL)
	frame = addOrigin(frame, cfg.Cap.APIURL)
	worker := []string{"'self'", "blob:", "data:"}

	return strings.Join([]string{
		"default-src 'none'",
		"media-src data:",
		"script-src " + strings.Join(script, " "),
		"style-src " + strings.Join(style, " "),
		"img-src " + strings.Join(img, " "),
		"font-src " + strings.Join(font, " "),
		"connect-src " + strings.Join(connect, " "),
		"frame-src " + strings.Join(frame, " "),
		"worker-src " + strings.Join(worker, " "),
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
	}, "; ")
}

func relativeLuminance(hex string) (float64, bool) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, false
	}
	r, err1 := strconv.ParseInt(hex[0:2], 16, 0)
	g, err2 := strconv.ParseInt(hex[2:4], 16, 0)
	b, err3 := strconv.ParseInt(hex[4:6], 16, 0)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, false
	}
	lin := func(c float64) float64 {
		c /= 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(float64(r)) + 0.7152*lin(float64(g)) + 0.0722*lin(float64(b)), true
}

func accentTextColor(accentHex string) string {
	l, ok := relativeLuminance(accentHex)
	if !ok {
		return "#ffffff"
	}
	if l < 0.183 {
		return "#ffffff"
	}
	return "#000000"
}

func capCheckmark(accentHex string) template.CSS {
	if _, ok := relativeLuminance(accentHex); !ok {
		return ""
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><style>@keyframes anim{0%{stroke-dashoffset:23.21320343017578px}to{stroke-dashoffset:0}}</style><path fill="none" stroke="` + accentHex + `" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m5 12 5 5L20 7" style="stroke-dashoffset:0;stroke-dasharray:23.21320343017578px;animation:anim .5s ease"/></svg>`
	return template.CSS(`url("data:image/svg+xml,` + url.PathEscape(svg) + `")`)
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
	if path == "" || !strings.HasPrefix(path, "/") || (len(path) > 1 && (path[1] == '/' || path[1] == '\\')) {
		return "/"
	}
	second := ""
	if len(path) > 1 {
		second = path[1:2]
	}
	if second == "/" || second == "\\" {
		return "/"
	}
	if strings.ContainsAny(path, "\r\n\\") {
		return "/"
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	clean := &url.URL{Path: u.Path, RawQuery: u.RawQuery, Fragment: u.Fragment}
	return clean.String()
}

func providerForRequest(cfg *Config, r *http.Request) string {
	p := chosenProvider(cfg, r)
	if p == "cap" && cfg.Slider.Enabled && capUnsupported(r.UserAgent()) {
		if ck, err := r.Cookie("cp_provider"); err != nil || ck.Value != "cap" {
			return "slider"
		}
	}
	return p
}

var (
	chromeMajor  = regexp.MustCompile(`Chrom(?:e|ium)/(\d+)`)
	firefoxMajor = regexp.MustCompile(`Firefox/(\d+)`)
	safariMajor  = regexp.MustCompile(`Version/(\d+)[.\d]* (?:Mobile/\S+ )?Safari/`)
)

func capUnsupported(ua string) bool {
	if strings.Contains(ua, "MSIE ") || strings.Contains(ua, "Trident/") || strings.Contains(ua, " Edge/") {
		return true
	}
	major := func(re *regexp.Regexp) (int, bool) {
		m := re.FindStringSubmatch(ua)
		if m == nil {
			return 0, false
		}
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	if n, ok := major(chromeMajor); ok {
		return n < 84
	}
	if n, ok := major(firefoxMajor); ok {
		return n < 90
	}
	if n, ok := major(safariMajor); ok {
		return n < 15
	}
	return false
}

func chosenProvider(cfg *Config, r *http.Request) string {
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
		case "slider", "jigsaw":
			if cfg.Slider.Enabled {
				return p
			}
		}
	}
	if cfg.Slider.Enabled {
		if ip, _ := clientIP(r, cfg); ip != nil && torKind(r, cfg, ip) != "" {
			return "slider"
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
	if cfg.Slider.Enabled {
		return "slider"
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
	if cfg.Slider.Enabled {
		out = append(out, "slider")
		out = append(out, "jigsaw")
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
	case "slider", "jigsaw":
		return ""
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
	case "slider", "jigsaw":
		return ""
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
