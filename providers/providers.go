package providers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Verifier interface {
	Verify(token string) (bool, error)
	SiteKey() string
	WidgetScriptURL() string
}

var httpClient = &http.Client{Timeout: 8 * time.Second}

type Cap struct {
	APIURL    string
	VerifyURL string
	SiteKeyV  string
	SecretKey string
}

func (c *Cap) verifyBase() string {
	if c.VerifyURL != "" {
		return c.VerifyURL
	}
	return c.APIURL
}

func (c *Cap) Verify(token string) (bool, error) {
	endpoint := strings.TrimRight(c.verifyBase(), "/") + "/" + c.SiteKeyV + "/siteverify"
	form := url.Values{"secret": {c.SecretKey}, "response": {token}}
	resp, err := httpClient.PostForm(endpoint, form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Success, nil
}

func (c *Cap) SiteKey() string { return c.SiteKeyV }
func (c *Cap) WidgetScriptURL() string {
	return "https://cdn.jsdelivr.net/npm/@cap.js/widget"
}

type Turnstile struct {
	SiteKeyV  string
	SecretKey string
}

func (t *Turnstile) Verify(token string) (bool, error) {
	form := url.Values{"secret": {t.SecretKey}, "response": {token}}
	resp, err := httpClient.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Success, nil
}

func (t *Turnstile) SiteKey() string { return t.SiteKeyV }
func (t *Turnstile) WidgetScriptURL() string {
	return "https://challenges.cloudflare.com/turnstile/v0/api.js"
}

type HCaptcha struct {
	SiteKeyV  string
	SecretKey string
}

func (h *HCaptcha) Verify(token string) (bool, error) {
	form := url.Values{"secret": {h.SecretKey}, "response": {token}}
	resp, err := httpClient.PostForm("https://hcaptcha.com/siteverify", form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
		ChallengeT string   `json:"challenge_ts"`
		Hostname   string   `json:"hostname"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	if !out.Success {
		log.Printf("hcaptcha verify failed status=%d errors=%v hostname=%s ts=%s", resp.StatusCode, out.ErrorCodes, out.Hostname, out.ChallengeT)
	}
	return out.Success, nil
}

func (h *HCaptcha) SiteKey() string { return h.SiteKeyV }
func (h *HCaptcha) WidgetScriptURL() string {
	return "https://js.hcaptcha.com/1/api.js?onload=hcaptchaOnLoad&render=explicit"
}
