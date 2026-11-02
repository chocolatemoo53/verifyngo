package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	cookieScopeFull    = "full"
	cookieScopePassive = "passive"
)

func isSecureRequest(r *http.Request, cfg *Config) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Scheme"), "https") {
		return true
	}
	return false
}

func cookieBinding(r *http.Request, cfg *Config) string {
	b := r.UserAgent() + "\n" + r.Header.Get("Accept-Language")
	if cfg != nil {
		if ip, _ := clientIP(r, cfg); ip != nil {
			tor := torKind(r, cfg, ip)
			if !sharedTorIP(tor, ip) {
				b += "\n" + clientNetwork(ip)
			}
		}
	}
	return b
}

func cookieMAC(secret, payload, binding string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	io.WriteString(mac, payload)
	io.WriteString(mac, "\n")
	io.WriteString(mac, binding)
	return mac.Sum(nil)
}

func signCookie(secret string, expiry time.Time, scope, tls, binding string) string {
	payload := strconv.FormatInt(expiry.Unix(), 10) + "." + scope + "." + tls
	return payload + "." + hex.EncodeToString(cookieMAC(secret, payload, binding))
}

func verifyCookie(secret, value, expectedScope, tls, binding string) bool {
	if strings.Count(value, ".") != 3 {
		return false
	}
	expiry, rest, _ := strings.Cut(value, ".")
	scope, rest, _ := strings.Cut(rest, ".")
	tlsPart, hexSig, _ := strings.Cut(rest, ".")
	if scope != expectedScope {
		return false
	}
	if tlsPart != "" && tls != "" && tlsPart != tls {
		return false
	}

	expUnix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || !time.Now().Before(time.Unix(expUnix, 0)) {
		return false
	}

	var sig [sha256.Size]byte
	if len(hexSig) != hex.EncodedLen(len(sig)) {
		return false
	}
	if _, err := hex.Decode(sig[:], []byte(hexSig)); err != nil {
		return false
	}
	payload := value[:len(value)-len(hexSig)-1]
	return hmac.Equal(cookieMAC(secret, payload, binding), sig[:])
}

func tlsCipherHash(r *http.Request, cfg *Config) string {
	fp, ok := clientFingerprint(r, cfg)
	if !ok {
		return ""
	}
	return strings.Split(fp, "_")[1]
}

func issueCookieValue(r *http.Request, cfg *Config, expiry time.Time, scope string) string {
	return signCookie(cfg.CookieSecret, expiry, scope, tlsCipherHash(r, cfg), cookieBinding(r, cfg))
}

func validCookieValue(r *http.Request, cfg *Config, value, scope string) bool {
	return verifyCookie(cfg.CookieSecret, value, scope, tlsCipherHash(r, cfg), cookieBinding(r, cfg))
}

func browserMismatch(r *http.Request, cfg *Config) string {
	ua := r.UserAgent()
	hints := r.Header.Get("Sec-CH-UA") != ""
	chromium := strings.Contains(ua, "Chrome/")
	if hints && (strings.Contains(ua, "Firefox/") || (strings.Contains(ua, "Safari/") && !chromium)) {
		return "fake"
	}
	if chromium && !hints && isSecureRequest(r, cfg) {
		return "no-hints"
	}
	return ""
}

func newCookie(r *http.Request, cfg *Config, name, value string, expiry time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	if !expiry.IsZero() {
		c.MaxAge = int(time.Until(expiry).Seconds())
	}

	return c
}

func setVerifiedCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	expiry := time.Now().Add(cfg.CookieTTL.Duration)

	http.SetCookie(w, newCookie(
		r,
		cfg,
		cfg.CookieName,
		issueCookieValue(r, cfg, expiry, cookieScopeFull),
		expiry,
	))
}

func setPassiveCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	expiry := time.Now().Add(cfg.Progressive.PassiveTTL.Duration)

	http.SetCookie(w, newCookie(
		r,
		cfg,
		cfg.CookieName+"_passive",
		issueCookieValue(r, cfg, expiry, cookieScopePassive),
		expiry,
	))
}

func clearPassiveCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	c := newCookie(
		r,
		cfg,
		cfg.CookieName+"_passive",
		"",
		time.Unix(0, 0),
	)

	c.MaxAge = -1

	http.SetCookie(w, c)
}

func hasValidCookie(r *http.Request, cfg *Config) bool {
	if r.Header.Get("Cookie") == "" {
		return false
	}
	c, err := r.Cookie(cfg.CookieName)
	if err != nil {
		return false
	}

	return validCookieValue(r, cfg, c.Value, cookieScopeFull)
}
