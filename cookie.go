package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	if cfg.TrustRealIP && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func signCookie(secret string, expiry time.Time, scope string) string {
	payload := strconv.FormatInt(expiry.Unix(), 10) + "." + scope

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))

	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func verifyCookie(secret, value string, expectedScope string) bool {
	parts := strings.Split(value, ".")

	var (
		expiry string
		scope  string
		sigHex string
	)

	switch len(parts) {
	case 2:
		// Legacy cookies: expiry.signature
		if expectedScope != cookieScopeFull {
			return false
		}
		expiry = parts[0]
		scope = cookieScopeFull
		sigHex = parts[1]

	case 3:
		// Current cookies: expiry.scope.signature
		expiry = parts[0]
		scope = parts[1]
		sigHex = parts[2]

	default:
		return false
	}

	if scope != expectedScope {
		return false
	}

	payload := expiry
	if len(parts) == 3 {
		payload += "." + scope
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))

	expected := mac.Sum(nil)

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	if !hmac.Equal(expected, sig) {
		return false
	}

	expUnix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now()
	return now.Before(time.Unix(expUnix, 0))
}

func newCookie(r *http.Request, cfg *Config, name, value string, expiry time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   isSecureRequest(r, cfg),
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
		signCookie(cfg.CookieSecret, expiry, cookieScopeFull),
		expiry,
	))
}

func setPassiveCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	expiry := time.Now().Add(cfg.Progressive.PassiveTTL.Duration)

	http.SetCookie(w, newCookie(
		r,
		cfg,
		cfg.CookieName+"_passive",
		signCookie(cfg.CookieSecret, expiry, cookieScopePassive),
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
	c, err := r.Cookie(cfg.CookieName)
	if err != nil {
		return false
	}

	return verifyCookie(cfg.CookieSecret, c.Value, cookieScopeFull)
}

func hasValidPassiveCookie(r *http.Request, cfg *Config) bool {
	c, err := r.Cookie(cfg.CookieName + "_passive")
	if err != nil {
		return false
	}

	return verifyCookie(cfg.CookieSecret, c.Value, cookieScopePassive)
}
