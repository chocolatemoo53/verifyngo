package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSliderChallengeStoreSingleUse(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	id, err := s.issue(100)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	res := s.consume(id, 104, 8, 0)
	if !res.ok {
		t.Fatal("expected within-tolerance answer to verify")
	}
	res = s.consume(id, 104, 8, 0)
	if res.ok {
		t.Fatal("expected challenge to be single-use")
	}
}

func TestSliderChallengeStoreToleranceAndExpiry(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	id, _ := s.issue(100)
	res := s.consume(id, 50, 8, 0)
	if res.ok {
		t.Fatal("expected out-of-tolerance answer to fail")
	}
	res = s.consume(id, 104, 8, 0)
	if res.ok {
		t.Fatal("expected challenge to be consumed on first attempt")
	}

	id2, _ := s.issue(100)
	s.mu.Lock()
	s.challenges[id2] = sliderChallenge{answer: 100, expires: time.Now().Add(-time.Second), issued: time.Now().Add(-time.Hour)}
	s.mu.Unlock()
	res = s.consume(id2, 100, 8, 0)
	if res.ok {
		t.Fatal("expected expired challenge to fail")
	}
}

func TestSliderChallengeStoreCapacity(t *testing.T) {
	s := newSliderChallengeStore(time.Minute, 2)
	if _, err := s.issue(1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.issue(2); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.issue(3); err == nil {
		t.Fatal("expected capacity limit to reject new challenges")
	}
}

func TestSliderChallengeStoreTooFast(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	id, _ := s.issue(100)
	res := s.consume(id, 100, 8, time.Hour)
	if res.ok {
		t.Fatal("expected too-fast solve to be rejected")
	}
	if !res.tooFast {
		t.Fatal("expected tooFast flag to be set")
	}

	id2, _ := s.issue(100)
	res = s.consume(id2, 100, 8, 0)
	if !res.ok {
		t.Fatalf("expected zero-minSolve to succeed (got ok=%v tooFast=%v)", res.ok, res.tooFast)
	}
}

func TestSliderChallengeStoreRateLimit(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	ip := "1.2.3.4"
	window := time.Minute
	limit := 3
	for i := 0; i < limit; i++ {
		if !s.allowAttempt(ip, window, limit) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if s.allowAttempt(ip, window, limit) {
		t.Fatal("expected 4th attempt to be throttled")
	}
}

func TestSliderChallengeStoreLowVariance(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	ip := "5.6.7.8"
	window := time.Minute
	n := 4
	tol := 8
	for i := 0; i < n-1; i++ {
		if s.recordAnswer(ip, 100, n, tol, window) {
			t.Fatalf("should not flag with %d answers", i+1)
		}
	}
	if !s.recordAnswer(ip, 101, n, tol, window) {
		t.Fatal("should flag when span=1 <= tolerance=8 (suspiciously exact)")
	}

	ip2 := "9.10.11.12"
	for _, v := range []int{50, 110, 80, 130} {
		s.recordAnswer(ip2, v, n, tol, window)
	}
	if s.recordAnswer(ip2, 50, n, tol, window) {
		t.Fatal("should not flag when spread-out answers")
	}
}

func TestBuildSliderChallenge(t *testing.T) {
	cfg := &Config{}
	cfg.Slider.Width = 320
	cfg.Slider.Height = 120
	cfg.Slider.Tolerance = 8
	cfg.Slider.TTL = Duration{10 * time.Minute}
	cfg.Slider.MaxChallenges = 5000

	for i := 0; i < 10; i++ {
		d, err := buildSliderChallenge(cfg)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if !strings.HasPrefix(d.BgDataURI, "data:image/png;base64,") {
			t.Error("background is not a PNG data URI")
		}
		if !strings.HasPrefix(d.PieceDataURI, "data:image/png;base64,") {
			t.Error("piece is not a PNG data URI")
		}
		if d.Answer < 0 || d.Answer > d.Max {
			t.Errorf("answer %d out of range [0, %d]", d.Answer, d.Max)
		}
		if d.Max > cfg.Slider.Tolerance && d.Answer <= cfg.Slider.Tolerance {
			t.Errorf("answer %d inside pre-aligned range [0, %d]", d.Answer, cfg.Slider.Tolerance)
		}
		if d.Width < cfg.Slider.Width || d.Height < cfg.Slider.Height {
			t.Errorf("dims %dx%d below requested %dx%d", d.Width, d.Height, cfg.Slider.Width, cfg.Slider.Height)
		}
		if d.PiecePct == "" {
			t.Error("PiecePct should not be empty")
		}
	}
}

func TestBuildSliderChallengeAllShapes(t *testing.T) {
	cfg := &Config{}
	cfg.Slider.Width = 320
	cfg.Slider.Height = 120
	cfg.Slider.Tolerance = 8
	cfg.Slider.TTL = Duration{10 * time.Minute}
	cfg.Slider.MaxChallenges = 5000

	for i := 0; i < 20; i++ {
		d, err := buildSliderChallenge(cfg)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if d.Answer <= cfg.Slider.Tolerance {
			t.Errorf("answer %d inside pre-aligned range [0, %d]", d.Answer, cfg.Slider.Tolerance)
		}
	}
}

func TestCapUnsupported(t *testing.T) {
	cases := map[string]bool{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0":                                                            true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0":                                                            true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                          false,
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko":                                                                     true,
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)":                                                                          true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041":         true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36":                       true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0":             false,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15":                   true,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1":   false,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1": true,
		"curl/8.7.1": false,
	}
	for ua, want := range cases {
		if got := capUnsupported(ua); got != want {
			t.Errorf("capUnsupported(%q) = %v, want %v", ua, got, want)
		}
	}
}

func TestNoScriptFallsBackToSlider(t *testing.T) {
	cfg := &Config{Provider: "cap"}
	cfg.Slider.Enabled = true
	req := httptest.NewRequest("GET", "/watch?v=a&b=c", nil)
	rec := httptest.NewRecorder()
	serveChallenge(rec, req, cfg, "https://cap.example", "203.0.113.9", "/watch?v=a&b=c", false)
	body := rec.Body.String()
	want := `<noscript><meta http-equiv="refresh" content="2;url=/__set_provider?provider=slider&amp;return_to=%2Fwatch%3Fv%3Da%26b%3Dc"></noscript>`
	if !strings.Contains(body, want) {
		i := strings.Index(body, "<noscript>")
		if i < 0 {
			t.Fatalf("no noscript fallback in challenge page")
		}
		t.Fatalf("noscript fallback = %q", body[i:i+160])
	}
}
