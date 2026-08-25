package main

import (
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
