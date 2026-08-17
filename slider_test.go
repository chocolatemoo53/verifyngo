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
	if !s.consume(id, 104, 8) {
		t.Fatal("expected within-tolerance answer to verify")
	}
	if s.consume(id, 104, 8) {
		t.Fatal("expected challenge to be single-use")
	}
}

func TestSliderChallengeStoreToleranceAndExpiry(t *testing.T) {
	s := newSliderChallengeStore(10*time.Minute, 10)
	id, _ := s.issue(100)
	if s.consume(id, 50, 8) {
		t.Fatal("expected out-of-tolerance answer to fail")
	}
	if s.consume(id, 104, 8) {
		t.Fatal("expected challenge to be consumed on first attempt")
	}

	id2, _ := s.issue(100)
	s.challenges[id2] = sliderChallenge{answer: 100, expires: time.Now().Add(-time.Second)}
	if s.consume(id2, 100, 8) {
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
	}
}
