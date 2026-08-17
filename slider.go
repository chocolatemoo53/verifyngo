package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math"
	mrand "math/rand"
	"sync"
	"time"
)

type sliderChallenge struct {
	answer  int
	expires time.Time
}

// sliderChallengeStore holds pending slider answers in memory. Entries are
// single-use and expire after the configured TTL, so nothing is persisted.
type sliderChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]sliderChallenge
	ttl        time.Duration
	max        int
}

func newSliderChallengeStore(ttl time.Duration, max int) *sliderChallengeStore {
	if max <= 0 {
		max = 5000
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s := &sliderChallengeStore{
		challenges: make(map[string]sliderChallenge),
		ttl:        ttl,
		max:        max,
	}
	go s.sweepLoop()
	return s
}

func (s *sliderChallengeStore) sweepLoop() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.challenges {
			if now.After(v.expires) {
				delete(s.challenges, k)
			}
		}
		s.mu.Unlock()
	}
}

func (s *sliderChallengeStore) issue(answer int) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.challenges {
		if now.After(v.expires) {
			delete(s.challenges, k)
		}
	}
	if len(s.challenges) >= s.max {
		return "", errors.New("slider: too many pending challenges")
	}
	s.challenges[id] = sliderChallenge{answer: answer, expires: now.Add(s.ttl)}
	return id, nil
}

// consume atomically validates and removes the challenge regardless of outcome.
func (s *sliderChallengeStore) consume(id string, value, tolerance int) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	c, ok := s.challenges[id]
	delete(s.challenges, id)
	s.mu.Unlock()
	if !ok {
		return false
	}
	if time.Now().After(c.expires) {
		return false
	}
	diff := value - c.answer
	if diff < 0 {
		diff = -diff
	}
	return diff <= tolerance
}

type sliderChallengeData struct {
	ID           string
	BgDataURI    string
	PieceDataURI string
	PieceWidth   int
	Max          int
	Answer       int
	Width        int
	Height       int
}

// buildSliderChallenge renders a fresh puzzle: a procedural scene, a target
// slot cut into a copy of it, and a matching piece. The range-input value maps
// 1:1 to the piece's left edge in pixels, so 'answer' doubles as the value.
func buildSliderChallenge(cfg *Config) (*sliderChallengeData, error) {
	w := cfg.Slider.Width
	h := cfg.Slider.Height
	pieceW := w / 5
	if pieceW < 40 {
		pieceW = 40
	}
	if pieceW > 80 {
		pieceW = 80
	}
	tabR := pieceW / 2
	pieceTotal := pieceW + tabR

	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	rng := mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed[:]))))

	scene := drawScene(w, h, rng)

	max := w - pieceTotal
	if max < pieceTotal {
		max = pieceTotal
	}
	answer := 0
	if max > 0 {
		answer = rng.Intn(max + 1)
	}

	bg := cloneRGBA(scene)
	drawSlot(bg, answer, pieceW, tabR, h)

	piece := drawPiece(scene, answer, pieceW, tabR, h)

	bgURI, err := pngDataURI(bg)
	if err != nil {
		return nil, err
	}
	pieceURI, err := pngDataURI(piece)
	if err != nil {
		return nil, err
	}

	return &sliderChallengeData{
		BgDataURI:    bgURI,
		PieceDataURI: pieceURI,
		PieceWidth:   pieceTotal,
		Max:          max,
		Answer:       answer,
		Width:        w,
		Height:       h,
	}, nil
}

func pngDataURI(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func cloneRGBA(img *image.RGBA) *image.RGBA {
	c := image.NewRGBA(img.Bounds())
	copy(c.Pix, img.Pix)
	return c
}

func blend(base, over color.RGBA) color.RGBA {
	a := float64(over.A) / 255.0
	r := float64(base.R)*(1-a) + float64(over.R)*a + 0.5
	g := float64(base.G)*(1-a) + float64(over.G)*a + 0.5
	b := float64(base.B)*(1-a) + float64(over.B)*a + 0.5
	return color.RGBA{uint8(r), uint8(g), uint8(b), 255}
}

func lerpColor(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		R: uint8(float64(a.R) + (float64(b.R)-float64(a.R))*t),
		G: uint8(float64(a.G) + (float64(b.G)-float64(a.G))*t),
		B: uint8(float64(a.B) + (float64(b.B)-float64(a.B))*t),
		A: 255,
	}
}

func setPx(img *image.RGBA, x, y int, c color.RGBA) {
	if x < 0 || y < 0 || x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
		return
	}
	img.SetRGBA(x, y, blend(img.At(x, y).(color.RGBA), c))
}

func fillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r {
				setPx(img, x, y, c)
			}
		}
	}
}

func ringCircle(img *image.RGBA, cx, cy, r, thick int, c color.RGBA) {
	for y := cy - r - 1; y <= cy+r+1; y++ {
		for x := cx - r - 1; x <= cx+r+1; x++ {
			dx, dy := x-cx, y-cy
			d := int(math.Sqrt(float64(dx*dx + dy*dy)))
			if d >= r-thick && d <= r {
				setPx(img, x, y, c)
			}
		}
	}
}

func drawScene(w, h int, rng *mrand.Rand) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	top := color.RGBA{17, 22, 38, 255}
	bot := color.RGBA{30, 43, 66, 255}
	for y := 0; y < h; y++ {
		t := float64(y) / float64(h)
		c := lerpColor(top, bot, t)
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, c)
		}
	}

	particleColors := []color.RGBA{
		{79, 209, 255, 200},
		{255, 255, 255, 210},
		{167, 139, 250, 190},
		{251, 220, 128, 180},
	}
	for i := 0; i < w*h/450; i++ {
		c := particleColors[rng.Intn(len(particleColors))]
		fillCircle(img, rng.Intn(w), rng.Intn(h), 1+rng.Intn(2), c)
	}

	ringColors := []color.RGBA{
		{79, 209, 255, 110},
		{167, 139, 250, 110},
	}
	for i := 0; i < 2; i++ {
		cx, cy, r := rng.Intn(w), rng.Intn(h), h/3+rng.Intn(h/3)
		ringCircle(img, cx, cy, r, 2, ringColors[rng.Intn(len(ringColors))])
	}

	trackColors := []color.RGBA{
		{147, 197, 253, 170},
		{251, 191, 36, 170},
		{167, 139, 250, 170},
	}
	for i := 0; i < 4; i++ {
		drawTrack(img, rng.Intn(w), rng.Intn(h), 8+rng.Intn(14), trackColors[rng.Intn(len(trackColors))])
	}

	return img
}

func drawTrack(img *image.RGBA, x0, y0, length int, c color.RGBA) {
	dir := 1
	if x0 > img.Bounds().Dx()/2 {
		dir = -1
	}
	for i := 0; i < length; i++ {
		setPx(img, x0+dir*i, y0+dir*i, c)
	}
}

// drawSlot cuts a target region into the background: a dark translucent band
// with a dashed border and a matching semicircular notch where the piece tab fits.
func drawSlot(img *image.RGBA, x0, pieceW, tabR, h int) {
	w := img.Bounds().Dx()
	overlay := color.RGBA{0, 0, 0, 130}
	for y := 0; y < h; y++ {
		for x := x0; x < x0+pieceW && x < w; x++ {
			if x >= 0 {
				img.SetRGBA(x, y, blend(img.At(x, y).(color.RGBA), overlay))
			}
		}
	}

	dash := color.RGBA{255, 255, 255, 190}
	dashLen, gap := 6, 6
	for y := 0; y < h; y++ {
		if (y/dashLen)%2 == 0 {
			setPx(img, x0, y, dash)
			if x0+pieceW < w {
				setPx(img, x0+pieceW-1, y, dash)
			}
		}
	}
	for x := x0; x < x0+pieceW; x++ {
		if (x/dashLen)%2 == 0 {
			setPx(img, x, 0, dash)
			if h > 1 {
				setPx(img, x, h-1, dash)
			}
		}
	}
	_ = gap

	// semicircular notch on the right edge of the slot, matching the piece tab
	notch := color.RGBA{0, 0, 0, 255}
	tabCX := x0 + pieceW
	for y := -tabR; y <= tabR; y++ {
		for x := 0; x <= tabR; x++ {
			if x*x+y*y <= tabR*tabR {
				setPx(img, tabCX+x, h/2+y, notch)
			}
		}
	}
}

// drawPiece extracts the scene content behind the slot and adds a semicircular
// tab on its right edge, so the piece reads as the missing piece of the puzzle.
func drawPiece(scene *image.RGBA, x0, pieceW, tabR, h int) *image.RGBA {
	w := scene.Bounds().Dx()
	pieceTotal := pieceW + tabR
	p := image.NewRGBA(image.Rect(0, 0, pieceTotal, h))

	extract := func(dx, dy int) bool {
		sx, sy := x0+dx, dy
		if sx < 0 || sx >= w || sy < 0 || sy >= h {
			return false
		}
		p.SetRGBA(dx, dy, scene.At(sx, sy).(color.RGBA))
		return true
	}

	for dy := 0; dy < h; dy++ {
		for dx := 0; dx < pieceW; dx++ {
			extract(dx, dy)
		}
		// tab bulges right from the piece's right edge at mid-height
		for dx := pieceW; dx < pieceTotal; dx++ {
			rx := dx - pieceW
			ry := dy - h/2
			if rx*rx+ry*ry <= tabR*tabR {
				extract(dx, dy)
			}
		}
	}

	border := color.RGBA{0, 0, 0, 200}
	for dy := 0; dy < h; dy++ {
		setPx(p, 0, dy, border)
		setPx(p, pieceW-1, dy, border)
	}
	if h > 1 {
		for dx := 0; dx < pieceW; dx++ {
			setPx(p, dx, 0, border)
			setPx(p, dx, h-1, border)
		}
	}
	ringCircle(p, pieceW, h/2, tabR, 2, border)

	return p
}