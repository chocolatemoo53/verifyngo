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

const (
	sliderVerifyWindow    = time.Minute
	sliderVerifyMaxPerMin = 12
	sliderAnswerWindow    = 15 * time.Minute
	sliderAnswerSamples   = 4
)

type tabShape int

const (
	shapeSemicircle tabShape = iota
	shapeTriangle
	shapeSquare
	shapeDoubleBump
	shapeCount
)

func inTab(shape tabShape, dx, dy, r int) bool {
	if dx < 0 {
		return false
	}
	switch shape {
	case shapeSemicircle:
		return dx*dx+dy*dy <= r*r
	case shapeTriangle:
		ady := dy
		if ady < 0 {
			ady = -ady
		}
		return ady+dx <= r
	case shapeSquare:
		ady := dy
		if ady < 0 {
			ady = -ady
		}
		return dx <= r && ady <= r
	case shapeDoubleBump:
		rr := r / 2
		if rr < 1 {
			rr = 1
		}
		for _, cy := range []int{-rr, rr} {
			ddy := dy - cy
			if dx*dx+ddy*ddy <= rr*rr {
				return true
			}
		}
		return false
	}
	return false
}

type sliderChallenge struct {
	answer  int
	expires time.Time
	issued  time.Time
}

type answerSample struct {
	value int
	at    time.Time
}

type sliderConsumeResult struct {
	ok      bool
	tooFast bool
}

type sliderChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]sliderChallenge
	attempts   map[string]counterEntry
	answers    map[string][]answerSample
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
		attempts:   make(map[string]counterEntry),
		answers:    make(map[string][]answerSample),
		ttl:        ttl,
		max:        max,
	}
	go s.sweepLoop()
	return s
}

func (s *sliderChallengeStore) sweepLoop() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		s.sweepOnce()
	}
}

func (s *sliderChallengeStore) sweepOnce() {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.challenges {
		if now.After(v.expires) {
			delete(s.challenges, k)
		}
	}
	for ip, e := range s.attempts {
		if now.After(e.Expires) {
			delete(s.attempts, ip)
		}
	}
	for ip, samples := range s.answers {
		kept := samples[:0]
		for _, sample := range samples {
			if now.Sub(sample.at) < sliderAnswerWindow {
				kept = append(kept, sample)
			}
		}
		if len(kept) == 0 {
			delete(s.answers, ip)
		} else {
			s.answers[ip] = kept
		}
	}
	s.mu.Unlock()
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
	s.challenges[id] = sliderChallenge{answer: answer, expires: now.Add(s.ttl), issued: now}
	return id, nil
}

func (s *sliderChallengeStore) consume(id string, value, tolerance int, minSolve time.Duration) sliderConsumeResult {
	if id == "" {
		return sliderConsumeResult{}
	}
	s.mu.Lock()
	c, ok := s.challenges[id]
	delete(s.challenges, id)
	s.mu.Unlock()
	if !ok {
		return sliderConsumeResult{}
	}
	now := time.Now()
	if now.After(c.expires) {
		return sliderConsumeResult{}
	}
	diff := value - c.answer
	if diff < 0 {
		diff = -diff
	}
	res := sliderConsumeResult{ok: diff <= tolerance}
	if minSolve > 0 && now.Sub(c.issued) < minSolve {
		res.ok = false
		res.tooFast = true
	}
	return res
}

func (s *sliderChallengeStore) allowAttempt(ip string, window time.Duration, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	e, ok := s.attempts[ip]
	if !ok || now.After(e.Expires) {
		e = counterEntry{Count: 0, Expires: now.Add(window)}
	}
	e.Count++
	s.attempts[ip] = e
	return e.Count <= limit
}

func (s *sliderChallengeStore) recordAnswer(ip string, value, n, tolerance int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	samples := append(s.answers[ip], answerSample{value: value, at: now})
	kept := samples[:0]
	for _, sample := range samples {
		if now.Sub(sample.at) < window {
			kept = append(kept, sample)
		}
	}
	if len(kept) > 4*n {
		kept = kept[len(kept)-4*n:]
	}
	s.answers[ip] = kept
	if len(kept) < n {
		return false
	}
	last := kept[len(kept)-n:]
	lo, hi := last[0].value, last[0].value
	for _, sample := range last[1:] {
		if sample.value < lo {
			lo = sample.value
		}
		if sample.value > hi {
			hi = sample.value
		}
	}
	return hi-lo <= tolerance
}

type sliderChallengeData struct {
	ID           string
	BgDataURI    string
	PieceDataURI string
	PieceWidth   int
	PiecePct     string
	Max          int
	Answer       int
	Width        int
	Height       int
}

func buildSliderChallenge(cfg *Config) (*sliderChallengeData, error) {
	w := cfg.Slider.Width
	h := cfg.Slider.Height

	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	rng := mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed[:]))))

	w += rng.Intn(81)
	h += rng.Intn(41)

	pieceW := w / 5
	if pieceW < 40 {
		pieceW = 40
	}
	if pieceW > 80 {
		pieceW = 80
	}
	tabR := pieceW / 2
	pieceTotal := pieceW + tabR
	shape := tabShape(rng.Intn(int(shapeCount)))

	max := w - pieceTotal
	if max < pieceTotal {
		max = pieceTotal
	}
	tol := cfg.Slider.Tolerance
	answer := 0
	if max > 0 {
		if max > tol {
			answer = tol + 1 + rng.Intn(max-tol)
		} else {
			answer = max
		}
	}

	scene := drawScene(w, h, rng)
	bg := cloneRGBA(scene)

	sep := pieceTotal + 12
	placed := []int{answer}
	nDecoys := 1 + rng.Intn(2)
	for i := 0; i < nDecoys; i++ {
		dx := placeDecoy(w, pieceTotal, placed, sep, rng)
		if dx < 0 {
			continue
		}
		placed = append(placed, dx)
		ds := tabShape(rng.Intn(int(shapeCount)))
		drawTargetBand(bg, dx, pieceW, tabR, h, ds, rng)
	}

	drawTargetBand(bg, answer, pieceW, tabR, h, shape, rng)
	piece := drawPiece(scene, answer, pieceW, tabR, h, shape)

	bgURI, err := pngDataURI(bg)
	if err != nil {
		return nil, err
	}
	pieceURI, err := pngDataURI(piece)
	if err != nil {
		return nil, err
	}

	piecePct := 0.0
	if w > 0 {
		piecePct = 100.0 * float64(pieceTotal) / float64(w)
	}

	return &sliderChallengeData{
		BgDataURI:    bgURI,
		PieceDataURI: pieceURI,
		PieceWidth:   pieceTotal,
		PiecePct:     fmtFloat(piecePct),
		Max:          max,
		Answer:       answer,
		Width:        w,
		Height:       h,
	}, nil
}

func placeDecoy(w, pieceTotal int, placed []int, sep int, rng *mrand.Rand) int {
	maxStart := w - pieceTotal - 2
	if maxStart < 3 {
		return -1
	}
	for i := 0; i < 20; i++ {
		x := 2 + rng.Intn(maxStart-2+1)
		ok := true
		for _, p := range placed {
			if x-p < sep && p-x < sep {
				ok = false
				break
			}
		}
		if ok {
			return x
		}
	}
	return -1
}

func fmtFloat(f float64) string {
	s := ""
	i := int(f)
	if i >= 100 {
		s += string('0' + byte(i%1000/100))
	}
	if i >= 10 {
		s += string('0' + byte(i%100/10))
	}
	s += string('0' + byte(i%10))
	s += "."
	frac := f - float64(i)
	for j := 0; j < 2; j++ {
		frac *= 10
		d := int(frac)
		s += string('0' + byte(d%10))
		frac -= float64(d)
	}
	return s
}

func drawTargetBand(img *image.RGBA, x0, pieceW, tabR, h int, shape tabShape, rng *mrand.Rand) {
	w := img.Bounds().Dx()
	for y := 0; y < h; y++ {
		for x := x0; x < x0+pieceW && x < w; x++ {
			if x < 0 {
				continue
			}
			a := uint8(105 + rng.Intn(55))
			setPx(img, x, y, color.RGBA{0, 0, 0, a})
		}
	}

	dash := color.RGBA{255, 255, 255, 190}
	dashLen := 6
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

	notch := color.RGBA{0, 0, 0, 255}
	tabCX := x0 + pieceW
	for dy := -tabR - 1; dy <= tabR+1; dy++ {
		for dx := 0; dx <= tabR+1; dx++ {
			if inTab(shape, dx, dy, tabR) {
				setPx(img, tabCX+dx, h/2+dy, notch)
			}
		}
	}
}

func drawPiece(scene *image.RGBA, x0, pieceW, tabR, h int, shape tabShape) *image.RGBA {
	w := scene.Bounds().Dx()
	pieceTotal := pieceW + tabR
	p := image.NewRGBA(image.Rect(0, 0, pieceTotal, h))

	extract := func(px, py int) bool {
		sx, sy := x0+px, py
		if sx < 0 || sx >= w || sy < 0 || sy >= h {
			return false
		}
		p.SetRGBA(px, py, scene.At(sx, sy).(color.RGBA))
		return true
	}

	for dy := 0; dy < h; dy++ {
		for dx := 0; dx < pieceW; dx++ {
			extract(dx, dy)
		}
		for dx := 0; dx <= tabR; dx++ {
			for dy := -tabR - 1; dy <= tabR+1; dy++ {
				if inTab(shape, dx, dy, tabR) {
					extract(pieceW+dx, h/2+dy)
				}
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

	for dx := 0; dx <= tabR+1; dx++ {
		for dy := -tabR - 1; dy <= tabR+1; dy++ {
			if !inTab(shape, dx, dy, tabR) {
				continue
			}
			if !inTab(shape, dx+1, dy, tabR) || !inTab(shape, dx, dy-1, tabR) || !inTab(shape, dx, dy+1, tabR) {
				setPx(p, pieceW+dx, h/2+dy, border)
			}
		}
	}

	return p
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
