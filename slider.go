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
	sliderCheckLimit      = 3
	jigsawTileSize        = 120
	jigsawMinSeam         = 12000.0
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
	timed   bool
	jigsaw  bool
	seed    int64
	checks  int
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
	return s.add(sliderChallenge{answer: answer})
}

func (s *sliderChallengeStore) issueSlider(answer int, seed int64) (string, error) {
	return s.add(sliderChallenge{answer: answer, seed: seed})
}

func (s *sliderChallengeStore) issueJigsaw(a, b int, seed int64) (string, error) {
	return s.add(sliderChallenge{jigsaw: true, answer: jigsawPair(a, b), seed: seed})
}

func (s *sliderChallengeStore) jigsawSeed(id string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok || !c.jigsaw || time.Now().After(c.expires) {
		return 0, false
	}
	return c.seed, true
}

func (s *sliderChallengeStore) consumeJigsaw(id string, a, b int, minSolve time.Duration) sliderConsumeResult {
	s.mu.Lock()
	c, ok := s.challenges[id]
	if ok && c.jigsaw {
		delete(s.challenges, id)
	}
	s.mu.Unlock()
	now := time.Now()
	if !ok || !c.jigsaw || now.After(c.expires) {
		return sliderConsumeResult{}
	}
	res := sliderConsumeResult{ok: c.answer == jigsawPair(a, b)}
	if minSolve > 0 && now.Sub(c.issued) < minSolve {
		res.ok = false
		res.tooFast = true
	}
	return res
}

func (s *sliderChallengeStore) issueTimed() (string, error) {
	return s.add(sliderChallenge{timed: true})
}

func (s *sliderChallengeStore) add(c sliderChallenge) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.challenges) >= s.max {
		for k, v := range s.challenges {
			if now.After(v.expires) {
				delete(s.challenges, k)
			}
		}
		if len(s.challenges) >= s.max {
			return "", errors.New("slider: too many pending challenges")
		}
	}
	c.expires, c.issued = now.Add(s.ttl), now
	s.challenges[id] = c
	return id, nil
}

type sliderCheck struct {
	ID      string
	Seed    int64
	Value   int
	Left    int
	InPlace bool
}

func (s *sliderChallengeStore) check(id string, value, tolerance int) *sliderCheck {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok || c.timed || c.jigsaw || time.Now().After(c.expires) {
		return nil
	}
	res := &sliderCheck{ID: id, Seed: c.seed, Value: value}
	if c.checks >= sliderCheckLimit {
		return res
	}
	c.checks++
	s.challenges[id] = c
	diff := value - c.answer
	if diff < 0 {
		diff = -diff
	}
	res.InPlace = diff <= tolerance
	res.Left = sliderCheckLimit - c.checks
	return res
}

func (s *sliderChallengeStore) timedRemaining(id string, wait time.Duration) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timedRemainingLocked(id, wait)
}

func (s *sliderChallengeStore) timedRemainingLocked(id string, wait time.Duration) (time.Duration, bool) {
	c, ok := s.challenges[id]
	now := time.Now()
	if !ok || !c.timed || now.After(c.expires) {
		return 0, false
	}
	return wait - now.Sub(c.issued), true
}

func (s *sliderChallengeStore) consumeTimed(id string, wait time.Duration) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining, ok := s.timedRemainingLocked(id, wait)
	if ok && remaining <= 0 {
		delete(s.challenges, id)
	}
	return remaining, ok
}

func (s *sliderChallengeStore) consume(id string, value, tolerance int, minSolve time.Duration) sliderConsumeResult {
	if id == "" {
		return sliderConsumeResult{}
	}
	s.mu.Lock()
	c, ok := s.challenges[id]
	delete(s.challenges, id)
	s.mu.Unlock()
	if !ok || c.timed || c.jigsaw {
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
	Seed         int64
	Width        int
	Height       int
}

func buildSliderChallenge(cfg *Config) (*sliderChallengeData, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return buildSliderFromSeed(cfg, int64(binary.BigEndian.Uint64(seed[:])))
}

func buildSliderFromSeed(cfg *Config, seed int64) (*sliderChallengeData, error) {
	w := cfg.Slider.Width
	h := cfg.Slider.Height
	rng := mrand.New(mrand.NewSource(seed))

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
	nDecoys := 2 + rng.Intn(2)
	sameDecoyIdx := rng.Intn(nDecoys)
	for i := 0; i < nDecoys; i++ {
		dx := placeDecoy(w, pieceTotal, placed, sep, rng)
		if dx < 0 {
			continue
		}
		placed = append(placed, dx)
		ds := tabShape(rng.Intn(int(shapeCount)))
		if i == sameDecoyIdx {
			ds = shape
		}
		drawTargetBand(bg, dx, pieceW, tabR, h, ds, rng)
	}

	drawTargetBand(bg, answer, pieceW, tabR, h, shape, rng)
	piece := drawPiece(scene, answer, pieceW, tabR, h, shape, rng)

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
		Seed:         seed,
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

	dashLen := 4 + rng.Intn(4)
	dashAlpha := uint8(160 + rng.Intn(50))
	dashColor := color.RGBA{uint8(220 + rng.Intn(35)), uint8(220 + rng.Intn(35)), uint8(220 + rng.Intn(35)), dashAlpha}

	for y := 0; y < h; y++ {
		if (y/dashLen)%2 == 0 {
			setPx(img, x0, y, dashColor)
			if x0+pieceW < w {
				setPx(img, x0+pieceW-1, y, dashColor)
			}
		}
	}
	for x := x0; x < x0+pieceW; x++ {
		if (x/dashLen)%2 == 0 {
			setPx(img, x, 0, dashColor)
			if h > 1 {
				setPx(img, x, h-1, dashColor)
			}
		}
	}

	notchAlpha := uint8(220 + rng.Intn(35))
	notch := color.RGBA{0, 0, 0, notchAlpha}
	tabCX := x0 + pieceW
	for dy := -tabR - 1; dy <= tabR+1; dy++ {
		for dx := 0; dx <= tabR+1; dx++ {
			if inTab(shape, dx, dy, tabR) {
				setPx(img, tabCX+dx, h/2+dy, notch)
			}
		}
	}
}

func drawPiece(scene *image.RGBA, x0, pieceW, tabR, h int, shape tabShape, rng *mrand.Rand) *image.RGBA {
	w := scene.Bounds().Dx()
	pieceTotal := pieceW + tabR
	p := image.NewRGBA(image.Rect(0, 0, pieceTotal, h))

	shiftR := rng.Intn(7) - 3
	shiftG := rng.Intn(7) - 3
	shiftB := rng.Intn(7) - 3

	extract := func(px, py int) bool {
		sx, sy := x0+px, py
		if sx < 0 || sx >= w || sy < 0 || sy >= h {
			return false
		}
		c := scene.At(sx, sy).(color.RGBA)
		clamp := func(v int) uint8 {
			if v < 0 {
				return 0
			}
			if v > 255 {
				return 255
			}
			return uint8(v)
		}
		p.SetRGBA(px, py, color.RGBA{
			R: clamp(int(c.R) + shiftR),
			G: clamp(int(c.G) + shiftG),
			B: clamp(int(c.B) + shiftB),
			A: c.A,
		})
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

	border := color.RGBA{255, 255, 255, 230}
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

var (
	soundCorrect = buildSound(0.45, func(t float64) float64 {
		env := math.Exp(-t / 0.11)
		return env * (math.Sin(2*math.Pi*1319*t) + 0.45*math.Sin(2*math.Pi*2637*t+1.2*math.Exp(-t/0.05)) + 0.2*math.Sin(2*math.Pi*4186*t)*math.Exp(-t/0.04))
	})
	soundWrong = buildSound(0.55, func(t float64) float64 {
		env := math.Min(t/0.012, 1) * math.Exp(-t/0.17)
		tone := func(hz float64) float64 {
			return math.Sin(2*math.Pi*hz*t + 0.9*math.Exp(-t/0.1)*math.Sin(2*math.Pi*2*hz*t))
		}
		return env * (tone(185) + 0.8*tone(233) + 0.7*tone(277))
	})
)

func buildSound(seconds float64, wave func(t float64) float64) string {
	const rate = 16000
	samples := make([]float64, int(seconds*rate))
	peak := 0.0
	for i := range samples {
		samples[i] = wave(float64(i) / rate)
		peak = math.Max(peak, math.Abs(samples[i]))
	}
	pcm := make([]int16, len(samples))
	for i, v := range samples {
		fade := math.Min(float64(len(samples)-i)/(0.02*rate), 1)
		pcm[i] = int16(16000 * fade * v / peak)
	}
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(36+len(pcm)*2))
	buf.WriteString("WAVEfmt ")
	for _, v := range []any{uint32(16), uint16(1), uint16(1), uint32(rate), uint32(rate * 2), uint16(2), uint16(16)} {
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
	buf.WriteString("data")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(pcm)*2))
	_ = binary.Write(&buf, binary.LittleEndian, pcm)
	return "data:audio/wav;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func jigsawPair(a, b int) int {
	if a > b {
		a, b = b, a
	}
	return a*9 + b
}

type jigsawChallenge struct {
	ImageURI string
	A, B     int
	Seed     int64
}

func jigsawSwap(src *image.RGBA, a, b int) *image.RGBA {
	out := cloneRGBA(src)
	ax, ay, bx, by := (a%3)*jigsawTileSize, (a/3)*jigsawTileSize, (b%3)*jigsawTileSize, (b/3)*jigsawTileSize
	for y := 0; y < jigsawTileSize; y++ {
		for x := 0; x < jigsawTileSize; x++ {
			out.SetRGBA(ax+x, ay+y, src.RGBAAt(bx+x, by+y))
			out.SetRGBA(bx+x, by+y, src.RGBAAt(ax+x, ay+y))
		}
	}
	return out
}

func jigsawSeamCost(img *image.RGBA) float64 {
	lum := func(x, y int) float64 {
		c := img.RGBAAt(x, y)
		return 0.3*float64(c.R) + 0.59*float64(c.G) + 0.11*float64(c.B)
	}
	cost := 0.0
	for _, seam := range []int{jigsawTileSize, 2 * jigsawTileSize} {
		for i := 0; i < 3*jigsawTileSize; i++ {
			cost += math.Abs(lum(seam-1, i)-lum(seam, i)) + math.Abs(lum(i, seam-1)-lum(i, seam))
		}
	}
	return cost
}

func drawJigsawScene(rng *mrand.Rand) *image.RGBA {
	size := 3 * jigsawTileSize
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	palettes := [][2]color.RGBA{
		{{22, 44, 92, 255}, {120, 62, 130, 255}},
		{{16, 70, 86, 255}, {150, 110, 60, 255}},
		{{70, 30, 80, 255}, {30, 110, 120, 255}},
		{{30, 60, 50, 255}, {140, 80, 90, 255}},
	}
	p := palettes[rng.Intn(len(palettes))]
	dx, dy := rng.Float64(), rng.Float64()
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			t := (dx*float64(x) + dy*float64(y)) / ((dx + dy) * float64(size))
			img.SetRGBA(x, y, lerpColor(p[0], p[1], t))
		}
	}
	bright := []color.RGBA{{255, 214, 102, 255}, {126, 222, 255, 255}, {255, 255, 255, 255}, {255, 150, 170, 255}, {170, 240, 150, 255}}
	for i := 0; i < 5; i++ {
		c := bright[rng.Intn(len(bright))]
		ringCircle(img, rng.Intn(size), rng.Intn(size), 70+rng.Intn(120), 8, c)
	}
	for i := 0; i < 9; i++ {
		c := bright[rng.Intn(len(bright))]
		fillCircle(img, rng.Intn(size), rng.Intn(size), 10+rng.Intn(14), c)
	}
	return img
}

func buildJigsawChallenge() (*jigsawChallenge, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return buildJigsawFromSeed(int64(binary.BigEndian.Uint64(seed[:])))
}

func buildJigsawFromSeed(seed int64) (*jigsawChallenge, error) {
	rng := mrand.New(mrand.NewSource(seed))
	scene := drawJigsawScene(rng)
	base := jigsawSeamCost(scene)
	var swapped *image.RGBA
	bestGain, bestA, bestB := math.Inf(-1), 0, 1
	for try := 0; try < 24; try++ {
		a := rng.Intn(9)
		b := (a + 1 + rng.Intn(8)) % 9
		candidate := jigsawSwap(scene, a, b)
		gain := jigsawSeamCost(candidate) - base
		if gain > bestGain {
			swapped, bestGain, bestA, bestB = candidate, gain, a, b
		}
		if gain >= jigsawMinSeam {
			break
		}
	}
	uri, err := pngDataURI(swapped)
	if err != nil {
		return nil, err
	}
	return &jigsawChallenge{ImageURI: uri, A: bestA, B: bestB, Seed: seed}, nil
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

	waveColors := []color.RGBA{
		{70, 95, 140, 60},
		{110, 80, 150, 50},
	}
	for i := 0; i < 2; i++ {
		freq := 0.03 + rng.Float64()*0.04
		phase := rng.Float64() * math.Pi * 2
		amp := float64(h) / float64(5+rng.Intn(4))
		baseY := float64(h/4 + rng.Intn(h/2))
		c := waveColors[i%len(waveColors)]
		for x := 0; x < w; x++ {
			wy := int(baseY + math.Sin(float64(x)*freq+phase)*amp)
			setPx(img, x, wy, c)
			setPx(img, x, wy+1, c)
		}
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
