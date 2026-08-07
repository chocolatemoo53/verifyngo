package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store interface {
	IncrWalkaway(ip string, ttl time.Duration) int
	ResetWalkaway(ip string)
	Block(ip string, dur time.Duration)
	IsBlocked(ip string) bool
	ShouldReport(ip string, cooldown time.Duration) bool

	IncrBanCount(ip string) int

	LogPath(ip, path string)
	RecentPaths(ip string) []string

	IncrPassiveCount(cookie string, window time.Duration) int
}

type counterEntry struct {
	Count   int       `json:"count"`
	Expires time.Time `json:"expires"`
}

const maxRecentPaths = 25

type memoryStore struct {
	mu         sync.Mutex
	walkaways  map[string]counterEntry
	blocked    map[string]time.Time
	reported   map[string]time.Time
	banCounts  map[string]int
	recentPath map[string][]string
	passiveCnt map[string]counterEntry

	persistPath  string
	saveInterval time.Duration
	dirty        bool
}

type memorySnapshot struct {
	Walkaways  map[string]counterEntry `json:"walkaways"`
	Blocked    map[string]time.Time    `json:"blocked"`
	Reported   map[string]time.Time    `json:"reported"`
	BanCounts  map[string]int          `json:"ban_counts"`
	RecentPath map[string][]string     `json:"recent_paths"`
}

func newMemoryStore(path string, saveInterval time.Duration) *memoryStore {
	s := &memoryStore{
		walkaways:    make(map[string]counterEntry),
		blocked:      make(map[string]time.Time),
		reported:     make(map[string]time.Time),
		banCounts:    make(map[string]int),
		recentPath:   make(map[string][]string),
		passiveCnt:   make(map[string]counterEntry),
		persistPath:  path,
		saveInterval: saveInterval,
	}
	s.loadSnapshot()
	go s.sweepLoop()
	if s.persistPath != "" {
		go s.persistLoop()
	}
	return s
}

func (s *memoryStore) sweepLoop() {
	t := time.NewTicker(5 * time.Minute)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for ip, e := range s.walkaways {
			if now.After(e.Expires) {
				delete(s.walkaways, ip)
				s.dirty = true
			}
		}
		for ip, exp := range s.blocked {
			if now.After(exp) {
				delete(s.blocked, ip)
				s.dirty = true
			}
		}
		for ip, ts := range s.reported {
			if now.Sub(ts) > time.Hour {
				delete(s.reported, ip)
				s.dirty = true
			}
		}
		for ip, e := range s.passiveCnt {
			if now.After(e.Expires) {
				delete(s.passiveCnt, ip)
				s.dirty = true
			}
		}
		s.mu.Unlock()
	}
}

func (s *memoryStore) IncrWalkaway(ip string, ttl time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.walkaways[ip]
	if !ok || time.Now().After(e.Expires) {
		e = counterEntry{Count: 0, Expires: time.Now().Add(ttl)}
	}
	e.Count++
	s.walkaways[ip] = e
	s.dirty = true
	return e.Count
}

func (s *memoryStore) ResetWalkaway(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.walkaways[ip]; ok {
		delete(s.walkaways, ip)
		s.dirty = true
	}
}

func (s *memoryStore) Block(ip string, dur time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked[ip] = time.Now().Add(dur)
	s.dirty = true
}

func (s *memoryStore) IsBlocked(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.blocked[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.blocked, ip)
		s.dirty = true
		return false
	}
	return true
}

func (s *memoryStore) ShouldReport(ip string, cooldown time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.reported[ip]
	if ok && time.Since(last) < cooldown {
		return false
	}
	s.reported[ip] = time.Now()
	s.dirty = true
	return true
}

func (s *memoryStore) IncrBanCount(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banCounts[ip]++
	s.dirty = true
	return s.banCounts[ip]
}

func (s *memoryStore) LogPath(ip, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	paths := s.recentPath[ip]
	if len(paths) == 0 || paths[len(paths)-1] != path {
		paths = append(paths, path)
	}
	if len(paths) > maxRecentPaths {
		paths = paths[len(paths)-maxRecentPaths:]
	}
	s.recentPath[ip] = paths
	s.dirty = true
}

func (s *memoryStore) RecentPaths(ip string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.recentPath[ip]))
	copy(out, s.recentPath[ip])
	return out
}

func (s *memoryStore) IncrPassiveCount(cookie string, window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	e, ok := s.passiveCnt[cookie]
	if !ok || now.After(e.Expires) {
		e = counterEntry{Count: 0, Expires: now.Add(window)}
	}
	e.Count++
	s.passiveCnt[cookie] = e
	s.dirty = true
	return e.Count
}

func (s *memoryStore) loadSnapshot() {
	if s.persistPath == "" {
		return
	}
	raw, err := os.ReadFile(s.persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("store: failed reading snapshot %s: %v", s.persistPath, err)
		}
		return
	}
	var snap memorySnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		log.Printf("store: failed parsing snapshot %s: %v", s.persistPath, err)
		return
	}
	now := time.Now()
	for ip, e := range snap.Walkaways {
		if now.Before(e.Expires) {
			s.walkaways[ip] = e
		}
	}
	for ip, exp := range snap.Blocked {
		if now.Before(exp) {
			s.blocked[ip] = exp
		}
	}
	for ip, ts := range snap.Reported {
		if now.Sub(ts) <= time.Hour {
			s.reported[ip] = ts
		}
	}
	for ip, n := range snap.BanCounts {
		s.banCounts[ip] = n
	}
	for ip, paths := range snap.RecentPath {
		s.recentPath[ip] = paths
	}
	log.Printf("store: loaded snapshot from %s", s.persistPath)
}

func (s *memoryStore) persistLoop() {
	t := time.NewTicker(s.saveInterval)
	for range t.C {
		s.persistSnapshot()
	}
}

func (s *memoryStore) persistSnapshot() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	snap := memorySnapshot{
		Walkaways:  make(map[string]counterEntry, len(s.walkaways)),
		Blocked:    make(map[string]time.Time, len(s.blocked)),
		Reported:   make(map[string]time.Time, len(s.reported)),
		BanCounts:  make(map[string]int, len(s.banCounts)),
		RecentPath: make(map[string][]string, len(s.recentPath)),
	}
	for ip, e := range s.walkaways {
		snap.Walkaways[ip] = e
	}
	for ip, exp := range s.blocked {
		snap.Blocked[ip] = exp
	}
	for ip, ts := range s.reported {
		snap.Reported[ip] = ts
	}
	for ip, n := range s.banCounts {
		snap.BanCounts[ip] = n
	}
	for ip, paths := range s.recentPath {
		snap.RecentPath[ip] = paths
	}
	s.dirty = false
	s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.persistPath), 0o755); err != nil {
		log.Printf("store: failed creating snapshot dir: %v", err)
		return
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("store: failed serializing snapshot: %v", err)
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("store: failed writing snapshot temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.Printf("store: failed replacing snapshot: %v", err)
	}
}

type redisStore struct {
	ctx context.Context
	rdb *redis.Client
	pfx string
}

func newRedisStore(cfg *Config) *redisStore {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Store.Redis.Addr,
		Password: cfg.Store.Redis.Password,
		DB:       cfg.Store.Redis.DB,
	})
	s := &redisStore{
		ctx: context.Background(),
		rdb: rdb,
		pfx: cfg.Store.Redis.KeyPrefix,
	}
	if err := rdb.Ping(s.ctx).Err(); err != nil {
		log.Printf("store: redis ping failed (%v); continuing with redis backend, operations may fail", err)
	}
	return s
}

func (s *redisStore) k(kind, ip string) string {
	return s.pfx + ":" + kind + ":" + ip
}

func (s *redisStore) IncrWalkaway(ip string, ttl time.Duration) int {
	key := s.k("walkaway", ip)
	pipe := s.rdb.TxPipeline()
	incr := pipe.Incr(s.ctx, key)
	pipe.Expire(s.ctx, key, ttl)
	_, err := pipe.Exec(s.ctx)
	if err != nil {
		log.Printf("store: redis incr walkaway failed: %v", err)
		return 0
	}
	return int(incr.Val())
}

func (s *redisStore) ResetWalkaway(ip string) {
	if err := s.rdb.Del(s.ctx, s.k("walkaway", ip)).Err(); err != nil {
		log.Printf("store: redis reset walkaway failed: %v", err)
	}
}

func (s *redisStore) Block(ip string, dur time.Duration) {
	if err := s.rdb.Set(s.ctx, s.k("blocked", ip), "1", dur).Err(); err != nil {
		log.Printf("store: redis block failed: %v", err)
	}
}

func (s *redisStore) IsBlocked(ip string) bool {
	ok, err := s.rdb.Exists(s.ctx, s.k("blocked", ip)).Result()
	if err != nil {
		log.Printf("store: redis blocked check failed: %v", err)
		return false
	}
	return ok > 0
}

func (s *redisStore) ShouldReport(ip string, cooldown time.Duration) bool {
	ok, err := s.rdb.SetNX(s.ctx, s.k("reported", ip), "1", cooldown).Result()
	if err != nil {
		log.Printf("store: redis report cooldown failed: %v", err)
		return false
	}
	return ok
}

func (s *redisStore) IncrBanCount(ip string) int {
	key := s.k("bancount", ip)
	n, err := s.rdb.Incr(s.ctx, key).Result()
	if err != nil {
		log.Printf("store: redis incr ban count failed: %v", err)
		return 0
	}
	if n == 1 {
		if err := s.rdb.Expire(s.ctx, key, 30*24*time.Hour).Err(); err != nil {
			log.Printf("store: redis expire ban count failed: %v", err)
		}
	}
	return int(n)
}

func (s *redisStore) LogPath(ip, path string) {
	key := s.k("paths", ip)
	pipe := s.rdb.TxPipeline()
	pipe.RPush(s.ctx, key, path)
	pipe.LTrim(s.ctx, key, int64(-maxRecentPaths), -1)
	pipe.Expire(s.ctx, key, 7*24*time.Hour)
	if _, err := pipe.Exec(s.ctx); err != nil {
		log.Printf("store: redis log path failed: %v", err)
	}
}

func (s *redisStore) RecentPaths(ip string) []string {
	out, err := s.rdb.LRange(s.ctx, s.k("paths", ip), 0, -1).Result()
	if err != nil {
		log.Printf("store: redis recent paths failed: %v", err)
		return nil
	}
	return out
}

func (s *redisStore) IncrPassiveCount(cookie string, window time.Duration) int {
	key := s.k("passive", cookie)
	pipe := s.rdb.TxPipeline()
	incr := pipe.Incr(s.ctx, key)
	pipe.Expire(s.ctx, key, window)
	_, err := pipe.Exec(s.ctx)
	if err != nil {
		log.Printf("store: redis incr passive count failed: %v", err)
		return 0
	}
	return int(incr.Val())
}

func newStore(cfg *Config) Store {
	switch cfg.Store.Backend {
	case "redis":
		return newRedisStore(cfg)
	default:
		return newMemoryStore(cfg.Store.File.Path, cfg.Store.File.SaveInterval.Duration)
	}
}
