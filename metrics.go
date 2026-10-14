package main

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_decisions_total",
		Help: "Requests by how they were handled.",
	}, []string{"decision"})
	metricRuleHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_rule_hits_total",
		Help: "Requests decided by each rule.",
	}, []string{"rule", "action"})
	metricChallenges = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_challenges_total",
		Help: "Challenges issued and the result of each verify attempt.",
	}, []string{"provider", "result"})
	metricBans = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_bans_total",
		Help: "Bans issued by reason.",
	}, []string{"reason"})
	metricBrowserMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_browser_mismatch_total",
		Help: "Requests whose user agent does not match the headers sent.",
	}, []string{"kind"})
	metricPassive = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_passive_total",
		Help: "Progressive mode outcomes on passive paths.",
	}, []string{"result"})
	metricUpstream = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_upstream_responses_total",
		Help: "Upstream responses by status class, or error when the upstream could not be reached.",
	}, []string{"status"})
	metricStoreErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_store_errors_total",
		Help: "Failed Redis operations.",
	}, []string{"op"})
	metricRuleReloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_rule_reloads_total",
		Help: "Rule loads and reloads by result.",
	}, []string{"result"})
	metricRulesLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "verifyngo_rules_loaded",
		Help: "1 once the rules have loaded, 0 while they are still loading at startup.",
	})
	metricTor = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verifyngo_tor_requests_total",
		Help: "Requests arriving over Tor, as onion or exit traffic.",
	}, []string{"kind"})
	metricTorExits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "verifyngo_tor_exits",
		Help: "Addresses in the Tor exit list.",
	})
	metricBlocklistEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "verifyngo_blocklist_entries",
		Help: "Entries in the AbuseIPDB blocklist.",
	})
)

func storeError(op string, err error) {
	metricStoreErrors.WithLabelValues(op).Inc()
	log.Printf("store: redis %s failed: %v", op, err)
}

func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("metrics listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("metrics: %v", err)
	}
}
