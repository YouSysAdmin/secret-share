package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// httpMetrics holds the request instruments plus the registry they live in.
// The registry is private (not the client_golang global) so tests can build
// as many servers as they like without duplicate-registration panics.
type httpMetrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newHTTPMetrics() *httpMetrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := &httpMetrics{
		registry: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secret_share_http_requests_total",
			Help: "HTTP requests processed, by method, route and status code.",
		}, []string{"method", "route", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "secret_share_http_request_duration_seconds",
			Help:    "HTTP request latency, by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
	reg.MustRegister(m.requests, m.duration)
	return m
}

// middleware records one observation per request. The route PATTERN
// (/api/secrets/:id/reveal) is used as the label, never the raw path, so
// per-secret ids can't explode label cardinality.
//
// c.Method() is a zero-copy string over the fasthttp request buffer, which is
// reused for the next request - it MUST be copied before being retained as a
// label value or stored labels mutate in place. c.Route().Path comes from the
// static route table and is safe.
func (m *httpMetrics) middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		route := c.Route().Path
		method := utils.CopyString(c.Method())
		m.requests.WithLabelValues(method, route, strconv.Itoa(c.Response().StatusCode())).Inc()
		m.duration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
		return err
	}
}

// startServer serves /metrics on its own listener (kept off the public
// address on purpose). Returned so the caller can Shutdown it.
func (m *httpMetrics) startServer(addr string, log *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info("metrics server start", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", "err", err)
		}
	}()
	return srv
}
