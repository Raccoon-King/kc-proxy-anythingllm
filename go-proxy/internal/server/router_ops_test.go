package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadyzDisabledReturnsOK(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestReadyzFailureReturns503(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.ReadinessChecks = true
	deps.Cfg.ReadinessTimeout = 500 * time.Millisecond
	deps.Ready = func(ctx context.Context) error { return errors.New("nope") }
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.MetricsEnabled = true
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rr, req)

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr2.Code)
	}
	body := rr2.Body.String()
	if !strings.Contains(body, "proxy_requests_total") {
		t.Fatalf("expected metrics output")
	}
}

func TestRateLimitReturns429(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.RateLimitPerMinute = 1
	deps.Cfg.RateLimitBurst = 0
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr2.Code)
	}
}

func TestSecurityHeadersApplied(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.SecurityHeaders = true
	deps.Cfg.HeaderFrameOptions = "SAMEORIGIN"
	deps.Cfg.HeaderReferrerPolicy = "no-referrer"
	deps.Cfg.HeaderPermissions = "geolocation=()"
	deps.Cfg.HeaderCSP = "default-src 'self'"
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rr, req)

	if rr.Header().Get("X-Frame-Options") == "" {
		t.Fatalf("expected X-Frame-Options header")
	}
	if rr.Header().Get("Referrer-Policy") == "" {
		t.Fatalf("expected Referrer-Policy header")
	}
	if rr.Header().Get("Permissions-Policy") == "" {
		t.Fatalf("expected Permissions-Policy header")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("expected Content-Security-Policy header")
	}
}
