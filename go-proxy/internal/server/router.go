package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// OIDCClient is the minimal interface needed for login flows.
type OIDCClient interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	VerifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, *auth.TokenClaims, error)
}

// LLMClient is the AnythingLLM API client interface used by the proxy.
type LLMClient interface {
	EnsureUser(ctx context.Context, email, name, role string, allowCreate bool) (string, error)
	IssueAuthToken(ctx context.Context, userID string) (*anythingllm.AuthTokenResponse, error)
}

// Dependencies bundles required services for handler construction.
type Dependencies struct {
	Cfg      config.Config
	Sessions *auth.SessionManager
	OIDC     OIDCClient
	LLM      LLMClient
	Ready    func(ctx context.Context) error
	// Feature flags (used only in tests or optional behaviors)
	DisableAgreement bool
}

// NewRouter builds the HTTP handler with all routes wired.
// Flow: Agreement (pre-auth) → Keycloak Auth → App
func NewRouter(d Dependencies) http.Handler {
	proxy := newReverseProxy(d.Cfg)
	idTokenCache := newTokenCache()
	metrics := newMetrics(d.Cfg.MetricsEnabled)
	limiter := newRateLimiter(d.Cfg.RateLimitPerMinute, d.Cfg.RateLimitBurst)
	secLog := func(format string, args ...interface{}) {
		if d.Cfg.SecurityLogging {
			log.Printf("[SEC] "+format, args...)
		}
	}
	dbgLog := func(format string, args ...interface{}) {
		if d.Cfg.DebugLogging {
			log.Printf("[DBG] "+format, args...)
		}
	}

	mux := http.NewServeMux()

	// Health check - no auth required
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Readiness check - optional upstream validation
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !d.Cfg.ReadinessChecks || d.Ready == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d.Cfg.ReadinessTimeout)
		defer cancel()
		if err := d.Ready(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Metrics endpoint (optional)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !d.Cfg.MetricsEnabled {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metrics.Render()))
	})

	// Debug endpoint - dump session state
	mux.HandleFunc("/debug/session", func(w http.ResponseWriter, r *http.Request) {
		sess, err := d.Sessions.Get(r)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Session Debug\n")
		fmt.Fprintf(w, "=============\n")
		fmt.Fprintf(w, "Error: %v\n", err)
		fmt.Fprintf(w, "IsNew: %v\n", sess.IsNew)
		fmt.Fprintf(w, "ID: %s\n", sess.ID)
		fmt.Fprintf(w, "\nValues:\n")
		for k, v := range sess.Values {
			fmt.Fprintf(w, "  %v: %v\n", k, v)
		}
		fmt.Fprintf(w, "\nCookies received:\n")
		for _, c := range r.Cookies() {
			fmt.Fprintf(w, "  %s: %s (len=%d)\n", c.Name, c.Value[:min(50, len(c.Value))], len(c.Value))
		}
	})

	// Debug endpoint - set a test value in session
	mux.HandleFunc("/debug/session/set", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		sess.Values["test_value"] = time.Now().Unix()
		sess.Values["agreement_accepted"] = true
		err := d.Sessions.Save(r, w, sess)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Session Set Debug\n")
		fmt.Fprintf(w, "=================\n")
		fmt.Fprintf(w, "Save error: %v\n", err)
		fmt.Fprintf(w, "IsNew: %v\n", sess.IsNew)
		fmt.Fprintf(w, "test_value set to: %v\n", sess.Values["test_value"])
		fmt.Fprintf(w, "agreement_accepted set to: %v\n", sess.Values["agreement_accepted"])
		fmt.Fprintf(w, "\nNow visit /debug/session to verify persistence\n")
	})

	// Agreement page - shown BEFORE Keycloak auth (no auth required)
	mux.HandleFunc("/agreement", func(w http.ResponseWriter, r *http.Request) {
		if d.DisableAgreement {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sess, _ := d.Sessions.Get(r)

		// If no valid session, force login first so we have a place to store acceptance/next
		if !isSessionValid(sess) {
			redirect := r.URL.String()
			dbgLog("agreement: no session, redirecting to login with redirect=%s", redirect)
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect), http.StatusFound)
			return
		}

		if accepted, _ := sess.Values["agreement_accepted"].(bool); accepted {
			// Already accepted, proceed to login or app
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		dbgLog("showing agreement page")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderAgreementPage(d.Cfg)))
	})

	// Agreement accept - stores acceptance in session, then redirects to login
	mux.HandleFunc("/agreement/accept", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if d.DisableAgreement {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sess, _ := d.Sessions.Get(r)
		if !isSessionValid(sess) {
			redirect := r.URL.Query().Get("redirect")
			if redirect == "" {
				redirect = "/"
			}
			dbgLog("agreement accept: no valid session, redirecting to login redirect=%s", redirect)
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect), http.StatusFound)
			return
		}
		sess.Values["agreement_accepted"] = true

		next := "/"
		if v, ok := sess.Values["agreement_next"].(string); ok && v != "" {
			next = v
		}
		delete(sess.Values, "agreement_next")

		_ = d.Sessions.Save(r, w, sess)
		secLog("agreement accepted; redirecting to %s", next)
		http.Redirect(w, r, next, http.StatusFound)
	})

	// Access request page (no auth required)
	mux.HandleFunc("/access-request", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		tokenFields := map[string]string{
			"username":    stringFromSession(sess, "access_request_username"),
			"email":       stringFromSession(sess, "access_request_email"),
			"given_name":  stringFromSession(sess, "access_request_given_name"),
			"family_name": stringFromSession(sess, "access_request_family_name"),
			"name":        stringFromSession(sess, "access_request_name"),
			"sub":         stringFromSession(sess, "access_request_sub"),
		}
		groups, _ := sess.Values["access_request_groups"].([]string)
		tokenFields["groups"] = strings.Join(groups, ", ")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderAccessRequestPage(d.Cfg, tokenFields)))
	})

	// Logged-out page (no auth required)
	mux.HandleFunc("/logged-out", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderLoggedOutPage(d.Cfg)))
	})

	// Login - requires agreement first, then initiates Keycloak auth
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)

		// Already authenticated?
		if isSessionValid(sess) {
			dbgLog("login: already authenticated, redirecting to /")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Start OAuth flow
		state := randomString(24)
		codeVerifier := randomString(64)
		codeChallenge := pkceChallenge(codeVerifier)
		redirectAfter := sanitizeRedirect(r.URL.Query().Get("redirect"))
		dbgLog("login: starting oauth flow, redirect=%s state=%s", redirectAfter, state)

		sess.Values["oauth_state"] = state
		sess.Values["redirect_after"] = redirectAfter
		sess.Values["code_verifier"] = codeVerifier
		_ = d.Sessions.Save(r, w, sess)

		authURL := d.OIDC.AuthCodeURL(state,
			oauth2AccessTypeOffline(),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	// OAuth callback - exchanges code for tokens, syncs user, redirects to app
	mux.HandleFunc(d.Cfg.CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)

		// Validate state
		state := r.URL.Query().Get("state")
		expectedState, _ := sess.Values["oauth_state"].(string)
		if expectedState == "" || expectedState != state {
			secLog("state mismatch session=%v incoming=%s", sess.Values["oauth_state"], state)
			clearIDTokenCache(sess, idTokenCache)
			_ = d.Sessions.Clear(r, w)
			http.Redirect(w, r, keycloakLogoutURL(d.Cfg), http.StatusFound)
			return
		}

		// Get PKCE verifier
		verifier, _ := sess.Values["code_verifier"].(string)
		if verifier == "" {
			secLog("missing pkce verifier for code exchange")
			http.Error(w, "missing pkce verifier", http.StatusBadRequest)
			return
		}

		// Consume state and verifier immediately to prevent duplicate processing
		delete(sess.Values, "oauth_state")
		delete(sess.Values, "code_verifier")
		_ = d.Sessions.Save(r, w, sess)

		// Exchange code for tokens
		code := r.URL.Query().Get("code")
		token, err := d.OIDC.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			secLog("code exchange failed: %v", err)
			http.Error(w, "login failed", http.StatusBadRequest)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			secLog("no id_token returned")
			http.Error(w, "no id_token in response", http.StatusBadRequest)
			return
		}
		dbgLog("kc id_token raw=%s", rawIDToken)

		idToken, claims, err := d.OIDC.VerifyIDToken(r.Context(), rawIDToken)
		if err != nil {
			secLog("invalid id token: %v", err)
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		dbgLog("kc id_token claims=%s", decodeJWTClaims(rawIDToken))

		// Store only small identity/session fields to avoid cookie bloat.
		storeIDToken(sess, idTokenCache, rawIDToken)
		expiry := token.Expiry
		if idToken != nil && !idToken.Expiry.IsZero() {
			expiry = idToken.Expiry
		}
		if expiry.IsZero() {
			expiry = time.Now().Add(1 * time.Hour)
		}
		sess.Values["expiry"] = expiry.Unix()
		sess.Values["email"] = claims.Email
		sess.Values["name"] = pickName(claims)
		sess.Values["agreement_accepted"] = false

		// Determine login ID (used for logs and fallback)
		loginID := claims.Email
		if claims.PreferredUsername != "" {
			loginID = claims.PreferredUsername
		}
		if loginID == "" && claims.Subject != "" {
			loginID = claims.Subject + "@oidc.local"
		}

		// Sync user with AnythingLLM (prefer email for lookup/creation)
		ensureEmail := claims.Email
		if ensureEmail == "" {
			ensureEmail = loginID
		}
		userID, err := d.LLM.EnsureUser(r.Context(), ensureEmail, pickName(claims), d.Cfg.DefaultRole, d.Cfg.AutoCreateUsers)
		if err != nil {
			if errors.Is(err, anythingllm.ErrUserNotFound) {
				sess.Values["access_request_email"] = claims.Email
				sess.Values["access_request_name"] = pickName(claims)
				sess.Values["access_request_username"] = claims.PreferredUsername
				sess.Values["access_request_given_name"] = claims.GivenName
				sess.Values["access_request_family_name"] = claims.FamilyName
				sess.Values["access_request_groups"] = claims.Groups
				sess.Values["access_request_sub"] = claims.Subject
				_ = d.Sessions.Save(r, w, sess)
				http.Redirect(w, r, "/access-request", http.StatusFound)
				return
			}
			secLog("ensure user failed loginID=%s: %v", loginID, err)
			http.Error(w, "failed to sync user", http.StatusBadGateway)
			return
		}

		// Get SSO token from AnythingLLM
		tokenResp, err := d.LLM.IssueAuthToken(r.Context(), userID)
		if err != nil {
			secLog("issue auth token failed userID=%s: %v", userID, err)
			http.Error(w, "failed to issue sso token", http.StatusBadGateway)
			return
		}

		_ = d.Sessions.Save(r, w, sess)
		secLog("login success userID=%s loginID=%s", userID, loginID)

		// Build redirect path
		redirectPath := tokenResp.LoginPath
		if !strings.HasPrefix(redirectPath, "/") {
			redirectPath = "/" + redirectPath
		}
		if after, _ := sess.Values["redirect_after"].(string); after != "" && after != "/" {
			redirectPath = redirectPath + "&redirectTo=" + url.QueryEscape(after)
		}

		// Force agreement gating
		sess.Values["agreement_next"] = redirectPath
		_ = d.Sessions.Save(r, w, sess)

		dbgLog("callback complete, redirecting to agreement then %s", redirectPath)
		secLog("sso token issued userID=%s loginID=%s next=%s", userID, loginID, redirectPath)
		http.Redirect(w, r, "/agreement", http.StatusFound)
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		idToken := getIDToken(sess, idTokenCache)
		clearIDTokenCache(sess, idTokenCache)
		_ = d.Sessions.Clear(r, w)
		secLog("logout local session cleared")
		http.Redirect(w, r, keycloakLogoutURLWithHint(d.Cfg, idToken), http.StatusFound)
	})

	// Main catch-all route - requires agreement + auth
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)
		sess, _ := d.Sessions.Get(r)

		// Handle logout paths early to avoid hanging on downstream redirects.
		if strings.Contains(path, "logout") {
			idToken := getIDToken(sess, idTokenCache)
			clearIDTokenCache(sess, idTokenCache)
			_ = d.Sessions.Clear(r, w)
			secLog("logout requested; local session cleared path=%s", r.URL.Path)
			http.Redirect(w, r, keycloakLogoutURLWithHint(d.Cfg, idToken), http.StatusFound)
			return
		}

		// Skip auth for static assets to prevent parallel auth flows
		if strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2") ||
			path == "/manifest.json" || path == "/asset-manifest.json" ||
			strings.HasPrefix(path, "/.well-known/") {
			proxy.ServeHTTP(w, r)
			return
		}

		// Allow AnythingLLM's SSO/API endpoints through with a guard for missing token
		if strings.HasPrefix(path, "/sso/") {
			if r.URL.Query().Get("token") == "" {
				// If session is still valid, re-issue SSO token instead of logging out
				if isSessionValid(sess) {
					email, _ := sess.Values["email"].(string)
					name, _ := sess.Values["name"].(string)
					if email != "" {
						dbgLog("sso request without token but valid session, re-issuing token for %s", email)
						userID, err := d.LLM.EnsureUser(r.Context(), email, name, d.Cfg.DefaultRole, false)
						if err == nil {
							tokenResp, err := d.LLM.IssueAuthToken(r.Context(), userID)
							if err == nil {
								redirectPath := tokenResp.LoginPath
								if !strings.HasPrefix(redirectPath, "/") {
									redirectPath = "/" + redirectPath
								}
								secLog("sso token re-issued userID=%s email=%s", userID, email)
								http.Redirect(w, r, redirectPath, http.StatusFound)
								return
							}
							secLog("failed to re-issue auth token: %v", err)
						} else {
							secLog("failed to ensure user for token re-issue: %v", err)
						}
					}
				}
				// Fall back to logout if session invalid or re-issue failed
				dbgLog("sso request without token, logging out of keycloak")
				idToken := getIDToken(sess, idTokenCache)
				clearIDTokenCache(sess, idTokenCache)
				_ = d.Sessions.Clear(r, w)
				http.Redirect(w, r, keycloakLogoutURLWithHint(d.Cfg, idToken), http.StatusFound)
				return
			}
			dbgLog("allowing SSO path through without proxy auth: %s", path)
			proxy.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/") {
			dbgLog("allowing API path through without proxy auth: %s", path)
			proxy.ServeHTTP(w, r)
			return
		}

		// Check authentication first
		if !isSessionValid(sess) {
			dbgLog("main: not authenticated, redirecting to login")
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.String()), http.StatusFound)
			return
		}

		// Then check agreement (unless disabled)
		if !d.DisableAgreement {
			if accepted, _ := sess.Values["agreement_accepted"].(bool); !accepted {
				dbgLog("main: agreement not accepted, redirecting to agreement")
				http.Redirect(w, r, "/agreement?redirect="+url.QueryEscape(r.URL.String()), http.StatusFound)
				return
			}
		}

		dbgLog("proxying %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})

	handler := http.Handler(mux)
	if limiter != nil {
		handler = withRateLimit(handler, limiter)
	}
	if d.Cfg.SecurityHeaders {
		handler = withSecurityHeaders(handler, d.Cfg)
	}
	if metrics != nil {
		handler = withMetrics(handler, metrics)
	}
	if d.Cfg.AccessLogging {
		handler = withAccessLog(handler)
	}
	return handler
}

// --- helpers ---

func newReverseProxy(cfg config.Config) *httputil.ReverseProxy {
	targetURL, _ := url.Parse(cfg.AnythingLLMBaseURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
		// Strip caching headers for HTML page requests to ensure we get fresh content to inject banners into.
		// Without this, 304 responses have no body and we can't inject.
		path := req.URL.Path
		isHTMLRequest := path == "/" || path == "" || (!strings.Contains(path, ".") && !strings.HasPrefix(path, "/api/"))
		if isHTMLRequest {
			req.Header.Del("If-None-Match")
			req.Header.Del("If-Modified-Since")
		}
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp == nil || resp.Body == nil {
			return nil
		}
		path := ""
		if resp.Request != nil && resp.Request.URL != nil {
			path = resp.Request.URL.Path
		}

		// If AnythingLLM returns auth failure or redirects to its own login, force a fresh SSO cycle.
		if !(strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/sso/")) &&
			(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || isLoginRedirect(resp)) {
			expireProxyCookie(resp)
			resp.StatusCode = http.StatusFound
			resp.Header.Set("Location", "/login")
			resp.Body = io.NopCloser(bytes.NewBuffer(nil))
			resp.Header.Set("Content-Length", "0")
			return nil
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "text/html") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		injected := injectBanners(string(body), cfg)
		resp.Body = io.NopCloser(bytes.NewBufferString(injected))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(injected)))
		return nil
	}
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: cfg.UpstreamDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   cfg.UpstreamTLSHandshake,
		ResponseHeaderTimeout: cfg.UpstreamResponseHdr,
		IdleConnTimeout:       cfg.UpstreamIdleTimeout,
		MaxIdleConns:          cfg.UpstreamMaxIdle,
		MaxIdleConnsPerHost:   cfg.UpstreamMaxIdleHost,
	}
	proxy.FlushInterval = 100 * time.Millisecond
	return proxy
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.size += n
	return n, err
}

func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/healthz") || strings.HasPrefix(r.URL.Path, "/readyz") || strings.HasPrefix(r.URL.Path, "/metrics") {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = randomString(12)
			rec.Header().Set("X-Request-Id", requestID)
		}
		next.ServeHTTP(rec, r)
		duration := time.Since(start)
		log.Printf("%s %s %s %d %d %s", clientIP(r), r.Method, r.URL.Path, rec.status, rec.size, duration)
	})
}

func withSecurityHeaders(next http.Handler, cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.HeaderFrameOptions != "" {
			w.Header().Set("X-Frame-Options", cfg.HeaderFrameOptions)
		}
		if cfg.HeaderReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", cfg.HeaderReferrerPolicy)
		}
		if cfg.HeaderPermissions != "" {
			w.Header().Set("Permissions-Policy", cfg.HeaderPermissions)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if cfg.HeaderCSP != "" {
			w.Header().Set("Content-Security-Policy", cfg.HeaderCSP)
		}
		next.ServeHTTP(w, r)
	})
}

type metricsState struct {
	enabled  bool
	inflight int64
	total    uint64
	errors   uint64
	mu       sync.Mutex
	byCode   map[int]int64
}

func newMetrics(enabled bool) *metricsState {
	if !enabled {
		return nil
	}
	return &metricsState{enabled: true, byCode: make(map[int]int64)}
}

func (m *metricsState) Render() string {
	if m == nil || !m.enabled {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	b.WriteString("# TYPE proxy_requests_total counter\n")
	b.WriteString("proxy_requests_total " + strconv.FormatUint(atomic.LoadUint64(&m.total), 10) + "\n")
	b.WriteString("# TYPE proxy_requests_inflight gauge\n")
	b.WriteString("proxy_requests_inflight " + strconv.FormatInt(atomic.LoadInt64(&m.inflight), 10) + "\n")
	b.WriteString("# TYPE proxy_requests_errors_total counter\n")
	b.WriteString("proxy_requests_errors_total " + strconv.FormatUint(atomic.LoadUint64(&m.errors), 10) + "\n")
	for code, count := range m.byCode {
		b.WriteString(fmt.Sprintf("proxy_requests_status_total{code=\"%d\"} %d\n", code, count))
	}
	return b.String()
}

func withMetrics(next http.Handler, m *metricsState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || !m.enabled {
			next.ServeHTTP(w, r)
			return
		}
		atomic.AddInt64(&m.inflight, 1)
		atomic.AddUint64(&m.total, 1)
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		atomic.AddInt64(&m.inflight, -1)
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		if code >= 500 {
			atomic.AddUint64(&m.errors, 1)
		}
		m.mu.Lock()
		m.byCode[code]++
		m.mu.Unlock()
	})
}

type rateLimiter struct {
	perMinute int
	burst     int
	mu        sync.Mutex
	buckets   map[string]*rateBucket
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

func newRateLimiter(perMinute, burst int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if burst < 0 {
		burst = 0
	}
	return &rateLimiter{perMinute: perMinute, burst: burst, buckets: make(map[string]*rateBucket)}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &rateBucket{windowStart: now, count: 1}
		return true
	}
	if now.Sub(b.windowStart) >= time.Minute {
		b.windowStart = now
		b.count = 1
		return true
	}
	limit := l.perMinute + l.burst
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

func withRateLimit(next http.Handler, limiter *rateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter == nil {
			next.ServeHTTP(w, r)
			return
		}
		key := clientIP(r)
		if key == "" {
			key = "unknown"
		}
		if !limiter.allow(key) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func pickName(c *auth.TokenClaims) string {
	if c == nil {
		return ""
	}
	if c.Name != "" {
		return c.Name
	}
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Email
}

func renderAgreementPage(cfg config.Config) string {
	body := fmt.Sprintf(`
<div class="proxy-agreement-modal">
  <div class="proxy-agreement-card">
    <h1>%s</h1>
    <p>%s</p>
    <form method="POST" action="/agreement/accept">
      <button type="submit">%s</button>
    </form>
  </div>
</div>
`, html.EscapeString(cfg.AgreementTitle), html.EscapeString(cfg.AgreementBody), html.EscapeString(cfg.AgreementButtonText))
	return injectBanners(agreementHTML(body), cfg)
}

func renderLoggedOutPage(cfg config.Config) string {
	title := strings.TrimSpace(cfg.LoggedOutTitle)
	if title == "" {
		title = "Signed out"
	}
	msg := strings.TrimSpace(cfg.LoggedOutBody)
	if msg == "" {
		msg = "You have been signed out."
	}
	linkText := strings.TrimSpace(cfg.LoggedOutLinkText)
	if linkText == "" {
		linkText = "Sign in again"
	}
	body := fmt.Sprintf(`
<div class="proxy-agreement-modal">
  <div class="proxy-agreement-card">
    <h1>%s</h1>
    <p>%s</p>
    <a href="/login">%s</a>
  </div>
</div>`, html.EscapeString(title), html.EscapeString(msg), html.EscapeString(linkText))
	return injectBanners(agreementHTML(body), cfg)
}

func renderAccessRequestPage(cfg config.Config, tokenFields map[string]string) string {
	display := strings.TrimSpace(tokenFields["name"])
	if display == "" {
		display = strings.TrimSpace(tokenFields["email"])
	}
	if display == "" {
		display = "Unknown user"
	}
	subjectLine := strings.TrimSpace(cfg.AccessRequestSubject)
	if subjectLine == "" {
		subjectLine = "AnythingLLM access request"
	}
	contactLine := strings.TrimSpace(cfg.AccessRequestContact)
	if contactLine == "" {
		contactLine = "helpdesk@help.com"
	}
	title := strings.TrimSpace(cfg.AccessRequestTitle)
	if title == "" {
		title = "Access required"
	}
	bodyTemplate := strings.TrimSpace(cfg.AccessRequestBody)
	if bodyTemplate == "" {
		bodyTemplate = "%s does not have an AnythingLLM account."
	}
	prompt := strings.TrimSpace(cfg.AccessRequestPrompt)
	if prompt == "" {
		prompt = "Paste this in an email to the helpdesk:"
	}
	contactLabel := strings.TrimSpace(cfg.AccessRequestContactLabel)
	if contactLabel == "" {
		contactLabel = "Contact:"
	}
	subjectLabel := strings.TrimSpace(cfg.AccessRequestSubjectLabel)
	if subjectLabel == "" {
		subjectLabel = "Use this subject line:"
	}
	signOutText := strings.TrimSpace(cfg.AccessRequestSignOutText)
	if signOutText == "" {
		signOutText = "Sign out"
	}
	infoLines := make([]string, 0, len(cfg.AccessRequestFields))
	for _, field := range cfg.AccessRequestFields {
		key := strings.TrimSpace(strings.ToLower(field))
		if key == "" {
			continue
		}
		label := accessRequestLabel(key)
		if label == "" {
			continue
		}
		value := strings.TrimSpace(tokenFields[key])
		if value == "" {
			continue
		}
		infoLines = append(infoLines, label+": "+value)
	}
	// Remove empty fields while keeping labels clean.
	clean := make([]string, 0, len(infoLines))
	for _, line := range infoLines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) == "" {
			continue
		}
		clean = append(clean, line)
	}
	joined := html.EscapeString(strings.Join(clean, "\n"))
	body := fmt.Sprintf(`
<div class="proxy-agreement-modal">
  <div class="proxy-agreement-card">
    <h1>%s</h1>
    <p>%s</p>
    <p><strong>%s</strong> %s</p>
    <p><strong>%s</strong> %s</p>
    <p><strong>%s</strong></p>
    <pre>%s</pre>
    <a href="/logout">%s</a>
  </div>
</div>`, html.EscapeString(title), html.EscapeString(fmt.Sprintf(bodyTemplate, display)), html.EscapeString(subjectLabel), html.EscapeString(subjectLine), html.EscapeString(contactLabel), html.EscapeString(contactLine), html.EscapeString(prompt), joined, html.EscapeString(signOutText))
	return injectBanners(agreementHTML(body), cfg)
}

func accessRequestLabel(field string) string {
	switch field {
	case "username", "preferred_username":
		return "Username"
	case "email":
		return "Email"
	case "given_name":
		return "First Name"
	case "family_name":
		return "Last Name"
	case "name":
		return "Display Name"
	case "groups":
		return "Groups"
	case "sub", "subject":
		return "Keycloak Subject"
	default:
		return ""
	}
}

func agreementHTML(inner string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Agreement</title>
</head>
<body class="proxy-standalone">
%s
</body>
</html>`, inner)
}

func injectBanners(htmlBody string, cfg config.Config) string {
	if strings.Contains(htmlBody, "proxy-banner-top") {
		return htmlBody
	}
style := fmt.Sprintf(`<style>
:root {
  --proxy-banner-height: 24px;
  --proxy-bg: #0b1020;
  --proxy-surface: #0f172a;
  --proxy-surface-strong: #111c34;
  --proxy-border: rgba(148, 163, 184, 0.18);
  --proxy-text: #e2e8f0;
  --proxy-muted: #94a3b8;
  --proxy-accent: #2dd4bf;
  --proxy-accent-strong: #14b8a6;
  --proxy-shadow: 0 24px 60px rgba(2, 6, 23, 0.55);
}
#proxy-banner-top,#proxy-banner-bottom {
  position: fixed;
  left: 0;
  right: 0;
  height: var(--proxy-banner-height);
  line-height: var(--proxy-banner-height);
  background: %s;
  color: %s;
  text-align: center;
  font-weight: 700;
  font-family: "Space Grotesk", "Segoe UI", system-ui, -apple-system, sans-serif;
  z-index: 2147483000;
}
#proxy-banner-top { top: 0; }
#proxy-banner-bottom { bottom: 0; }
html, body { height: 100%%; }
body {
  margin: 0;
  padding-top: var(--proxy-banner-height);
  padding-bottom: var(--proxy-banner-height);
  box-sizing: border-box;
  scroll-padding-top: var(--proxy-banner-height);
  scroll-padding-bottom: var(--proxy-banner-height);
  overflow-y: auto;
}
.proxy-standalone {
  background:
    radial-gradient(1200px 520px at 10%% -10%%, rgba(45, 212, 191, 0.18), transparent 60%%),
    radial-gradient(900px 520px at 90%% 0%%, rgba(56, 189, 248, 0.16), transparent 60%%),
    var(--proxy-bg);
  color: var(--proxy-text);
  font-family: "Space Grotesk", "Segoe UI", system-ui, -apple-system, sans-serif;
}
#root,
#app,
main {
  min-height: calc(100vh - (var(--proxy-banner-height) * 2));
  height: auto;
  max-height: none;
  overflow: visible !important;
}
.proxy-agreement-modal {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(3, 7, 18, 0.65);
  backdrop-filter: blur(8px);
  z-index: 2147483001;
  padding: 32px 20px;
}
.proxy-agreement-card {
  background: linear-gradient(180deg, var(--proxy-surface), var(--proxy-surface-strong));
  padding: 28px;
  max-width: 560px;
  width: min(560px, 100%%);
  border-radius: 16px;
  border: 1px solid var(--proxy-border);
  box-shadow: var(--proxy-shadow);
  font-family: "Space Grotesk", "Segoe UI", system-ui, -apple-system, sans-serif;
}
.proxy-agreement-card h1 {
  margin: 0 0 12px;
  font-size: 22px;
  letter-spacing: -0.02em;
}
.proxy-agreement-card p {
  margin: 0 0 16px;
  font-size: 15px;
  line-height: 1.5;
  color: var(--proxy-muted);
}
.proxy-agreement-card strong { color: var(--proxy-text); }
.proxy-agreement-card pre {
  margin: 0 0 18px;
  padding: 14px 16px;
  border-radius: 12px;
  background: rgba(15, 23, 42, 0.8);
  border: 1px solid var(--proxy-border);
  color: var(--proxy-text);
  font-family: "IBM Plex Mono", "SFMono-Regular", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.5;
  white-space: pre-wrap;
}
.proxy-agreement-card button,
.proxy-agreement-card a {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  text-decoration: none;
  background: linear-gradient(135deg, var(--proxy-accent), var(--proxy-accent-strong));
  color: #05101a;
  border: 0;
  padding: 10px 18px;
  font-weight: 700;
  font-size: 14px;
  border-radius: 10px;
  cursor: pointer;
  box-shadow: 0 10px 24px rgba(20, 184, 166, 0.35);
  transition: transform 120ms ease, box-shadow 120ms ease;
}
.proxy-agreement-card button:hover,
.proxy-agreement-card a:hover {
  transform: translateY(-1px);
  box-shadow: 0 14px 30px rgba(20, 184, 166, 0.4);
}
</style>`, cssSafe(cfg.BannerBgColor), cssSafe(cfg.BannerTextColor), cssSafe(cfg.BannerBgColor), cssSafe(cfg.BannerTextColor))
	// Script to handle SSO logout: when AnythingLLM's frontend navigates to /sso/simple
	// without a token (after clicking Sign out), redirect to proxy logout to log out
	// from both the proxy and Keycloak.
	ssoScript := `<script>
(function(){
  var checking = false;
  var check = function() {
    if (checking) return;
    if (window.location.pathname === '/sso/simple' && !window.location.search.includes('token=')) {
      checking = true;
      window.location.href = '/logout';
    }
  };
  check();
  // Hook pushState and replaceState for SPA navigation
  var origPush = history.pushState;
  var origReplace = history.replaceState;
  history.pushState = function() { origPush.apply(this, arguments); setTimeout(check, 50); };
  history.replaceState = function() { origReplace.apply(this, arguments); setTimeout(check, 50); };
  window.addEventListener('popstate', function() { setTimeout(check, 50); });
  // Fallback: periodic check for URL changes (React Router workaround)
  var lastPath = window.location.pathname + window.location.search;
  setInterval(function() {
    var curPath = window.location.pathname + window.location.search;
    if (curPath !== lastPath) { lastPath = curPath; check(); }
  }, 200);
})();
</script>`
	// Use string concatenation to avoid any fmt.Sprintf issues with % in style
	banners := style + ssoScript + `<div id="proxy-banner-top">` + html.EscapeString(cfg.BannerTopText) + `</div><div id="proxy-banner-bottom">` + html.EscapeString(cfg.BannerBottomText) + `</div>`

	lower := strings.ToLower(htmlBody)
	if idx := strings.Index(lower, "<body"); idx != -1 {
		gt := strings.Index(lower[idx:], ">")
		if gt != -1 {
			insertAt := idx + gt + 1
			return htmlBody[:insertAt] + banners + htmlBody[insertAt:]
		}
	}
	return banners + htmlBody
}

func cssSafe(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "#f6f000"
	}
	return val
}

func stringFromSession(sess *sessions.Session, key string) string {
	if sess == nil || key == "" {
		return ""
	}
	raw, ok := sess.Values[key]
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func isSessionValid(sess *sessions.Session) bool {
	if sess == nil {
		return false
	}
	rawExp, ok := sess.Values["expiry"]
	if !ok {
		return false
	}
	var expiry time.Time
	switch v := rawExp.(type) {
	case int64:
		expiry = time.Unix(v, 0)
	case int:
		expiry = time.Unix(int64(v), 0)
	case float64:
		expiry = time.Unix(int64(v), 0)
	default:
		return false
	}
	return expiry.After(time.Now().Add(-5 * time.Minute))
}

func oauth2AccessTypeOffline() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("access_type", "offline")
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type tokenCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newTokenCache() *tokenCache {
	return &tokenCache{m: make(map[string]string)}
}

func (c *tokenCache) Get(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	val, ok := c.m[key]
	return val, ok
}

func (c *tokenCache) Set(key, val string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if val == "" {
		delete(c.m, key)
		return
	}
	c.m[key] = val
}

func (c *tokenCache) Delete(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func storeIDToken(sess *sessions.Session, cache *tokenCache, raw string) {
	if sess == nil || cache == nil || raw == "" {
		return
	}
	if key, _ := sess.Values["id_token_key"].(string); key != "" {
		cache.Delete(key)
	}
	key := randomString(24)
	sess.Values["id_token_key"] = key
	cache.Set(key, raw)
}

func getIDToken(sess *sessions.Session, cache *tokenCache) string {
	if sess == nil || cache == nil {
		return ""
	}
	key, _ := sess.Values["id_token_key"].(string)
	val, _ := cache.Get(key)
	return val
}

func clearIDTokenCache(sess *sessions.Session, cache *tokenCache) {
	if sess == nil || cache == nil {
		return
	}
	key, _ := sess.Values["id_token_key"].(string)
	if key != "" {
		cache.Delete(key)
	}
	delete(sess.Values, "id_token_key")
}

func sanitizeRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "/sso/") || strings.HasPrefix(lower, "/auth/") ||
		strings.HasPrefix(lower, "/login") || strings.HasPrefix(lower, "/agreement") {
		return ""
	}
	return raw
}

// isLoginRedirect detects AnythingLLM redirects to its own login page.
func isLoginRedirect(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	lower := strings.ToLower(loc)
	return strings.Contains(lower, "/login")
}

// expireProxyCookie adds a Set-Cookie header to drop the proxy session cookie.
func expireProxyCookie(resp *http.Response) {
	if resp == nil {
		return
	}
	c := (&http.Cookie{
		Name:     "anythingllm_proxy",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}).String()
	resp.Header.Add("Set-Cookie", c)
}

// keycloakLogoutURL builds the RP-initiated logout URL for Keycloak.
func keycloakLogoutURL(cfg config.Config) string {
	base := strings.TrimSuffix(cfg.KeycloakExternalURL, "/")
	redirect := cfg.KeycloakRedirectURL
	if redirect == "" {
		redirect = "http://localhost:" + cfg.Port + "/"
	}
	return fmt.Sprintf("%s/protocol/openid-connect/logout?client_id=%s&redirect_uri=%s",
		base, url.QueryEscape(cfg.KeycloakClientID), url.QueryEscape(redirect))
}

func keycloakLogoutURLWithHint(cfg config.Config, idToken string) string {
	base := strings.TrimSuffix(cfg.KeycloakExternalURL, "/")
	redirect := cfg.KeycloakRedirectURL
	if redirect == "" {
		redirect = "http://localhost:" + cfg.Port + "/"
	}
	query := fmt.Sprintf("client_id=%s&redirect_uri=%s",
		url.QueryEscape(cfg.KeycloakClientID), url.QueryEscape(redirect))
	if idToken != "" {
		query += "&id_token_hint=" + url.QueryEscape(idToken)
	}
	return fmt.Sprintf("%s/protocol/openid-connect/logout?%s", base, query)
}

func decodeJWTClaims(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return "invalid jwt"
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "invalid base64 payload"
	}
	return string(data)
}
