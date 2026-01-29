package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	DefaultReadTimeout  = 15 * time.Second
	DefaultWriteTimeout = 15 * time.Second
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
}

// NewRouter builds the HTTP handler with all routes wired.
// Flow: Agreement (pre-auth) → Keycloak Auth → App
func NewRouter(d Dependencies) http.Handler {
	proxy := newReverseProxy(d.Cfg)
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
		sess, _ := d.Sessions.Get(r)
		if accepted, _ := sess.Values["agreement_accepted"].(bool); accepted {
			// Already accepted, proceed to login or app
			if isSessionValid(sess) {
				http.Redirect(w, r, "/", http.StatusFound)
			} else {
				redirect := r.URL.Query().Get("redirect")
				if redirect == "" {
					redirect = "/"
				}
				http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect), http.StatusFound)
			}
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
		sess, _ := d.Sessions.Get(r)
		sess.Values["agreement_accepted"] = true
		_ = d.Sessions.Save(r, w, sess)
		secLog("agreement accepted")

		// Redirect to login to start auth flow
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/"
		}
		dbgLog("agreement accepted, redirecting to login with redirect=%s", redirect)
		http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect), http.StatusFound)
	})

	// Login - requires agreement first, then initiates Keycloak auth
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)

		// Check agreement first
		if accepted, _ := sess.Values["agreement_accepted"].(bool); !accepted {
			redirect := r.URL.Query().Get("redirect")
			if redirect == "" {
				redirect = "/"
			}
			dbgLog("login: agreement not accepted, redirecting to agreement")
			http.Redirect(w, r, "/agreement?redirect="+url.QueryEscape(redirect), http.StatusFound)
			return
		}

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
		dbgLog("login: starting oauth flow, redirect=%s state=%s", r.URL.Query().Get("redirect"), state)

		sess.Values["oauth_state"] = state
		sess.Values["redirect_after"] = r.URL.Query().Get("redirect")
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
			http.Error(w, "state mismatch", http.StatusBadRequest)
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

		_, claims, err := d.OIDC.VerifyIDToken(r.Context(), rawIDToken)
		if err != nil {
			secLog("invalid id token: %v", err)
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		dbgLog("kc id_token claims=%s", decodeJWTClaims(rawIDToken))

		// Store tokens in session
		sess.Values["id_token"] = rawIDToken
		sess.Values["access_token"] = token.AccessToken
		sess.Values["refresh_token"] = token.RefreshToken
		sess.Values["expiry"] = token.Expiry.Unix()
		sess.Values["email"] = claims.Email
		sess.Values["name"] = pickName(claims)

		// Determine login ID
		loginID := claims.Email
		if claims.PreferredUsername != "" {
			loginID = claims.PreferredUsername
		}
		if loginID == "" && claims.Subject != "" {
			loginID = claims.Subject + "@oidc.local"
		}

		// Sync user with AnythingLLM
		userID, err := d.LLM.EnsureUser(r.Context(), loginID, pickName(claims), d.Cfg.DefaultRole, d.Cfg.AutoCreateUsers)
		if err != nil {
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
			redirectPath = redirectPath + "&redirect_to=" + url.QueryEscape(after)
		}

		dbgLog("callback complete, redirecting to %s", redirectPath)
		http.Redirect(w, r, redirectPath, http.StatusFound)
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = d.Sessions.Clear(r, w)
		secLog("logout local session cleared")
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Main catch-all route - requires agreement + auth
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)

		// Skip auth for static assets to prevent parallel auth flows
		if strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2") {
			proxy.ServeHTTP(w, r)
			return
		}

		// Allow AnythingLLM's SSO endpoints through - they handle their own auth
		if strings.HasPrefix(path, "/sso/") || strings.HasPrefix(path, "/api/") {
			dbgLog("allowing through without proxy auth: %s", path)
			proxy.ServeHTTP(w, r)
			return
		}

		sess, _ := d.Sessions.Get(r)

		// Check agreement first (before auth)
		if accepted, _ := sess.Values["agreement_accepted"].(bool); !accepted {
			dbgLog("main: agreement not accepted, redirecting to agreement")
			http.Redirect(w, r, "/agreement?redirect="+url.QueryEscape(r.URL.String()), http.StatusFound)
			return
		}

		// Check authentication
		if !isSessionValid(sess) {
			dbgLog("main: not authenticated, redirecting to login")
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.String()), http.StatusFound)
			return
		}

		// Handle logout paths
		if strings.Contains(strings.ToLower(r.URL.Path), "logout") {
			_ = d.Sessions.Clear(r, w)
			secLog("downstream logout path detected; local session cleared path=%s", r.URL.Path)
		}

		dbgLog("proxying %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})

	return logging(mux)
}

// --- helpers ---

func newReverseProxy(cfg config.Config) *httputil.ReverseProxy {
	targetURL, _ := url.Parse(cfg.AnythingLLMBaseURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Host = req.Header.Get("X-Forwarded-Host")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp == nil || resp.Body == nil {
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
	proxy.FlushInterval = 100 * time.Millisecond
	return proxy
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		_ = time.Since(start)
	})
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

func agreementHTML(inner string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Agreement</title>
</head>
<body>
%s
</body>
</html>`, inner)
}

func injectBanners(htmlBody string, cfg config.Config) string {
	if strings.Contains(htmlBody, "proxy-banner-top") {
		return htmlBody
	}
	style := fmt.Sprintf(`<style>
:root { --proxy-banner-height: 24px; }
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
  font-family: Arial, sans-serif;
  z-index: 2147483000;
}
#proxy-banner-top { top: 0; }
#proxy-banner-bottom { bottom: 0; }
body { padding-top: var(--proxy-banner-height); padding-bottom: var(--proxy-banner-height); }
.proxy-agreement-modal {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0,0,0,0.45);
  z-index: 2147483001;
}
.proxy-agreement-card {
  background: #fff;
  padding: 24px;
  max-width: 520px;
  width: calc(100%% - 32px);
  border-radius: 8px;
  box-shadow: 0 10px 40px rgba(0,0,0,0.25);
  font-family: Arial, sans-serif;
}
.proxy-agreement-card h1 { margin: 0 0 12px; font-size: 20px; }
.proxy-agreement-card p { margin: 0 0 16px; font-size: 14px; line-height: 1.4; }
.proxy-agreement-card button {
  background: %s;
  color: %s;
  border: 0;
  padding: 8px 16px;
  font-weight: 700;
  cursor: pointer;
}
</style>`, cssSafe(cfg.BannerBgColor), cssSafe(cfg.BannerTextColor), cssSafe(cfg.BannerBgColor), cssSafe(cfg.BannerTextColor))
	banners := fmt.Sprintf(`%s<div id="proxy-banner-top">%s</div><div id="proxy-banner-bottom">%s</div>`,
		style, html.EscapeString(cfg.BannerTopText), html.EscapeString(cfg.BannerBottomText))

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
