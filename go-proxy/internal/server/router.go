package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"io"
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
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
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
func NewRouter(d Dependencies) http.Handler {
	proxy := newReverseProxy(d.Cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := randomString(24)
		sess, _ := d.Sessions.Get(r)
		sess.Values["oauth_state"] = state
		sess.Values["redirect_after"] = r.URL.Query().Get("redirect")
		_ = d.Sessions.Save(r, w, sess)

		url := d.OIDC.AuthCodeURL(state, oauth2AccessTypeOffline())
		http.Redirect(w, r, url, http.StatusFound)
	})

	mux.HandleFunc(d.Cfg.CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		state := r.URL.Query().Get("state")
		if sess.Values["oauth_state"] != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		token, err := d.OIDC.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, "login failed", http.StatusBadRequest)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in response", http.StatusBadRequest)
			return
		}

		_, claims, err := d.OIDC.VerifyIDToken(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}

		sess.Values["id_token"] = rawIDToken
		sess.Values["access_token"] = token.AccessToken
		sess.Values["refresh_token"] = token.RefreshToken
		sess.Values["expiry"] = token.Expiry.Unix()
		sess.Values["email"] = claims.Email
		sess.Values["name"] = pickName(claims)
		sess.Values["agreement_accepted"] = false
		_ = d.Sessions.Save(r, w, sess)

		userID, err := d.LLM.EnsureUser(r.Context(), claims.Email, pickName(claims), d.Cfg.DefaultRole, d.Cfg.AutoCreateUsers)
		if err != nil {
			http.Error(w, "failed to sync user", http.StatusBadGateway)
			return
		}

		tokenResp, err := d.LLM.IssueAuthToken(r.Context(), userID)
		if err != nil {
			http.Error(w, "failed to issue sso token", http.StatusBadGateway)
			return
		}

		redirectPath := tokenResp.LoginPath
		if !strings.HasPrefix(redirectPath, "/") {
			redirectPath = "/" + redirectPath
		}

		if after, _ := sess.Values["redirect_after"].(string); after != "" {
			redirectPath = redirectPath + "&redirect_to=" + url.QueryEscape(after)
		}

		sess.Values["agreement_next"] = redirectPath
		_ = d.Sessions.Save(r, w, sess)
		http.Redirect(w, r, "/agreement", http.StatusFound)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = d.Sessions.Clear(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/agreement", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		if !isSessionValid(sess) {
			loginURL := "/login?redirect=" + url.QueryEscape(r.URL.String())
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		if accepted, _ := sess.Values["agreement_accepted"].(bool); accepted {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderAgreementPage(d.Cfg)))
	})

	mux.HandleFunc("/agreement/accept", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		if !isSessionValid(sess) {
			loginURL := "/login?redirect=" + url.QueryEscape(r.URL.String())
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		sess.Values["agreement_accepted"] = true
		next, _ := sess.Values["agreement_next"].(string)
		delete(sess.Values, "agreement_next")
		_ = d.Sessions.Save(r, w, sess)
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := d.Sessions.Get(r)
		if !isSessionValid(sess) {
			loginURL := "/login?redirect=" + url.QueryEscape(r.URL.String())
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		if accepted, _ := sess.Values["agreement_accepted"].(bool); !accepted {
			http.Redirect(w, r, "/agreement", http.StatusFound)
			return
		}
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
		req.Host = targetURL.Host
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
		_ = time.Since(start) // placeholder for metrics
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
