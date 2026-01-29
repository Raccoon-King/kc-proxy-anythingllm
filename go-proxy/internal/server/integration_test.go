package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"

	"golang.org/x/oauth2"
)

func TestAccessRequestForMissingUser(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.AutoCreateUsers = false
	deps.OIDC.(*fakeOIDC).token = (&oauth2.Token{
		AccessToken: "acc",
		Expiry:      time.Now().Add(time.Hour),
	}).WithExtra(map[string]interface{}{"id_token": "id123"})
	deps.OIDC.(*fakeOIDC).verifyClaims = &auth.TokenClaims{
		Email:             "nonuser@user.mail",
		Name:              "non user",
		PreferredUsername: "nonuser",
		Subject:           "sub-123",
	}
	deps.LLM.(*fakeLLM).ensureErr = anythingllm.ErrUserNotFound

	router := NewRouter(deps)

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, loginReq, cookie)+"&code=abc", nil)
	cbReq.AddCookie(cookie)
	cbRR := httptest.NewRecorder()
	router.ServeHTTP(cbRR, cbReq)
	cbCookie := cookie
	for _, c := range cbRR.Result().Cookies() {
		if c.Name == "anythingllm_proxy" {
			cbCookie = c
		}
	}

	if cbRR.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", cbRR.Code)
	}
	if loc := cbRR.Header().Get("Location"); loc != "/access-request" {
		t.Fatalf("expected access-request redirect, got %s", loc)
	}

	arReq := httptest.NewRequest(http.MethodGet, "/access-request", nil)
	arReq.AddCookie(cbCookie)
	arRR := httptest.NewRecorder()
	router.ServeHTTP(arRR, arReq)

	if arRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", arRR.Code)
	}
	body := arRR.Body.String()
	assertContains(t, body, "Access required")
	assertContains(t, body, "Paste this in an email")
	assertContains(t, body, "nonuser@user.mail")
	assertContains(t, body, "nonuser")
	assertContains(t, body, "Keycloak Subject: sub-123")
}

func TestSSOMissingTokenRedirectsToKeycloakLogout(t *testing.T) {
	deps := newTestDeps()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sso/simple", nil)

	NewRouter(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/protocol/openid-connect/logout") {
		t.Fatalf("expected keycloak logout redirect, got %s", loc)
	}
}

func assertContains(t *testing.T, body, needle string) {
	t.Helper()
	if !strings.Contains(body, needle) {
		t.Fatalf("expected body to contain %q", needle)
	}
}
