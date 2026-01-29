package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEndToEndLoginAgreementAndProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><main>upstream ok %s</main></body></html>", r.URL.Path)
	}))
	defer upstream.Close()

	deps := newTestDeps()
	deps.Cfg.AnythingLLMBaseURL = upstream.URL
	deps.Cfg.BannerTopText = "E2E TOP"
	deps.Cfg.BannerBottomText = "E2E BOTTOM"
	deps.Cfg.AgreementTitle = "E2E Agreement"
	deps.DisableAgreement = false

	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(srv.URL + "/login?redirect=%2Fchat")
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from login, got %d", resp.StatusCode)
	}

	serverURL, _ := url.Parse(srv.URL)
	var sessCookie *http.Cookie
	for _, c := range jar.Cookies(serverURL) {
		if c.Name == "anythingllm_proxy" {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil {
		t.Fatalf("expected session cookie after login")
	}

	stateReq := httptest.NewRequest(http.MethodGet, "http://example", nil)
	state := extractState(t, deps, stateReq, sessCookie)

	resp, err = client.Get(srv.URL + "/auth/callback?state=" + url.QueryEscape(state) + "&code=abc")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from callback, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/agreement" {
		t.Fatalf("expected agreement redirect, got %s", loc)
	}

	resp, err = client.Get(srv.URL + "/agreement")
	if err != nil {
		t.Fatalf("agreement request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from agreement, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "E2E Agreement") {
		t.Fatalf("expected agreement page content")
	}

	acceptReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/agreement/accept", nil)
	resp, err = client.Do(acceptReq)
	if err != nil {
		t.Fatalf("agreement accept failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from agreement accept, got %d", resp.StatusCode)
	}
	expectedLogin := "/login/path?token=tkn&redirectTo=%2Fchat"
	if loc := resp.Header.Get("Location"); loc != expectedLogin {
		t.Fatalf("expected redirect to %s, got %s", expectedLogin, loc)
	}

	resp, err = client.Get(srv.URL + expectedLogin)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from proxied request, got %d", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	text := string(body)
	if !strings.Contains(text, "upstream ok /login/path") {
		t.Fatalf("expected upstream content to pass through")
	}
	if !strings.Contains(text, "E2E TOP") || !strings.Contains(text, "E2E BOTTOM") {
		t.Fatalf("expected banners to be injected")
	}
}
