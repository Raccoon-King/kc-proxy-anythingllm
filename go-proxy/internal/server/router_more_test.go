package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func TestCallbackMissingIDToken(t *testing.T) {
	deps := newTestDeps()
	// force OIDC token without id_token
	deps.OIDC.(*fakeOIDC).token = &oauth2.Token{AccessToken: "acc", Expiry: time.Now().Add(time.Hour)}

	router := NewRouter(deps)
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookie := loginRR.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, httptest.NewRequest(http.MethodGet, "/", nil), cookie), nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestCallbackEnsureUserFailure(t *testing.T) {
	deps := newTestDeps()
	deps.LLM.(*fakeLLM).ensureErr = errors.New("boom")
	router := NewRouter(deps)

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, loginReq, cookie)+"&code=abc", nil)
	cbReq.AddCookie(cookie)
	router.ServeHTTP(rr, cbReq)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
}

func TestCallbackIssueTokenFailure(t *testing.T) {
	deps := newTestDeps()
	deps.LLM.(*fakeLLM).tokenErr = errors.New("nope")
	router := NewRouter(deps)

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, loginReq, cookie)+"&code=abc", nil)
	cbReq.AddCookie(cookie)
	router.ServeHTTP(rr, cbReq)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on token failure, got %d", rr.Code)
	}
}

func TestCallbackRedirectAfterAppended(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	// seed session with redirect_after
	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/login?redirect=%2Fdocs", nil)
	router.ServeHTTP(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, loginReq, cookie)+"&code=abc", nil)
	cbReq.AddCookie(cookie)
	router.ServeHTTP(rr, cbReq)

	if loc := rr.Header().Get("Location"); loc != "/agreement" {
		t.Fatalf("expected agreement redirect, got %s", loc)
	}

	ar := httptest.NewRecorder()
	acceptReq := httptest.NewRequest(http.MethodPost, "/agreement/accept", nil)
	// use updated session cookie from callback response
	var acceptCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "anythingllm_proxy" {
			acceptCookie = c
		}
	}
	if acceptCookie == nil {
		t.Fatalf("missing callback session cookie")
	}
	acceptReq.AddCookie(acceptCookie)
	router.ServeHTTP(ar, acceptReq)
	if loc := ar.Header().Get("Location"); !strings.Contains(loc, "redirect_to=%2Fdocs") {
		t.Fatalf("expected redirect_to param, got %s", loc)
	}
}
func TestPickNamePrefersFields(t *testing.T) {
	if pickName(&auth.TokenClaims{Name: "Full", PreferredUsername: "user", Email: "a"}) != "Full" {
		t.Fatalf("expected name")
	}
	if pickName(&auth.TokenClaims{Name: "", PreferredUsername: "user", Email: "a"}) != "user" {
		t.Fatalf("expected preferred username")
	}
	if pickName(&auth.TokenClaims{Name: "", PreferredUsername: "", Email: "a"}) != "a" {
		t.Fatalf("expected email fallback")
	}
	if pickName(nil) != "" {
		t.Fatalf("expected empty for nil claims")
	}
}

func TestIsSessionValidTypes(t *testing.T) {
	store := sessions.NewCookieStore([]byte("secret"))
	sess, _ := store.Get(httptest.NewRequest("GET", "/", nil), "anythingllm_proxy")
	sess.Values["expiry"] = float64(time.Now().Add(time.Hour).Unix())
	if !isSessionValid(sess) {
		t.Fatalf("expected float expiry valid")
	}
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	if !isSessionValid(sess) {
		t.Fatalf("expected int64 expiry valid")
	}
	sess.Values["expiry"] = int(time.Now().Add(time.Hour).Unix())
	if !isSessionValid(sess) {
		t.Fatalf("expected int expiry valid")
	}
	sess.Values["expiry"] = "bad"
	if isSessionValid(sess) {
		t.Fatalf("expected invalid for wrong type")
	}
}

func TestProtectedRouteRedirectsToAgreement(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)

	if rr.Header().Get("Location") != "/agreement" {
		t.Fatalf("expected agreement redirect")
	}
}

func TestAgreementPageShowsBannerAndText(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.BannerTopText = "TOP"
	deps.Cfg.BannerBottomText = "BOTTOM"
	deps.Cfg.AgreementTitle = "Title"
	deps.Cfg.AgreementBody = "Body"
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)
	body := rr.Body.String()
	if !strings.Contains(body, "TOP") || !strings.Contains(body, "BOTTOM") {
		t.Fatalf("expected banner text")
	}
	if !strings.Contains(body, "Title") || !strings.Contains(body, "Body") {
		t.Fatalf("expected agreement text")
	}
}

func TestInjectBannersAddsMarkup(t *testing.T) {
	cfg := config.Config{
		BannerTopText:    "A",
		BannerBottomText: "B",
		BannerBgColor:    "#fff",
		BannerTextColor:  "#000",
	}
	html := "<html><body><div>Hi</div></body></html>"
	out := injectBanners(html, cfg)
	if !strings.Contains(out, "proxy-banner-top") || !strings.Contains(out, "proxy-banner-bottom") {
		t.Fatalf("missing banner markup")
	}
	if !strings.Contains(out, "A") || !strings.Contains(out, "B") {
		t.Fatalf("missing banner text")
	}
}

func TestAgreementNoSessionRedirectsToLogin(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	router.ServeHTTP(rr, req)

	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?redirect=") {
		t.Fatalf("expected login redirect")
	}
}

func TestAgreementAcceptedRedirectsHome(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	sess.Values["agreement_accepted"] = true
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("expected home redirect")
	}
}

func TestAgreementAcceptNoSessionRedirectsToLogin(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agreement/accept", nil)
	router.ServeHTTP(rr, req)
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?redirect=") {
		t.Fatalf("expected login redirect")
	}
}

func TestAgreementAcceptDefaultNext(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodPost, "/agreement/accept", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/agreement/accept", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("expected default redirect /")
	}
}

func TestInjectBannersNoBodyTag(t *testing.T) {
	cfg := config.Config{BannerTopText: "T", BannerBottomText: "B", BannerBgColor: "#fff", BannerTextColor: "#000"}
	out := injectBanners("<div>Hi</div>", cfg)
	if !strings.HasPrefix(out, "<style>") {
		t.Fatalf("expected style prefix when no body tag")
	}
}

func TestInjectBannersIdempotent(t *testing.T) {
	cfg := config.Config{BannerTopText: "T", BannerBottomText: "B", BannerBgColor: "#fff", BannerTextColor: "#000"}
	first := injectBanners("<html><body>Hi</body></html>", cfg)
	second := injectBanners(first, cfg)
	if strings.Count(second, "proxy-banner-top") != strings.Count(first, "proxy-banner-top") {
		t.Fatalf("expected banner count unchanged")
	}
}

func TestCssSafeDefault(t *testing.T) {
	if cssSafe("") == "" {
		t.Fatalf("expected default color")
	}
}

func TestModifyResponseInjectsBanner(t *testing.T) {
	cfg := config.Config{
		AnythingLLMBaseURL: "http://example.com",
		BannerTopText:      "A",
		BannerBottomText:   "B",
		BannerBgColor:      "#fff",
		BannerTextColor:    "#000",
	}
	proxy := newReverseProxy(cfg)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader("<html><body>Hi</body></html>")),
	}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy-banner-top") {
		t.Fatalf("expected injected banner")
	}
}

func TestModifyResponseSkipsNonHTML(t *testing.T) {
	cfg := config.Config{AnythingLLMBaseURL: "http://example.com"}
	proxy := newReverseProxy(cfg)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body mutation")
	}
}
