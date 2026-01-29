package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type fakeOIDC struct {
	codeURL      string
	token        *oauth2.Token
	tokenErr     error
	verifyClaims *auth.TokenClaims
	verifyErr    error
}

func (f *fakeOIDC) AuthCodeURL(state string, _ ...oauth2.AuthCodeOption) string {
	return f.codeURL + "?state=" + state
}

func (f *fakeOIDC) Exchange(_ context.Context, _ string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return f.token, f.tokenErr
}

func (f *fakeOIDC) VerifyIDToken(_ context.Context, _ string) (*oidc.IDToken, *auth.TokenClaims, error) {
	return nil, f.verifyClaims, f.verifyErr
}

type fakeLLM struct {
	userID    string
	ensureErr error
	tokenResp *anythingllm.AuthTokenResponse
	tokenErr  error
}

func (f *fakeLLM) EnsureUser(_ context.Context, _, _, _ string, _ bool) (string, error) {
	return f.userID, f.ensureErr
}

func (f *fakeLLM) IssueAuthToken(_ context.Context, _ string) (*anythingllm.AuthTokenResponse, error) {
	return f.tokenResp, f.tokenErr
}

func newTestDeps() Dependencies {
	cfg := config.Config{
		Port:               "8080",
		AnythingLLMBaseURL: "http://anythingllm:3001",
		DefaultRole:        "user",
		AutoCreateUsers:    true,
		CallbackPath:       "/auth/callback",
		SessionSecret:      []byte("secret"),
	}
	return Dependencies{
		Cfg:      cfg,
		Sessions: auth.NewSessionManager(cfg.SessionSecret, false),
		OIDC: &fakeOIDC{
			codeURL: "http://keycloak/auth",
			token: (&oauth2.Token{
				AccessToken:  "acc",
				RefreshToken: "ref",
				Expiry:       time.Now().Add(time.Hour),
			}).WithExtra(map[string]interface{}{"id_token": "id123"}),
			verifyClaims: &auth.TokenClaims{Email: "user@example.com", Name: "User"},
		},
		LLM: &fakeLLM{
			userID:    "123",
			tokenResp: &anythingllm.AuthTokenResponse{Token: "tkn", LoginPath: "/login/path?token=tkn"},
		},
		DisableAgreement: true,
	}
}

func TestHealth(t *testing.T) {
	deps := newTestDeps()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	NewRouter(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestLoginRedirectsToKeycloak(t *testing.T) {
	deps := newTestDeps()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect=%2Fchat", nil)

	NewRouter(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://keycloak/auth?state=") {
		t.Fatalf("unexpected redirect %s", loc)
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatalf("expected session cookie")
	}
}

func TestCallbackHappyPath(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(loginRR, loginReq)

	var sessCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatalf("missing session cookie")
	}

	cbRR := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+extractState(t, deps, loginReq, sessCookie)+"&code=abc", nil)
	cbReq.AddCookie(sessCookie)
	router.ServeHTTP(cbRR, cbReq)

	if cbRR.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", cbRR.Code)
	}
	if loc := cbRR.Header().Get("Location"); loc != "/agreement" {
		t.Fatalf("unexpected redirect %s", loc)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=bad", nil)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect on state mismatch, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "/protocol/openid-connect/logout") {
		t.Fatalf("expected logout redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestProtectedRouteRedirectsWhenNoSession(t *testing.T) {
	deps := newTestDeps()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/chat", nil)

	NewRouter(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?redirect=") {
		t.Fatalf("unexpected redirect %s", rr.Header().Get("Location"))
	}
}

func TestIsSessionValid(t *testing.T) {
	store := sessions.NewCookieStore([]byte("secret"))
	sess, _ := store.Get(httptest.NewRequest("GET", "/", nil), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	if !isSessionValid(sess) {
		t.Fatalf("expected valid session")
	}
	sess.Values["expiry"] = time.Now().Add(-time.Hour).Unix()
	if isSessionValid(sess) {
		t.Fatalf("expected invalid session")
	}
}

func extractState(t *testing.T, deps Dependencies, req *http.Request, cookie *http.Cookie) string {
	t.Helper()
	r := req.Clone(context.Background())
	r.AddCookie(cookie)
	sess, err := deps.Sessions.Get(r)
	if err != nil {
		t.Fatal(err)
	}
	val, _ := sess.Values["oauth_state"].(string)
	if val == "" {
		t.Fatalf("state not set")
	}
	return val
}
