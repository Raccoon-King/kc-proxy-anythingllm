package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func TestLogoutClearsSession(t *testing.T) {
	deps := newTestDeps()
	router := NewRouter(deps)

	// Seed session
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "anythingllm_proxy" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("session cookie missing")
	}

	// Logout
	lr := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodGet, "/logout", nil)
	lreq.AddCookie(cookie)
	router.ServeHTTP(lr, lreq)
	if lr.Code != http.StatusFound {
		t.Fatalf("expected redirect on logout")
	}
}

func TestProtectedRouteWithValidSessionPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	deps := newTestDeps()
	deps.Cfg.AnythingLLMBaseURL = upstream.URL
	router := NewRouter(deps)

	// Create session with future expiry
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	sess.Values["agreement_accepted"] = true
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)

	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected proxy to upstream, got %d", rr.Code)
	}
}
