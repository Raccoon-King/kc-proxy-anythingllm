package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// TestSessionTracker tests the session limiting functionality (STIG V-222387)
func TestSessionTrackerBasic(t *testing.T) {
	tracker := newSessionTracker(1)

	// Register first session
	invalidated := tracker.Register("user@example.com", "session1", "192.168.1.1")
	if len(invalidated) != 0 {
		t.Errorf("first session should not invalidate anything, got %v", invalidated)
	}

	// Verify first session is valid
	if !tracker.IsValid("user@example.com", "session1") {
		t.Error("first session should be valid")
	}

	// Register second session - should invalidate first
	invalidated = tracker.Register("user@example.com", "session2", "192.168.1.2")
	if len(invalidated) != 1 || invalidated[0] != "session1" {
		t.Errorf("expected session1 to be invalidated, got %v", invalidated)
	}

	// First session should now be invalid
	if tracker.IsValid("user@example.com", "session1") {
		t.Error("first session should be invalid after second login")
	}

	// Second session should be valid
	if !tracker.IsValid("user@example.com", "session2") {
		t.Error("second session should be valid")
	}
}

func TestSessionTrackerUnlimited(t *testing.T) {
	tracker := newSessionTracker(0) // unlimited

	// All sessions should be valid when limit is 0
	tracker.Register("user@example.com", "session1", "192.168.1.1")
	tracker.Register("user@example.com", "session2", "192.168.1.2")
	tracker.Register("user@example.com", "session3", "192.168.1.3")

	// All should be valid (no tracking when limit is 0)
	if !tracker.IsValid("user@example.com", "session1") {
		t.Error("session1 should be valid with unlimited sessions")
	}
	if !tracker.IsValid("user@example.com", "session2") {
		t.Error("session2 should be valid with unlimited sessions")
	}
}

func TestSessionTrackerRemove(t *testing.T) {
	tracker := newSessionTracker(2)

	tracker.Register("user@example.com", "session1", "192.168.1.1")
	tracker.Register("user@example.com", "session2", "192.168.1.2")

	// Remove session1
	tracker.Remove("user@example.com", "session1")

	// session1 should be invalid
	if tracker.IsValid("user@example.com", "session1") {
		t.Error("removed session should be invalid")
	}

	// session2 should still be valid
	if !tracker.IsValid("user@example.com", "session2") {
		t.Error("session2 should still be valid")
	}

	// New session should not invalidate anything since we removed one
	invalidated := tracker.Register("user@example.com", "session3", "192.168.1.3")
	if len(invalidated) != 0 {
		t.Errorf("should not invalidate when under limit, got %v", invalidated)
	}
}

func TestSessionTrackerRemoveAll(t *testing.T) {
	tracker := newSessionTracker(5)

	tracker.Register("user@example.com", "session1", "192.168.1.1")
	tracker.Register("user@example.com", "session2", "192.168.1.2")

	tracker.RemoveAll("user@example.com")

	if tracker.IsValid("user@example.com", "session1") {
		t.Error("session1 should be invalid after RemoveAll")
	}
	if tracker.IsValid("user@example.com", "session2") {
		t.Error("session2 should be invalid after RemoveAll")
	}
}

func TestSessionTrackerMultipleUsers(t *testing.T) {
	tracker := newSessionTracker(1)

	tracker.Register("user1@example.com", "session1", "192.168.1.1")
	tracker.Register("user2@example.com", "session2", "192.168.1.2")

	// Both users should have valid sessions
	if !tracker.IsValid("user1@example.com", "session1") {
		t.Error("user1's session should be valid")
	}
	if !tracker.IsValid("user2@example.com", "session2") {
		t.Error("user2's session should be valid")
	}

	// User1's new session should only affect user1
	invalidated := tracker.Register("user1@example.com", "session3", "192.168.1.3")
	if len(invalidated) != 1 || invalidated[0] != "session1" {
		t.Errorf("expected session1 invalidated, got %v", invalidated)
	}

	// User2's session should still be valid
	if !tracker.IsValid("user2@example.com", "session2") {
		t.Error("user2's session should still be valid")
	}
}

// TestIsSessionExpired tests the session expiry detection (STIG V-222445)
func TestIsSessionExpired(t *testing.T) {
	store := sessions.NewCookieStore([]byte("secret"))

	tests := []struct {
		name     string
		setup    func(*sessions.Session)
		expected bool
	}{
		{
			name:     "nil session",
			setup:    nil,
			expected: false,
		},
		{
			name: "no expiry set",
			setup: func(s *sessions.Session) {
				// no expiry
			},
			expected: false,
		},
		{
			name: "future expiry - not expired",
			setup: func(s *sessions.Session) {
				s.Values["expiry"] = time.Now().Add(time.Hour).Unix()
			},
			expected: false,
		},
		{
			name: "past expiry - expired",
			setup: func(s *sessions.Session) {
				s.Values["expiry"] = time.Now().Add(-time.Hour).Unix()
			},
			expected: true,
		},
		{
			name: "expiry as int",
			setup: func(s *sessions.Session) {
				s.Values["expiry"] = int(time.Now().Add(-time.Hour).Unix())
			},
			expected: true,
		},
		{
			name: "expiry as float64",
			setup: func(s *sessions.Session) {
				s.Values["expiry"] = float64(time.Now().Add(-time.Hour).Unix())
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sess *sessions.Session
			if tt.setup != nil {
				sess, _ = store.Get(httptest.NewRequest("GET", "/", nil), "test")
				tt.setup(sess)
			}
			result := isSessionExpired(sess)
			if result != tt.expected {
				t.Errorf("isSessionExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSessionTimeoutLogging tests that SESSION_TIMEOUT is logged (STIG V-222445)
func TestSessionTimeoutLogging(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.SecurityLogging = true
	deps.Cfg.SessionMaxPerUser = 1
	router := NewRouter(deps)

	// Create a session with expired expiry
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(-time.Hour).Unix() // expired
	sess.Values["email"] = "expired@example.com"
	sess.Values["agreement_accepted"] = true
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	// Capture log output
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	// Make request with expired session
	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)

	// Should redirect to login
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}

	// Check log contains SESSION_TIMEOUT
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "SESSION_TIMEOUT") {
		t.Errorf("expected SESSION_TIMEOUT in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "expired@example.com") {
		t.Errorf("expected user email in log, got: %s", logOutput)
	}
}

// TestLoginStoresLoginTime tests that login time is stored (STIG V-222437)
func TestLoginStoresLoginTime(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.SessionMaxPerUser = 1
	router := NewRouter(deps)

	// Start login flow
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

	// Complete callback
	state := extractState(t, deps, loginReq, sessCookie)
	cbRR := httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=abc", nil)
	cbReq.AddCookie(sessCookie)
	router.ServeHTTP(cbRR, cbReq)

	// Get updated session cookie
	for _, c := range cbRR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			sessCookie = c
		}
	}

	// Verify session contains login_time and login_ip
	sess, err := deps.Sessions.Get(func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(sessCookie)
		return r
	}())
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	loginTime, ok := sess.Values["login_time"].(int64)
	if !ok || loginTime == 0 {
		t.Errorf("login_time not stored in session, got %v", sess.Values["login_time"])
	}

	loginIP, ok := sess.Values["login_ip"].(string)
	if !ok || loginIP == "" {
		t.Errorf("login_ip not stored in session, got %v", sess.Values["login_ip"])
	}
}

// TestAgreementPageShowsLoginTime tests that agreement page displays login time (STIG V-222437)
func TestAgreementPageShowsLoginTime(t *testing.T) {
	deps := newTestDeps()
	deps.DisableAgreement = false
	deps.Cfg.SessionMaxPerUser = 1
	router := NewRouter(deps)

	// Create session with login time
	req := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	sess := sessions.NewSession(deps.Sessions.Store(), "anythingllm_proxy")
	sess.Values["expiry"] = time.Now().Add(time.Hour).Unix()
	sess.Values["email"] = "user@example.com"
	sess.Values["login_time"] = time.Now().Unix()
	sess.Values["login_ip"] = "192.168.1.100"
	sess.Values["agreement_accepted"] = false
	w := httptest.NewRecorder()
	_ = sess.Save(req, w)
	cookie := w.Result().Cookies()[0]

	// Request agreement page
	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/agreement", nil)
	r2.AddCookie(cookie)
	router.ServeHTTP(rr, r2)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Current login:") {
		t.Errorf("expected 'Current login:' in page, got: %s", body[:min(500, len(body))])
	}
	if !strings.Contains(body, "192.168.1.100") {
		t.Errorf("expected IP address in page, got: %s", body[:min(500, len(body))])
	}
}

// TestSessionRevokedOnNewLogin tests that old sessions are revoked (STIG V-222387)
func TestSessionRevokedOnNewLogin(t *testing.T) {
	deps := newTestDeps()
	deps.Cfg.SecurityLogging = true
	deps.Cfg.SessionMaxPerUser = 1
	router := NewRouter(deps)

	// First login
	login1RR := httptest.NewRecorder()
	login1Req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(login1RR, login1Req)

	var cookie1 *http.Cookie
	for _, c := range login1RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie1 = c
		}
	}

	state1 := extractState(t, deps, login1Req, cookie1)
	cb1RR := httptest.NewRecorder()
	cb1Req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state1+"&code=abc", nil)
	cb1Req.AddCookie(cookie1)
	router.ServeHTTP(cb1RR, cb1Req)

	// Get session1's cookie after callback
	for _, c := range cb1RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie1 = c
		}
	}

	// Second login (simulating different browser)
	login2RR := httptest.NewRecorder()
	login2Req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(login2RR, login2Req)

	var cookie2 *http.Cookie
	for _, c := range login2RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie2 = c
		}
	}

	// Capture log output for SESSION_REVOKED
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	state2 := extractState(t, deps, login2Req, cookie2)
	cb2RR := httptest.NewRecorder()
	cb2Req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state2+"&code=abc", nil)
	cb2Req.AddCookie(cookie2)
	router.ServeHTTP(cb2RR, cb2Req)

	// Check that SESSION_REVOKED was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "SESSION_REVOKED") {
		t.Errorf("expected SESSION_REVOKED in log, got: %s", logOutput)
	}
}

// TestOldSessionInvalidAfterNewLogin tests that old session is rejected (STIG V-222387)
func TestOldSessionInvalidAfterNewLogin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	deps := newTestDeps()
	deps.Cfg.AnythingLLMBaseURL = upstream.URL
	deps.Cfg.SecurityLogging = true
	deps.Cfg.SessionMaxPerUser = 1
	router := NewRouter(deps)

	// First login - complete flow
	login1RR := httptest.NewRecorder()
	login1Req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(login1RR, login1Req)

	var cookie1 *http.Cookie
	for _, c := range login1RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie1 = c
		}
	}

	state1 := extractState(t, deps, login1Req, cookie1)
	cb1RR := httptest.NewRecorder()
	cb1Req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state1+"&code=abc", nil)
	cb1Req.AddCookie(cookie1)
	router.ServeHTTP(cb1RR, cb1Req)

	for _, c := range cb1RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie1 = c
		}
	}

	// Accept agreement for session1
	sess1, _ := deps.Sessions.Get(func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(cookie1)
		return r
	}())
	sess1.Values["agreement_accepted"] = true
	agreeRR := httptest.NewRecorder()
	agreeReq := httptest.NewRequest("GET", "/", nil)
	agreeReq.AddCookie(cookie1)
	_ = sess1.Save(agreeReq, agreeRR)
	for _, c := range agreeRR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie1 = c
		}
	}

	// Verify session1 can access protected route
	access1RR := httptest.NewRecorder()
	access1Req := httptest.NewRequest(http.MethodGet, "/", nil)
	access1Req.AddCookie(cookie1)
	router.ServeHTTP(access1RR, access1Req)

	if access1RR.Code != http.StatusTeapot {
		t.Fatalf("session1 should be able to access protected route, got %d", access1RR.Code)
	}

	// Second login (different browser)
	login2RR := httptest.NewRecorder()
	login2Req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(login2RR, login2Req)

	var cookie2 *http.Cookie
	for _, c := range login2RR.Result().Cookies() {
		if strings.HasPrefix(c.Name, "anythingllm_proxy") {
			cookie2 = c
		}
	}

	state2 := extractState(t, deps, login2Req, cookie2)
	cb2RR := httptest.NewRecorder()
	cb2Req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state2+"&code=abc", nil)
	cb2Req.AddCookie(cookie2)
	router.ServeHTTP(cb2RR, cb2Req)

	// Capture log for SESSION_INVALID
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	// Now session1 should be invalid
	access1RR2 := httptest.NewRecorder()
	access1Req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	access1Req2.AddCookie(cookie1)
	router.ServeHTTP(access1RR2, access1Req2)

	// Should redirect to login (session invalidated)
	if access1RR2.Code != http.StatusFound {
		t.Fatalf("old session should be rejected, got %d", access1RR2.Code)
	}

	// Check SESSION_INVALID was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "SESSION_INVALID") {
		t.Errorf("expected SESSION_INVALID in log, got: %s", logOutput)
	}
}

// TestRenderAgreementPageWithLoginInfo tests the agreement page rendering
func TestRenderAgreementPageWithLoginInfo(t *testing.T) {
	cfg := newTestDeps().Cfg
	cfg.AgreementTitle = "Test Agreement"
	cfg.AgreementBody = "Please agree"
	cfg.AgreementButtonText = "Accept"

	// With login info
	loginTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC).Unix()
	page := renderAgreementPage(cfg, loginTime, "192.168.1.50")

	if !strings.Contains(page, "Current login:") {
		t.Error("expected 'Current login:' in page")
	}
	if !strings.Contains(page, "192.168.1.50") {
		t.Error("expected IP in page")
	}
	if !strings.Contains(page, "2024-01-15") {
		t.Error("expected date in page")
	}

	// Without login info
	page2 := renderAgreementPage(cfg, 0, "")
	if strings.Contains(page2, "Current login:") {
		t.Error("should not show login info when loginTime is 0")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
