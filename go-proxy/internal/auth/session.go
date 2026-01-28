package auth

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

const sessionName = "anythingllm_proxy"

// SessionManager wraps gorilla sessions cookie store.
type SessionManager struct {
	store *sessions.CookieStore
}

// NewSessionManager builds a manager with secure defaults.
func NewSessionManager(secret []byte, secure bool) *SessionManager {
	store := sessions.NewCookieStore(secret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()) * 7, // one week
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	return &SessionManager{store: store}
}

// Get returns the session for the request.
func (s *SessionManager) Get(r *http.Request) (*sessions.Session, error) {
	return s.store.Get(r, sessionName)
}

// Store exposes the underlying store (used in tests).
func (s *SessionManager) Store() *sessions.CookieStore {
	return s.store
}

// Save persists the session.
func (s *SessionManager) Save(r *http.Request, w http.ResponseWriter, sess *sessions.Session) error {
	return sess.Save(r, w)
}

// Clear removes all stored values and expires the cookie.
func (s *SessionManager) Clear(r *http.Request, w http.ResponseWriter) error {
	sess, _ := s.Get(r)
	sess.Options.MaxAge = -1
	sess.Values = map[interface{}]interface{}{}
	return sess.Save(r, w)
}
