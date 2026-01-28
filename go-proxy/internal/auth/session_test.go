package auth

import (
	"net/http/httptest"
	"testing"
)

func TestSessionManagerLifecycle(t *testing.T) {
	mgr := NewSessionManager([]byte("secret"), false)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	sess, err := mgr.Get(r)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	sess.Values["foo"] = "bar"
	if err := mgr.Save(r, w, sess); err != nil {
		t.Fatalf("save: %v", err)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}
	sess2, _ := mgr.Get(r2)
	if sess2.Values["foo"].(string) != "bar" {
		t.Fatalf("expected value persisted")
	}

	w2 := httptest.NewRecorder()
	if err := mgr.Clear(r2, w2); err != nil {
		t.Fatalf("clear: %v", err)
	}
}
