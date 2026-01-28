package anythingllm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnsureUserFindsExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[{"id":"1","email":"user@example.com"}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	id, err := c.EnsureUser(context.Background(), "user@example.com", "", "", true)
	if err != nil || id != "1" {
		t.Fatalf("expected existing user, got %s err %v", id, err)
	}
}

func TestEnsureUserCreatesWhenMissing(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"users":[]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"2","email":"new@example.com"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	id, err := c.EnsureUser(context.Background(), "new@example.com", "", "", true)
	if err != nil || id != "2" {
		t.Fatalf("expected created user id 2, got %s err %v", id, err)
	}
	if calls < 2 {
		t.Fatalf("expected at least two calls, got %d", calls)
	}
}

func TestFindUserFallbackQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "email") {
			http.Error(w, "fail", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[{"id":"42","email":"user@example.com"}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	id, err := c.EnsureUser(context.Background(), "user@example.com", "", "", true)
	if err != nil || id != "42" {
		t.Fatalf("expected fallback user id 42, got %s err %v", id, err)
	}
}

func TestEnsureUserConflictRetry(t *testing.T) {
	stage := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			if stage == 0 {
				stage++
				w.Write([]byte(`{"users":[]}`))
				return
			}
			w.Write([]byte(`{"users":[{"id":"88","email":"conflict@example.com"}]}`))
			return
		}
		http.Error(w, "conflict", http.StatusConflict)
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	id, err := c.EnsureUser(context.Background(), "conflict@example.com", "", "", true)
	if err != nil || id != "88" {
		t.Fatalf("expected resolved conflict id 88, got %s err %v", id, err)
	}
}

func TestIssueAuthToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token":"abc","loginPath":"/login?token=abc"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	resp, err := c.IssueAuthToken(context.Background(), "1")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if resp.Token != "abc" {
		t.Fatalf("token mismatch")
	}
}

func TestIssueAuthTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	if _, err := c.IssueAuthToken(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty userID")
	}
	if _, err := c.IssueAuthToken(context.Background(), "1"); err == nil {
		t.Fatalf("expected error for bad response")
	}
}

func TestEnsureUserNoCreate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	if _, err := c.EnsureUser(context.Background(), "none@example.com", "", "", false); err == nil {
		t.Fatalf("expected error when auto-create disabled")
	}
}

func TestEnsureUserMissingEmail(t *testing.T) {
	c := New("http://example.com", "key")
	if _, err := c.EnsureUser(context.Background(), "", "", "", true); err == nil {
		t.Fatalf("expected error for missing email")
	}
}

func TestFindUserNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "key")
	if _, err := c.EnsureUser(context.Background(), "nouser@example.com", "", "", true); err == nil {
		t.Fatalf("expected not found error")
	}
}

func TestEnsureUserCreateFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"users":[]}`))
			return
		}
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	if _, err := c.EnsureUser(context.Background(), "error@example.com", "", "", true); err == nil {
		t.Fatalf("expected creation failure error")
	}
}

func TestEnsureUserCreateBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"users":[]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	if _, err := c.EnsureUser(context.Background(), "badjson@example.com", "", "", true); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestIssueAuthTokenBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	if _, err := c.IssueAuthToken(context.Background(), "1"); err == nil {
		t.Fatalf("expected decode error")
	}
}
func TestIssueAuthTokenBadURL(t *testing.T) {
	c := New("://bad", "key")
	if _, err := c.IssueAuthToken(context.Background(), "1"); err == nil {
		t.Fatalf("expected error for bad url")
	}
}
