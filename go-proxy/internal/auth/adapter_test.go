package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestAdapterAuthCodeURL(t *testing.T) {
	o := &OIDC{OAuth2: &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://auth"}}}
	a := NewOIDCAdapter(o)
	url := a.AuthCodeURL("state123")
	if url == "" {
		t.Fatalf("expected url")
	}
}

func TestAdapterExchangeAndVerifyErrors(t *testing.T) {
	// Token endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"acc","token_type":"bearer"}`))
	}))
	defer srv.Close()

	o := &OIDC{OAuth2: &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: srv.URL}}}
	a := NewOIDCAdapter(o)

	if _, err := a.Exchange(context.Background(), "code"); err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if _, _, err := a.VerifyIDToken(context.Background(), "raw"); err == nil {
		t.Fatalf("expected verify error with nil verifier")
	}
}
