package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestNewAuthenticatedClientAddsBearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer acc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewAuthenticatedClient(context.Background(), &oauth2.Token{AccessToken: "acc"})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestNewOIDCInvalidIssuer(t *testing.T) {
	if _, err := NewOIDC(context.Background(), "http://invalid.invalid", "id", "secret", "http://redirect", nil); err == nil {
		t.Fatalf("expected error for invalid issuer")
	}
}
