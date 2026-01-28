package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type discovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
}

func TestNewOIDCAndVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := discovery{Issuer: srv.URL, AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", JWKSURI: srv.URL + "/keys"}
			json.NewEncoder(w).Encode(resp)
		case "/keys":
			pub := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.RS256), KeyID: "kid1"}
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []jose.JSONWebKey{pub}})
		case "/token":
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "kid1"))
			claims := jwt.Claims{
				Issuer:   srv.URL,
				Subject:  "sub",
				Audience: jwt.Audience{"client"},
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt: jwt.NewNumericDate(time.Now()),
			}
			raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "acc",
				"id_token":     raw,
				"token_type":   "Bearer",
				"expires_in":   "3600",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oidcClient, err := NewOIDC(context.Background(), srv.URL, "client", "secret", "http://localhost/callback", nil)
	if err != nil {
		t.Fatalf("new oidc: %v", err)
	}

	token, err := oidcClient.OAuth2.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	raw := token.Extra("id_token").(string)
	if _, _, err := oidcClient.VerifyIDToken(context.Background(), raw); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
