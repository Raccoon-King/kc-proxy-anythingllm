package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"
	"golang.org/x/oauth2"
)

func baseTestConfig() config.Config {
	return config.Config{
		Port:                 "8080",
		AnythingLLMBaseURL:   "http://anythingllm:3001",
		AnythingLLMAPIKey:    "key",
		KeycloakIssuerURL:    "https://issuer",
		KeycloakClientID:     "client",
		KeycloakClientSecret: "secret",
		SessionSecret:        []byte("abc"),
		CallbackPath:         "/auth/callback",
		SessionSameSite:      "lax",
		SessionMaxAgeDays:    7,
		SessionHTTPOnly:      true,
		ReadTimeout:          5 * time.Second,
		WriteTimeout:         5 * time.Second,
		ReadHeaderTimeout:    2 * time.Second,
		IdleTimeout:          10 * time.Second,
		ShutdownTimeout:      2 * time.Second,
		MaxHeaderBytes:       1 << 20,
	}
}

func TestMainExitsWhenSkipListen(t *testing.T) {
	os.Setenv("SESSION_SECRET", "abc")
	os.Setenv("ANYLLM_API_KEY", "key")
	os.Setenv("KEYCLOAK_ISSUER_URL", "https://issuer")
	os.Setenv("KEYCLOAK_CLIENT_ID", "client")
	os.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")
	os.Setenv("SKIP_LISTEN", "true")
	defer os.Clearenv()

	// Should return without panic or hang
	main()
}

func TestMainRunsWithStubServe(t *testing.T) {
	cfg := baseTestConfig()

	origNewOIDC := newOIDC
	origServe := serve
	defer func() {
		newOIDC = origNewOIDC
		serve = origServe
	}()

	newOIDC = func(ctx context.Context, issuer, clientID, secret, redirect string, _ *http.Client) (*auth.OIDC, error) {
		return &auth.OIDC{
			OAuth2: &oauth2.Config{},
		}, nil
	}
	serve = func(_ *http.Server) error { return http.ErrServerClosed }

	if err := run(context.Background(), cfg); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunReturnsErrorOnOIDCInit(t *testing.T) {
	cfg := baseTestConfig()
	orig := newOIDC
	defer func() { newOIDC = orig }()
	newOIDC = func(ctx context.Context, issuer, clientID, secret, redirect string, _ *http.Client) (*auth.OIDC, error) {
		return nil, errors.New("fail")
	}
	if err := run(context.Background(), cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunServeError(t *testing.T) {
	cfg := baseTestConfig()
	origNewOIDC := newOIDC
	origServe := serve
	defer func() {
		newOIDC = origNewOIDC
		serve = origServe
	}()
	newOIDC = func(ctx context.Context, issuer, clientID, secret, redirect string, _ *http.Client) (*auth.OIDC, error) {
		return &auth.OIDC{OAuth2: &oauth2.Config{}}, nil
	}
	serve = func(_ *http.Server) error { return errors.New("boom") }

	if err := run(context.Background(), cfg); err == nil {
		t.Fatalf("expected serve error")
	}
}
func TestRunReturnsServeError(t *testing.T) {
	cfg := baseTestConfig()
	origNewOIDC := newOIDC
	origServe := serve
	defer func() {
		newOIDC = origNewOIDC
		serve = origServe
	}()
	newOIDC = func(ctx context.Context, issuer, clientID, secret, redirect string, _ *http.Client) (*auth.OIDC, error) {
		return &auth.OIDC{OAuth2: &oauth2.Config{}}, nil
	}
	serve = func(_ *http.Server) error { return errors.New("boom") }

	if err := run(context.Background(), cfg); err == nil {
		t.Fatalf("expected serve error")
	}
}
func TestMainTriggersFatalOnRunError(t *testing.T) {
	os.Setenv("SESSION_SECRET", "abc")
	os.Setenv("ANYLLM_API_KEY", "key")
	os.Setenv("KEYCLOAK_ISSUER_URL", "https://issuer")
	os.Setenv("KEYCLOAK_CLIENT_ID", "client")
	os.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")
	os.Setenv("SKIP_LISTEN", "false")
	os.Setenv("CALLBACK_PATH", "/auth/callback")
	defer os.Clearenv()

	called := false
	origRun := runFn
	origFatal := fatalf
	runFn = func(ctx context.Context, cfg config.Config) error { return errors.New("boom") }
	fatalf = func(string, ...interface{}) { called = true }
	defer func() {
		runFn = origRun
		fatalf = origFatal
	}()

	main()
	if !called {
		t.Fatalf("expected fatal to be invoked")
	}
}
