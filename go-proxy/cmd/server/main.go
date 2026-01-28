package main

import (
	"context"
	"log"
	"net/http"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"
	"anythingllm-proxy/internal/server"
)

var (
	newOIDC = auth.NewOIDC
	serve   = func(s *http.Server) error { return s.ListenAndServe() }
	fatalf  = log.Fatalf
	runFn   = run
)

func main() {
	ctx := context.Background()
	cfg := config.Load()

	if cfg.SkipListen {
		log.Printf("skip listen enabled; exiting (test mode)")
		return
	}

	if err := runFn(ctx, cfg); err != nil {
		fatalf("server error: %v", err)
	}
}

func run(ctx context.Context, cfg config.Config) error {
	oidcProvider, err := newOIDC(ctx, cfg.KeycloakIssuerURL, cfg.KeycloakClientID, cfg.KeycloakClientSecret, cfg.KeycloakRedirectURL, cfg.HTTPClient())
	if err != nil {
		return err
	}

	deps := server.Dependencies{
		Cfg:      cfg,
		Sessions: auth.NewSessionManager(cfg.SessionSecret, cfg.SessionSecure),
		OIDC:     auth.NewOIDCAdapter(oidcProvider),
		LLM:      anythingllm.New(cfg.AnythingLLMBaseURL, cfg.AnythingLLMAPIKey),
	}

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.NewRouter(deps),
		ReadTimeout:  server.DefaultReadTimeout,
		WriteTimeout: server.DefaultWriteTimeout,
	}

	log.Printf("Go proxy listening on %s -> %s", cfg.Port, cfg.AnythingLLMBaseURL)
	if err := serve(srv); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
