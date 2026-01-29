package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	if err := cfg.Validate(); err != nil {
		return err
	}
	oidcProvider, err := newOIDC(ctx, cfg.KeycloakIssuerURL, cfg.KeycloakClientID, cfg.KeycloakClientSecret, cfg.KeycloakRedirectURL, cfg.HTTPClient())
	if err != nil {
		return err
	}

	deps := server.Dependencies{
		Cfg: cfg,
		Sessions: auth.NewSessionManager(cfg.SessionSecret, auth.SessionOptions{
			Secure:   cfg.SessionSecure,
			SameSite: cfg.SessionSameSiteMode(),
			MaxAge:   time.Duration(cfg.SessionMaxAgeDays) * 24 * time.Hour,
			HttpOnly: cfg.SessionHTTPOnly,
		}),
		OIDC: auth.NewOIDCAdapterWithExternalURL(oidcProvider, cfg.KeycloakIssuerURL, cfg.KeycloakExternalURL),
		LLM:  anythingllm.NewWithHTTPClient(cfg.AnythingLLMBaseURL, cfg.AnythingLLMAPIKey, &http.Client{Timeout: cfg.AnythingLLMTimeout}, cfg.AnythingLLMRetryMax, cfg.AnythingLLMRetryBackoff),
	}
	if cfg.ReadinessChecks && cfg.ReadinessURL != "" {
		deps.Ready = func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ReadinessURL, nil)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: cfg.ReadinessTimeout}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 500 {
				return fmt.Errorf("readiness check failed: %s", resp.Status)
			}
			return nil
		}
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.NewRouter(deps),
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	log.Printf("Go proxy listening on %s -> %s", cfg.Port, cfg.AnythingLLMBaseURL)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(srv)
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received; shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		err := <-errCh
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}
