package config

import (
	"os"
	"testing"
)

func TestLoadUsesDefaultsAndEnv(t *testing.T) {
	os.Setenv("SESSION_SECRET", "abc")
	os.Setenv("ANYLLM_API_KEY", "key")
	os.Setenv("KEYCLOAK_ISSUER_URL", "https://issuer")
	os.Setenv("KEYCLOAK_CLIENT_ID", "client")
	os.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")
	os.Setenv("SKIP_LISTEN", "true")
	defer os.Clearenv()

	cfg := Load()
	if cfg.Port != "8080" || cfg.AnythingLLMBaseURL != "http://anythingllm:3001" {
		t.Fatalf("defaults not applied")
	}
	if !cfg.SkipListen {
		t.Fatalf("expected SkipListen true")
	}
	if string(cfg.SessionSecret) != "abc" {
		t.Fatalf("session secret not loaded")
	}
}
