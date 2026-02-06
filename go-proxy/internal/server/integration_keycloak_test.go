//go:build integration

package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anythingllm-proxy/internal/anythingllm"
	"anythingllm-proxy/internal/auth"
	"anythingllm-proxy/internal/config"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// KeycloakTestContainer holds the running Keycloak container and its configuration.
type KeycloakTestContainer struct {
	container testcontainers.Container
	issuerURL string
	adminURL  string
}

// setupKeycloakContainer starts a Keycloak container with the test realm.
func setupKeycloakContainer(ctx context.Context, t *testing.T) *KeycloakTestContainer {
	t.Helper()

	// Get absolute path to test realm file
	realmPath, err := filepath.Abs("testdata/test-realm.json")
	if err != nil {
		t.Fatalf("failed to get absolute path for realm file: %v", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:24.0",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
		},
		Cmd: []string{"start-dev", "--import-realm"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      realmPath,
				ContainerFilePath: "/opt/keycloak/data/import/test-realm.json",
				FileMode:          0644,
			},
		},
		WaitingFor: wait.ForHTTP("/realms/test-realm/.well-known/openid-configuration").
			WithPort("8080/tcp").
			WithStartupTimeout(120 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start keycloak container: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get keycloak port: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get keycloak host: %v", err)
	}

	authURL := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	return &KeycloakTestContainer{
		container: container,
		issuerURL: authURL + "/realms/test-realm",
		adminURL:  authURL,
	}
}

// Terminate stops the Keycloak container.
func (k *KeycloakTestContainer) Terminate(ctx context.Context) {
	if k.container != nil {
		_ = k.container.Terminate(ctx)
	}
}

// newIntegrationDeps creates Dependencies with a real OIDC client pointing to Keycloak.
func newIntegrationDeps(t *testing.T, keycloakURL, proxyCallbackURL string) Dependencies {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oidcClient, err := auth.NewOIDC(ctx,
		keycloakURL,
		"test-proxy-client",
		"test-secret-12345",
		proxyCallbackURL,
	)
	if err != nil {
		t.Fatalf("failed to create OIDC client: %v", err)
	}

	cfg := config.Config{
		Port:                 "8080",
		AnythingLLMBaseURL:   "http://mock-anythingllm:3001",
		KeycloakIssuerURL:    keycloakURL,
		DefaultRole:          "user",
		AutoCreateUsers:      true,
		CallbackPath:         "/auth/callback",
		SessionSecret:        []byte("test-session-secret-minimum-32-chars!!"),
		SessionSameSite:      "lax",
		SessionMaxAgeDays:    7,
		SessionHTTPOnly:      true,
		UpstreamDialTimeout:  5 * time.Second,
		UpstreamTLSHandshake: 5 * time.Second,
		UpstreamResponseHdr:  5 * time.Second,
		UpstreamIdleTimeout:  10 * time.Second,
		UpstreamMaxIdle:      10,
		UpstreamMaxIdleHost:  5,
	}

	return Dependencies{
		Cfg: cfg,
		Sessions: auth.NewSessionManager(cfg.SessionSecret, auth.SessionOptions{
			Secure:   false,
			SameSite: cfg.SessionSameSiteMode(),
			MaxAge:   7 * 24 * time.Hour,
			HttpOnly: true,
		}),
		OIDC: oidcClient,
		LLM: &fakeLLM{
			userID:    "integration-user-123",
			tokenResp: &anythingllm.AuthTokenResponse{Token: "integration-tkn", LoginPath: "/login/path?token=integration-tkn"},
		},
		DisableAgreement: true, // Skip agreement for simpler tests
	}
}

// TestIntegrationKeycloakHealth verifies Keycloak container starts and responds.
func TestIntegrationKeycloakHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	// Verify Keycloak is responding
	resp, err := http.Get(kc.issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("keycloak health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from keycloak, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "authorization_endpoint") {
		t.Fatalf("unexpected OIDC config response: %s", string(body))
	}
}

// TestIntegrationLoginRedirectsToRealKeycloak verifies login redirects to real Keycloak.
func TestIntegrationLoginRedirectsToRealKeycloak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	// Create a test server for the proxy
	deps := newIntegrationDeps(t, kc.issuerURL, "http://localhost:8080/auth/callback")
	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	// Update callback URL to match test server
	deps = newIntegrationDeps(t, kc.issuerURL, srv.URL+"/auth/callback")
	srv.Config.Handler = NewRouter(deps)

	// Make login request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(srv.URL + "/login?redirect=%2Fchat")
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, kc.adminURL) {
		t.Fatalf("expected redirect to keycloak, got %s", loc)
	}
	if !strings.Contains(loc, "response_type=code") {
		t.Fatalf("expected OIDC auth code flow, got %s", loc)
	}
}

// TestIntegrationNoRedirectLoop verifies no redirect loops occur.
func TestIntegrationNoRedirectLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	deps := newIntegrationDeps(t, kc.issuerURL, "http://localhost:8080/auth/callback")
	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	// Track visited URLs to detect loops
	visited := make(map[string]int)
	maxRedirects := 20

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			path := req.URL.Path
			visited[path]++
			if visited[path] > 2 {
				return fmt.Errorf("redirect loop detected: %s visited %d times", path, visited[path])
			}
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects: %d", len(via))
			}
			return nil
		},
	}

	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	// Start auth flow - this should redirect to Keycloak
	resp, err := client.Get(srv.URL + "/")
	if err != nil && !strings.Contains(err.Error(), "redirect") {
		// Redirect errors are expected since we're not completing auth
		t.Logf("expected redirect: %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Verify no path was visited more than twice
	for path, count := range visited {
		if count > 2 {
			t.Errorf("redirect loop: %s visited %d times", path, count)
		}
	}
}

// TestIntegrationHealthEndpointWithKeycloak verifies health endpoint works with real Keycloak.
func TestIntegrationHealthEndpointWithKeycloak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	deps := newIntegrationDeps(t, kc.issuerURL, "http://localhost:8080/auth/callback")
	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestIntegrationStateMismatchRedirectsToLogout tests state validation with real Keycloak.
func TestIntegrationStateMismatchRedirectsToLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	deps := newIntegrationDeps(t, kc.issuerURL, "http://localhost:8080/auth/callback")
	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try callback with invalid state
	resp, err := client.Get(srv.URL + "/auth/callback?state=invalid-state&code=fake-code")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	// Should redirect to Keycloak logout or login
	if !strings.Contains(loc, "logout") && !strings.Contains(loc, "login") && !strings.Contains(loc, "logged-out") {
		t.Fatalf("expected logout/login redirect, got %s", loc)
	}
}

// TestIntegrationDirectAccessGrant tests getting tokens via direct access (resource owner password).
func TestIntegrationDirectAccessGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	// Get token directly from Keycloak using resource owner password grant
	tokenURL := kc.issuerURL + "/protocol/openid-connect/token"

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "test-proxy-client")
	data.Set("client_secret", "test-secret-12345")
	data.Set("username", "testuser")
	data.Set("password", "testpass")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "access_token") {
		t.Fatalf("expected access_token in response: %s", string(body))
	}
	if !strings.Contains(string(body), "id_token") {
		t.Fatalf("expected id_token in response: %s", string(body))
	}
}

// TestIntegrationProtectedRouteRequiresAuth verifies protected routes redirect to login.
func TestIntegrationProtectedRouteRequiresAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	kc := setupKeycloakContainer(ctx, t)
	defer kc.Terminate(ctx)

	deps := newIntegrationDeps(t, kc.issuerURL, "http://localhost:8080/auth/callback")
	srv := httptest.NewServer(NewRouter(deps))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Access protected route without session
	resp, err := client.Get(srv.URL + "/chat")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %s", loc)
	}
}
