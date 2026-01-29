package config

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"strings"
)

// Config holds runtime configuration loaded from environment.
type Config struct {
	Port                 string
	AnythingLLMBaseURL   string
	AnythingLLMAPIKey    string
	KeycloakIssuerURL    string
	KeycloakExternalURL  string // External URL for browser redirects (defaults to KeycloakIssuerURL)
	KeycloakClientID     string
	KeycloakClientSecret string
	KeycloakRedirectURL  string
	SessionSecret        []byte
	SessionSecure        bool
	AutoCreateUsers      bool
	DefaultRole          string
	CallbackPath         string
	SkipListen           bool
	BannerTopText        string
	BannerBottomText     string
	BannerBgColor        string
	BannerTextColor      string
	AgreementTitle       string
	AgreementBody        string
	AgreementButtonText  string
	KeycloakCAPath       string
	KeycloakInsecureSkip bool
	DebugLogging         bool
	SecurityLogging      bool
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required env %s", key)
	}
	return v
}

// Load reads environment variables into Config with defaults where possible.
func Load() Config {
	sessionSecret := mustEnv("SESSION_SECRET")
	issuerURL := mustEnv("KEYCLOAK_ISSUER_URL")
	cfg := Config{
		Port:                 getenv("PORT", "8080"),
		AnythingLLMBaseURL:   getenv("ANYLLM_URL", "http://anythingllm:3001"),
		AnythingLLMAPIKey:    mustEnv("ANYLLM_API_KEY"),
		KeycloakIssuerURL:    issuerURL,
		KeycloakExternalURL:  getenv("KEYCLOAK_EXTERNAL_URL", issuerURL), // defaults to internal URL
		KeycloakClientID:     mustEnv("KEYCLOAK_CLIENT_ID"),
		KeycloakClientSecret: mustEnv("KEYCLOAK_CLIENT_SECRET"),
		KeycloakRedirectURL:  getenv("KEYCLOAK_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		SessionSecret:        []byte(sessionSecret),
		SessionSecure:        getenv("SESSION_SECURE", "false") == "true",
		AutoCreateUsers:      getenv("ANYLLM_AUTO_CREATE", "true") != "false",
		DefaultRole:          getenv("ANYLLM_DEFAULT_ROLE", "user"),
		CallbackPath:         getenv("CALLBACK_PATH", "/auth/callback"),
		SkipListen:           getenv("SKIP_LISTEN", "false") == "true",
		BannerTopText:        getenv("BANNER_TOP_TEXT", "SITE UNDER TEST"),
		BannerBottomText:     getenv("BANNER_BOTTOM_TEXT", "SITE UNDER TEST"),
		BannerBgColor:        getenv("BANNER_BG_COLOR", "#f6f000"),
		BannerTextColor:      getenv("BANNER_TEXT_COLOR", "#000000"),
		AgreementTitle:       getenv("AGREEMENT_TITLE", "User Agreement"),
		AgreementBody:        getenv("AGREEMENT_BODY", "Please acknowledge and accept this agreement to continue."),
		AgreementButtonText:  getenv("AGREEMENT_BUTTON_TEXT", "OK"),
		KeycloakCAPath:       getenv("KEYCLOAK_CA_PATH", ""),
		KeycloakInsecureSkip: getenv("KEYCLOAK_INSECURE_SKIP_VERIFY", "false") == "true",
		DebugLogging:         getenv("DEBUG_LOGGING", "false") == "true",
		SecurityLogging:      getenv("SECURITY_LOGGING", "true") != "false",
	}

	return cfg
}

// HTTPClient builds an http.Client honoring Keycloak TLS settings.
func (c Config) HTTPClient() *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.KeycloakInsecureSkip, //nolint:gosec
	}
	if c.KeycloakCAPath != "" {
		if pem, err := os.ReadFile(c.KeycloakCAPath); err == nil {
			cp := x509.NewCertPool()
			if cp.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = cp
			}
		}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}
