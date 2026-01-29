package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration loaded from environment.
type Config struct {
	Port                      string
	Environment               string
	AnythingLLMBaseURL        string
	AnythingLLMAPIKey         string
	AnythingLLMTimeout        time.Duration
	AnythingLLMRetryMax       int
	AnythingLLMRetryBackoff   time.Duration
	KeycloakIssuerURL         string
	KeycloakExternalURL       string // External URL for browser redirects (defaults to KeycloakIssuerURL)
	KeycloakClientID          string
	KeycloakClientSecret      string
	KeycloakRedirectURL       string
	SessionSecret             []byte
	SessionSecure             bool
	SessionSameSite           string
	SessionMaxAgeDays         int
	SessionHTTPOnly           bool
	AutoCreateUsers           bool
	DefaultRole               string
	CallbackPath              string
	SkipListen                bool
	ReadTimeout               time.Duration
	WriteTimeout              time.Duration
	ReadHeaderTimeout         time.Duration
	IdleTimeout               time.Duration
	MaxHeaderBytes            int
	ShutdownTimeout           time.Duration
	UpstreamDialTimeout       time.Duration
	UpstreamTLSHandshake      time.Duration
	UpstreamResponseHdr       time.Duration
	UpstreamIdleTimeout       time.Duration
	UpstreamMaxIdle           int
	UpstreamMaxIdleHost       int
	AccessLogging             bool
	MetricsEnabled            bool
	ReadinessChecks           bool
	ReadinessTimeout          time.Duration
	ReadinessURL              string
	SecurityHeaders           bool
	HeaderFrameOptions        string
	HeaderReferrerPolicy      string
	HeaderCSP                 string
	HeaderPermissions         string
	RateLimitPerMinute        int
	RateLimitBurst            int
	BannerTopText             string
	BannerBottomText          string
	BannerBgColor             string
	BannerTextColor           string
	AgreementTitle            string
	AgreementBody             string
	AgreementButtonText       string
	AccessRequestSubject      string
	AccessRequestContact      string
	AccessRequestTitle        string
	AccessRequestBody         string
	AccessRequestPrompt       string
	AccessRequestContactLabel string
	AccessRequestSubjectLabel string
	AccessRequestSignOutText  string
	LoggedOutTitle            string
	LoggedOutBody             string
	LoggedOutLinkText         string
	KeycloakCAPath            string
	KeycloakInsecureSkip      bool
	DebugLogging              bool
	SecurityLogging           bool
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

func envInt(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid %s=%q; using %d", key, raw, def)
		return def
	}
	return val
}

func envDuration(key, def string) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		raw = def
	}
	dur, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("invalid %s=%q; using %s", key, raw, def)
		dur, _ = time.ParseDuration(def)
	}
	return dur
}

// Load reads environment variables into Config with defaults where possible.
func Load() Config {
	sessionSecret := mustEnv("SESSION_SECRET")
	issuerURL := mustEnv("KEYCLOAK_ISSUER_URL")
	externalURL := getenv("KEYCLOAK_EXTERNAL_URL", "")
	if externalURL == "" {
		externalURL = deriveExternalIssuer(issuerURL)
	}
	cfg := Config{
		Port:                      getenv("PORT", "8080"),
		Environment:               getenv("APP_ENV", "development"),
		AnythingLLMBaseURL:        getenv("ANYLLM_URL", "http://anythingllm:3001"),
		AnythingLLMAPIKey:         mustEnv("ANYLLM_API_KEY"),
		AnythingLLMTimeout:        envDuration("ANYLLM_HTTP_TIMEOUT", "10s"),
		AnythingLLMRetryMax:       envInt("ANYLLM_RETRY_MAX", 0),
		AnythingLLMRetryBackoff:   envDuration("ANYLLM_RETRY_BACKOFF", "200ms"),
		KeycloakIssuerURL:         issuerURL,
		KeycloakExternalURL:       externalURL,
		KeycloakClientID:          mustEnv("KEYCLOAK_CLIENT_ID"),
		KeycloakClientSecret:      mustEnv("KEYCLOAK_CLIENT_SECRET"),
		KeycloakRedirectURL:       getenv("KEYCLOAK_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		SessionSecret:             []byte(sessionSecret),
		SessionSecure:             getenv("SESSION_SECURE", "false") == "true",
		SessionSameSite:           getenv("SESSION_SAMESITE", "lax"),
		SessionMaxAgeDays:         envInt("SESSION_MAX_AGE_DAYS", 7),
		SessionHTTPOnly:           getenv("SESSION_HTTP_ONLY", "true") != "false",
		AutoCreateUsers:           getenv("ANYLLM_AUTO_CREATE", "true") != "false",
		DefaultRole:               getenv("ANYLLM_DEFAULT_ROLE", "user"),
		CallbackPath:              getenv("CALLBACK_PATH", "/auth/callback"),
		SkipListen:                getenv("SKIP_LISTEN", "false") == "true",
		ReadTimeout:               envDuration("READ_TIMEOUT", "15s"),
		WriteTimeout:              envDuration("WRITE_TIMEOUT", "15s"),
		ReadHeaderTimeout:         envDuration("READ_HEADER_TIMEOUT", "5s"),
		IdleTimeout:               envDuration("IDLE_TIMEOUT", "60s"),
		MaxHeaderBytes:            envInt("MAX_HEADER_BYTES", 1<<20),
		ShutdownTimeout:           envDuration("SHUTDOWN_TIMEOUT", "10s"),
		UpstreamDialTimeout:       envDuration("UPSTREAM_DIAL_TIMEOUT", "10s"),
		UpstreamTLSHandshake:      envDuration("UPSTREAM_TLS_HANDSHAKE_TIMEOUT", "10s"),
		UpstreamResponseHdr:       envDuration("UPSTREAM_RESPONSE_HEADER_TIMEOUT", "15s"),
		UpstreamIdleTimeout:       envDuration("UPSTREAM_IDLE_TIMEOUT", "60s"),
		UpstreamMaxIdle:           envInt("UPSTREAM_MAX_IDLE_CONNS", 100),
		UpstreamMaxIdleHost:       envInt("UPSTREAM_MAX_IDLE_CONNS_PER_HOST", 10),
		AccessLogging:             getenv("ACCESS_LOGGING", "true") != "false",
		MetricsEnabled:            getenv("METRICS_ENABLED", "false") == "true",
		ReadinessChecks:           getenv("READINESS_CHECKS", "false") == "true",
		ReadinessTimeout:          envDuration("READINESS_TIMEOUT", "2s"),
		ReadinessURL:              getenv("READINESS_URL", ""),
		SecurityHeaders:           getenv("SECURITY_HEADERS", "true") != "false",
		HeaderFrameOptions:        getenv("HEADER_FRAME_OPTIONS", "SAMEORIGIN"),
		HeaderReferrerPolicy:      getenv("HEADER_REFERRER_POLICY", "strict-origin-when-cross-origin"),
		HeaderCSP:                 getenv("HEADER_CSP", ""),
		HeaderPermissions:         getenv("HEADER_PERMISSIONS", "geolocation=(), microphone=(), camera=()"),
		RateLimitPerMinute:        envInt("RATE_LIMIT_PER_MIN", 0),
		RateLimitBurst:            envInt("RATE_LIMIT_BURST", 0),
		BannerTopText:             getenv("BANNER_TOP_TEXT", "SITE UNDER TEST"),
		BannerBottomText:          getenv("BANNER_BOTTOM_TEXT", "SITE UNDER TEST"),
		BannerBgColor:             getenv("BANNER_BG_COLOR", "#f6f000"),
		BannerTextColor:           getenv("BANNER_TEXT_COLOR", "#000000"),
		AgreementTitle:            getenv("AGREEMENT_TITLE", "User Agreement"),
		AgreementBody:             getenv("AGREEMENT_BODY", "Please acknowledge and accept this agreement to continue."),
		AgreementButtonText:       getenv("AGREEMENT_BUTTON_TEXT", "OK"),
		AccessRequestSubject:      getenv("ACCESS_REQUEST_SUBJECT", "AnythingLLM access request"),
		AccessRequestContact:      getenv("ACCESS_REQUEST_CONTACT", "helpdesk@help.com"),
		AccessRequestTitle:        getenv("ACCESS_REQUEST_TITLE", "Access required"),
		AccessRequestBody:         getenv("ACCESS_REQUEST_BODY", "%s does not have an AnythingLLM account."),
		AccessRequestPrompt:       getenv("ACCESS_REQUEST_PROMPT", "Paste this in an email to the helpdesk:"),
		AccessRequestContactLabel: getenv("ACCESS_REQUEST_CONTACT_LABEL", "Contact:"),
		AccessRequestSubjectLabel: getenv("ACCESS_REQUEST_SUBJECT_LABEL", "Use this subject line:"),
		AccessRequestSignOutText:  getenv("ACCESS_REQUEST_SIGNOUT_TEXT", "Sign out"),
		LoggedOutTitle:            getenv("LOGGED_OUT_TITLE", "Signed out"),
		LoggedOutBody:             getenv("LOGGED_OUT_BODY", "You have been signed out."),
		LoggedOutLinkText:         getenv("LOGGED_OUT_LINK_TEXT", "Sign in again"),
		KeycloakCAPath:            getenv("KEYCLOAK_CA_PATH", ""),
		KeycloakInsecureSkip:      getenv("KEYCLOAK_INSECURE_SKIP_VERIFY", "false") == "true",
		DebugLogging:              getenv("DEBUG_LOGGING", "false") == "true",
		SecurityLogging:           getenv("SECURITY_LOGGING", "true") != "false",
	}

	return cfg
}

// deriveExternalIssuer attempts to produce a browser-facing issuer URL when only an internal
// issuer is provided (common in Docker: issuer=http://keycloak:8080/realms/... but browser must
// hit localhost:8180).
func deriveExternalIssuer(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return issuer
	}
	host := parsed.Hostname()
	port := parsed.Port()
	// heuristic: if host is the internal docker hostname "keycloak" and port is 8080,
	// assume the browser can reach it on localhost:8180 (compose default).
	if strings.EqualFold(host, "keycloak") {
		if port == "8080" || port == "" {
			parsed.Host = "localhost:8180"
		} else {
			parsed.Host = "localhost"
		}
		return strings.TrimSuffix(parsed.String(), "/")
	}
	return issuer
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

// SessionSameSiteMode converts SessionSameSite to the http.SameSite enum.
func (c Config) SessionSameSiteMode() http.SameSite {
	switch strings.ToLower(strings.TrimSpace(c.SessionSameSite)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		fallthrough
	default:
		return http.SameSiteLaxMode
	}
}

// Validate performs basic sanity checks to catch unsafe prod settings.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Port) == "" {
		return fmt.Errorf("PORT must not be empty")
	}
	if !strings.HasPrefix(c.CallbackPath, "/") {
		return fmt.Errorf("CALLBACK_PATH must start with /")
	}
	if c.SessionMaxAgeDays <= 0 {
		return fmt.Errorf("SESSION_MAX_AGE_DAYS must be > 0")
	}
	if strings.EqualFold(strings.TrimSpace(c.SessionSameSite), "none") && !c.SessionSecure {
		return fmt.Errorf("SESSION_SAMESITE=none requires SESSION_SECURE=true")
	}
	if c.MaxHeaderBytes <= 0 {
		return fmt.Errorf("MAX_HEADER_BYTES must be > 0")
	}
	if c.ReadinessChecks && strings.TrimSpace(c.ReadinessURL) == "" {
		return fmt.Errorf("READINESS_URL must be set when READINESS_CHECKS=true")
	}
	if strings.EqualFold(c.Environment, "production") {
		if !c.SessionSecure {
			return fmt.Errorf("SESSION_SECURE must be true in production")
		}
		if c.KeycloakInsecureSkip {
			return fmt.Errorf("KEYCLOAK_INSECURE_SKIP_VERIFY must be false in production")
		}
		if strings.HasPrefix(strings.ToLower(c.KeycloakExternalURL), "http://") {
			return fmt.Errorf("KEYCLOAK_EXTERNAL_URL must be https in production")
		}
	}
	return nil
}
