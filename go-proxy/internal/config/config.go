package config

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"
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
	AccessRequestSubject string
	AccessRequestContact string
	AccessRequestTitle   string
	AccessRequestBody    string
	AccessRequestPrompt  string
	AccessRequestContactLabel string
	AccessRequestSubjectLabel string
	AccessRequestSignOutText  string
	LoggedOutTitle       string
	LoggedOutBody        string
	LoggedOutLinkText    string
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
	externalURL := getenv("KEYCLOAK_EXTERNAL_URL", "")
	if externalURL == "" {
		externalURL = deriveExternalIssuer(issuerURL)
	}
	cfg := Config{
		Port:                 getenv("PORT", "8080"),
		AnythingLLMBaseURL:   getenv("ANYLLM_URL", "http://anythingllm:3001"),
		AnythingLLMAPIKey:    mustEnv("ANYLLM_API_KEY"),
		KeycloakIssuerURL:    issuerURL,
		KeycloakExternalURL:  externalURL,
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
		AccessRequestSubject: getenv("ACCESS_REQUEST_SUBJECT", "AnythingLLM access request"),
		AccessRequestContact: getenv("ACCESS_REQUEST_CONTACT", "helpdesk@help.com"),
		AccessRequestTitle:   getenv("ACCESS_REQUEST_TITLE", "Access required"),
		AccessRequestBody:    getenv("ACCESS_REQUEST_BODY", "%s does not have an AnythingLLM account."),
		AccessRequestPrompt:  getenv("ACCESS_REQUEST_PROMPT", "Paste this in an email to the helpdesk:"),
		AccessRequestContactLabel: getenv("ACCESS_REQUEST_CONTACT_LABEL", "Contact:"),
		AccessRequestSubjectLabel: getenv("ACCESS_REQUEST_SUBJECT_LABEL", "Use this subject line:"),
		AccessRequestSignOutText:  getenv("ACCESS_REQUEST_SIGNOUT_TEXT", "Sign out"),
		LoggedOutTitle:       getenv("LOGGED_OUT_TITLE", "Signed out"),
		LoggedOutBody:        getenv("LOGGED_OUT_BODY", "You have been signed out."),
		LoggedOutLinkText:    getenv("LOGGED_OUT_LINK_TEXT", "Sign in again"),
		KeycloakCAPath:       getenv("KEYCLOAK_CA_PATH", ""),
		KeycloakInsecureSkip: getenv("KEYCLOAK_INSECURE_SKIP_VERIFY", "false") == "true",
		DebugLogging:         getenv("DEBUG_LOGGING", "false") == "true",
		SecurityLogging:      getenv("SECURITY_LOGGING", "true") != "false",
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
