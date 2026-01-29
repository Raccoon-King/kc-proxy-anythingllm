package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC wraps provider, verifier and oauth2 config for Keycloak.
type OIDC struct {
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
	OAuth2   *oauth2.Config
}

// NewOIDC initializes OIDC helpers.
// The issuer parameter is the URL used to fetch OIDC discovery (can be internal URL).
// InsecureIssuerURLContext allows the discovered issuer to differ from the request URL,
// which is needed when the proxy accesses Keycloak via internal hostname but Keycloak
// advertises an external hostname in its configuration.
func NewOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, httpClient *http.Client) (*OIDC, error) {
	if httpClient != nil {
		ctx = oidc.ClientContext(ctx, httpClient)
	}
	// Allow issuer mismatch between request URL and discovery response
	// This is needed for internal/external URL split (e.g., keycloak:8080 vs localhost:8180)
	ctx = oidc.InsecureIssuerURLContext(ctx, issuer)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
		// Skip issuer check to allow internal/external URL split
		// (proxy accesses Keycloak at internal URL, but tokens have external issuer)
		SkipIssuerCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		RedirectURL:  redirectURL,
	}

	return &OIDC{Provider: provider, Verifier: verifier, OAuth2: oauthConfig}, nil
}

// TokenClaims represents the subset of ID token claims we care about.
type TokenClaims struct {
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Subject           string `json:"sub"`
}

// VerifyIDToken parses and verifies an ID token string.
func (o *OIDC) VerifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, *TokenClaims, error) {
	if o.Verifier == nil {
		return nil, nil, fmt.Errorf("verifier not configured")
	}
	idToken, err := o.Verifier.Verify(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	var claims TokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, err
	}
	return idToken, &claims, nil
}

// NewAuthenticatedClient returns an HTTP client that injects OAuth2 tokens.
func NewAuthenticatedClient(ctx context.Context, token *oauth2.Token) *http.Client {
	ts := oauth2.StaticTokenSource(token)
	return oauth2.NewClient(ctx, ts)
}
