package auth

import (
	"context"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCAdapter implements server.OIDCClient using the concrete OIDC helper.
type OIDCAdapter struct {
	inner       *OIDC
	internalURL string // Internal issuer URL (for token exchange)
	externalURL string // External issuer URL (for browser redirects)
}

func NewOIDCAdapter(o *OIDC) *OIDCAdapter {
	return &OIDCAdapter{inner: o}
}

// NewOIDCAdapterWithExternalURL creates an adapter with separate internal/external URLs.
// The external URL is used for browser redirects (authorization endpoint).
func NewOIDCAdapterWithExternalURL(o *OIDC, internalURL, externalURL string) *OIDCAdapter {
	return &OIDCAdapter{
		inner:       o,
		internalURL: internalURL,
		externalURL: externalURL,
	}
}

func (a *OIDCAdapter) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	url := a.inner.OAuth2.AuthCodeURL(state, opts...)
	// If external URL is configured and different from internal, rewrite the URL
	if a.externalURL != "" && a.internalURL != "" && a.externalURL != a.internalURL {
		url = strings.Replace(url, a.internalURL, a.externalURL, 1)
	}
	return url
}

func (a *OIDCAdapter) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return a.inner.OAuth2.Exchange(ctx, code, opts...)
}

func (a *OIDCAdapter) VerifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, *TokenClaims, error) {
	return a.inner.VerifyIDToken(ctx, raw)
}
