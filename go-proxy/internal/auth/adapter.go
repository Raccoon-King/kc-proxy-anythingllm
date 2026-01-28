package auth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCAdapter implements server.OIDCClient using the concrete OIDC helper.
type OIDCAdapter struct {
	inner *OIDC
}

func NewOIDCAdapter(o *OIDC) *OIDCAdapter {
	return &OIDCAdapter{inner: o}
}

func (a *OIDCAdapter) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return a.inner.OAuth2.AuthCodeURL(state, opts...)
}

func (a *OIDCAdapter) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return a.inner.OAuth2.Exchange(ctx, code)
}

func (a *OIDCAdapter) VerifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, *TokenClaims, error) {
	return a.inner.VerifyIDToken(ctx, raw)
}
