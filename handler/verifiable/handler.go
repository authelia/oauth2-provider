// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	draftNonceField    = "c_nonce_draft_00"
	draftNonceExpField = "c_nonce_expires_in_draft_00"
)

type Handler struct {
	Config interface {
		oauth2.VerifiableCredentialsNonceLifespanProvider
	}
	NonceManager
}

// HandleTokenEndpointRequest returns oauth2.ErrUnknownRequest unless the request was granted the scopes this handler
// acts on. It performs no other validation.
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	return nil
}

// PopulateTokenEndpointResponse generates a nonce bound to the issued access token and adds it to the response as
// 'c_nonce_draft_00', along with its lifespan in seconds.
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	lifespan := c.Config.GetVerifiableCredentialsNonceLifespan(ctx)
	expiry := time.Now().UTC().Add(lifespan)
	nonce, err := c.NewNonce(ctx, response.GetAccessToken(), expiry)
	if err != nil {
		return err
	}

	response.SetExtra(draftNonceField, nonce)
	response.SetExtra(draftNonceExpField, int64(lifespan.Seconds()))

	return nil
}

// IsVerifiableCredentialsHandler marks this handler as the OpenID for Verifiable Credentials userinfo handler.
//
// See: https://openid.net/specs/openid-connect-userinfo-vc-1_0.html#section-2
func (c *Handler) IsVerifiableCredentialsHandler() {}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *Handler) CanSkipClientAuth(context.Context, oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the request was granted both the 'openid' and
// 'userinfo_credential_draft_00' scopes.
func (c *Handler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantedScopes().Has(consts.ScopeOpenID, consts.ScopeUserinfoCredentialDraft00)
}

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *Handler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *Handler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *Handler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *Handler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var (
	_ oauth2.TokenEndpointHandler = (*Handler)(nil)
)
