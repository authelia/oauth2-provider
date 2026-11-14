// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/x/errorsx"
)

type internalIssuanceKey struct{}

// IsInternalIssuance returns true when ctx belongs to a token request issued internally for a stored grant rather than
// received at the token endpoint. Such a request has no *http.Request: RequestContextKey holds none, and no DPoP proof
// or client certificate was presented, so a binding handler binds from the key material recorded on the session.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
func IsInternalIssuance(ctx context.Context) bool {
	internal, _ := ctx.Value(internalIssuanceKey{}).(bool)

	return internal
}

// handleAccessRequest runs the grant handlers, binding handlers and sender-constraint check on a parsed requester.
// r is nil for an internally issued request; handlers then see no RequestContextKey and binding handlers bind from the
// session. It returns a nil requester when no grant handler accepted the request.
func (f *Fosite) handleAccessRequest(ctx context.Context, r *http.Request, requester *AccessRequest, clientErr error, presented bool) (ar AccessRequester, err error) {
	var found = false

	for _, loader := range f.Config.GetTokenEndpointHandlers(ctx) {
		if !loader.CanHandleTokenEndpointRequest(ctx, requester) {
			continue
		}

		if clientErr != nil && (presented || !loader.CanSkipClientAuth(ctx, requester)) {
			return requester, clientErr
		}

		if err = loader.HandleTokenEndpointRequest(ctx, requester); err == nil {
			found = true
		} else if errors.Is(err, ErrUnknownRequest) {
			// This is a duplicate because it should already have been handled by
			// `loader.CanHandleTokenEndpointRequest` but let's keep it for sanity.

			continue
		} else if err != nil {
			return requester, err
		}
	}

	if !found {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithDebugf("The client with id '%s' requested grant type '%s' which is invalid, unknown, not supported, or not configured to be handled.", accessRequestClientID(requester), strings.Join(requester.GetGrantTypes(), " ")))
	}

	// Created here rather than by a handler because context values do not propagate between the handlers in this
	// loop: the container must exist before the first handler runs for a later one to observe what an earlier one
	// published.
	ctx = context.WithValue(ctx, DPoPProofContextKey, &DPoPProofHolder{})

	// Binding handlers run only once a grant handler has accepted the request, so a binding handler needs neither a
	// grant type claim nor a client authentication policy of its own: by this point the accepting grant handler has
	// enforced whatever authentication it requires, or legitimately waived it.
	for _, binding := range f.Config.GetTokenEndpointBindingHandlers(ctx) {
		if err = binding.BindAccessRequest(ctx, requester); err != nil {
			return requester, err
		}
	}

	// FAPI 2.0 Security Profile Section 5.3.2.1: only sender-constrained access tokens may be issued, and the request
	// must prove possession of the key or certificate the session is bound to. An internally issued request presents
	// no proof, so the binding recorded on the session when the grant was requested stands in for it.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
	provider, _ := f.Config.(EnforceSenderConstrainedAccessTokensProvider)

	if IsSenderConstrainedAccessTokenEnforced(ctx, provider, requester.GetClient()) {
		var constrained bool

		if IsInternalIssuance(ctx) {
			constrained = f.isSenderConstrainedBySession(ctx, requester.GetSession())
		} else {
			constrained = f.isSenderConstrainedByRequest(ctx, r, requester.GetSession())
		}

		if !constrained {
			return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("The request requires a sender-constrained access token, but neither a DPoP proof nor a mutual-TLS client certificate was presented to bind it to."))
		}
	}

	return requester, nil
}

// issueInternalAccessResponse issues the token response for a stored grant without an HTTP token request. requester
// is a synthetic access request built from the stored grant; it runs through the same grant handlers, binding handlers
// and sender-constraint check as a token endpoint request, then NewAccessResponse.
func (f *Fosite) issueInternalAccessResponse(ctx context.Context, requester *AccessRequest) (AccessResponder, error) {
	if requester == nil || requester.GetSession() == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The internally issued access request has no session."))
	}

	ctx = context.WithValue(ctx, internalIssuanceKey{}, true)
	ctx = context.WithValue(ctx, RequestContextKey, (*http.Request)(nil))
	ctx = context.WithValue(ctx, AccessRequestContextKey, requester)

	if _, err := f.handleAccessRequest(ctx, nil, requester, nil, false); err != nil {
		return nil, err
	}

	return f.NewAccessResponse(ctx, requester)
}

// accessRequestClientID returns the 'client_id' parameter of the request, or the ID of its client when the request has
// none, as an internally issued request has no form client.
func accessRequestClientID(requester AccessRequester) (id string) {
	if id = requester.GetRequestForm().Get(consts.FormParameterClientID); id == "" && !reflection.IsNil(requester.GetClient()) {
		id = requester.GetClient().GetID()
	}

	return id
}

func (f *Fosite) isSenderConstrainedByRequest(ctx context.Context, r *http.Request, session Session) bool {
	if s, ok := session.(DPoPBoundSession); ok && s.GetDPoPJWKThumbprint() != "" && f.Config.GetDPoPEnabled(ctx) {
		if proof := GetDPoPProof(ctx); proof != nil && subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(s.GetDPoPJWKThumbprint())) == 1 {
			return true
		}
	}

	if s, ok := session.(MTLSBoundSession); ok && s.GetClientCertificateSHA256Thumbprint() != "" && f.Config.GetMTLSEnabled(ctx) {
		if _, err := ValidateClientCertificateBinding(r, f.Config.GetMTLSClientCertificateHeader(ctx), s.GetClientCertificateSHA256Thumbprint()); err == nil {
			return true
		}
	}

	return false
}

// isSenderConstrainedBySession returns true when the session carries a DPoP JWK thumbprint or an mTLS certificate
// thumbprint whose mechanism is enabled.
func (f *Fosite) isSenderConstrainedBySession(ctx context.Context, session Session) bool {
	return isSenderConstrained(ctx, f.Config, session)
}
