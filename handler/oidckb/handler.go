// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"context"
	"crypto/subtle"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Handler implements the OpenID Connect Key Binding 1.0 token endpoint rules: the Section 2.3 and Section 3.3
// 'c_s256' confirmation, and recording the proof's public key so the ID Token can carry it in 'cnf'.
//
// It performs no proof validation and no parsing at all. It consumes the proof rfc9449.Handler has already fully
// validated and published via oauth2.PublishDPoPProof, including the replay check that consumes the proof's 'jti';
// parsing the header itself would present that same 'jti' to the replay store a second time and reject the request.
//
// This handler MUST therefore be registered AFTER rfc9449.Handler in the token endpoint binding handler list. A proof
// obtained from oauth2.GetDPoPProof has passed every RFC 9449 Section 5 check and has matched any binding the grant
// already carried: oauth2.PublishDPoPProof has exactly one call site, after all of them.
type Handler struct {
	Config interface {
		oauth2.OIDCKeyBindingConfigProvider
		oauth2.DPoPConfigProvider
	}
}

// BindAccessRequest confirms the 'c_s256' claim and records the proof's public key on the session.
//
// The granted scopes are not consulted for the authorization code and device code grants: both grant their scopes in
// the populate phase, after every binding handler has run, so 'bound_key' is not yet visible here. The presence of the
// 'c_s256' claim is the signal instead, which Section 2.3 makes mandatory for a key-bound token request and which a
// plain RFC 9449 client never sends. The 'bound_key' gate is applied at issuance by oauth2.ApplyIDTokenConfirmation.
func (h *Handler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	// A refresh records nothing. The key is already on the session from the original token request, and
	// oauth2.ApplyIDTokenConfirmation decides from the key binding marker rather than the current request's granted
	// scopes, so a refresh narrowing 'bound_key' away keeps its confirmation. That is what Section 5 asks for: the
	// refreshed ID Token's 'cnf' must equal the original's.
	//
	// The presence of a recorded key cannot stand in for "this grant is key bound": the bind phase records one
	// without consulting scopes, so a grant that requested 'bound_key' and was granted only 'openid' carries a key
	// while never having issued a bound ID Token. That is why the marker exists.
	if request.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken) {
		return nil
	}

	code, ok := h.code(request)
	if !ok {
		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		// The session supports RFC 9449 binding but not key binding. That is only an error for a client that
		// actually attempted key binding, which Section 2.3 makes identifiable by the 'c_s256' claim.
		if proof := oauth2.GetDPoPProof(ctx); proof != nil && proof.CodeHash != "" {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP key binding."))
		}

		return nil
	}

	granted := session.GetOIDCKeyBindingGranted()

	requested := session.GetRequestedDPoPJWKThumbprint()

	if requested == "" {
		// A grant granted 'bound_key' always carried 'dpop_jkt': Section 2.1 and Section 3.1 make it mandatory
		// alongside the scope, and AuthorizeHandler and DeviceAuthorizeHandler both reject the scope without it.
		// The marker set with no thumbprint recorded is therefore a handler that never ran rather than anything
		// the client did or omitted, and saying so here keeps the fault from surfacing at issuance as a missing
		// 'c_s256' the client did in fact send.
		if granted {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("No 'dpop_jkt' was recorded for a grant that was granted the 'bound_key' scope; DPoPAuthorizeFactory, or DPoPDeviceAuthorizeFactory for the device flow, must be registered."))
		}

		// Section 2.3: when the authentication request carried no 'dpop_jkt' the OP MUST NOT include the 'cnf'
		// claim, which keeps a deployment using DPoP for access tokens from having key-bound ID Tokens issued
		// accidentally. The value is read here rather than the grant binding because the token endpoint overwrites
		// the latter from the presented proof.
		return nil
	}

	// A grant that was not granted 'bound_key' issues no key-bound ID Token, so recording its key would make a
	// later reader believe otherwise. This is what keeps a recorded key meaning "this grant is key bound".
	if !granted {
		return nil
	}

	proof := oauth2.GetDPoPProof(ctx)
	if proof == nil {
		// A grant asked to be key bound and no validated proof exists for it, which a correctly wired deployment
		// cannot produce: rfc9449.Handler rejects a request whose session carries a binding and presents no proof.
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("No validated DPoP proof was available; DPoPTokenFactory must be registered before OpenIDConnectKeyBindingFactory."))
	}

	if proof.CodeHash == "" {
		// Section 2.3 and Section 3.3 make 'c_s256' mandatory for the token request of a key-bound grant, and this
		// point is reached only for one: a grant granted 'bound_key' whose authentication request carried
		// 'dpop_jkt'. Section 5 waives the claim for a refresh, which returns above.
		return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing the 'c_s256' claim, which is required because the 'bound_key' scope was granted."))
	}

	if subtle.ConstantTimeCompare([]byte(proof.CodeHash), []byte(CodeHash(code))) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof 'c_s256' claim does not match the presented code."))
	}

	if subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(requested)) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof key does not match the key the authentication request bound the grant to."))
	}

	if proof.JWK == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The DPoP proof carried no public key to record."))
	}

	var raw []byte

	if raw, err = proof.JWK.MarshalJSON(); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The DPoP proof key could not be recorded.").WithWrap(err).WithDebugError(err))
	}

	session.SetDPoPPublicKeyJWK(raw)

	return nil
}

func (h *Handler) code(request oauth2.AccessRequester) (code string, ok bool) {
	switch types := request.GetGrantTypes(); {
	case types.ExactOne(consts.GrantTypeAuthorizationCode):
		code = request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	case types.ExactOne(consts.GrantTypeOAuthDeviceCode):
		code = request.GetRequestForm().Get(consts.FormParameterDeviceCode)
	default:
		return "", false
	}

	return code, code != ""
}

// PopulateBoundTokenEndpointResponse makes no adjustment to the token response. The key binding is expressed in the
// ID Token, which the OpenID Connect handlers issue, and the RFC 9449 token type is set by rfc9449.Handler.
func (h *Handler) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

var (
	_ oauth2.TokenEndpointBindingHandler = (*Handler)(nil)
)
