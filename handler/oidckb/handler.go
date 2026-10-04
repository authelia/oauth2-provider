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
// It performs no proof validation or parsing: it consumes the proof rfc9449.Handler has validated and published via
// oauth2.PublishDPoPProof, so it MUST be registered after rfc9449.Handler in the token endpoint binding handler list.
type Handler struct {
	Config interface {
		oauth2.OIDCKeyBindingConfigProvider
		oauth2.DPoPConfigProvider
	}
}

// BindAccessRequest confirms the 'c_s256' claim and records the proof's public key on the session.
//
// The authorization code and device code grants grant their scopes after the binding handlers run, so the Section 2.3
// 'c_s256' claim is the signal rather than the granted scopes. The 'bound_key' gate is applied at issuance by
// oauth2.ApplyIDTokenConfirmation.
func (h *Handler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	// A refresh records nothing: the key and the key binding marker are already on the session, and Section 5
	// requires the refreshed ID Token's 'cnf' to equal the original's.
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
		// A grant granted 'bound_key' always carried 'dpop_jkt' (Section 2.1 and Section 3.1), so the marker with no
		// thumbprint recorded means a handler did not run.
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
