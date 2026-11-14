// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BindBackChannelAuthenticationRequest binds an OpenID Connect CIBA authentication request to a DPoP key: the key of a
// DPoP proof presented with the request, else the RFC 9449 Section 10 'dpop_jkt' parameter. The thumbprint is recorded
// both as the binding and as the requested thumbprint, and a proof's public key is recorded too. In poll and ping mode
// the token request's proof must then match it; in push mode the tokens are bound to it at issuance.
//
// The proof is validated as at the token endpoint, with the backchannel authentication endpoint or its mutual-TLS
// alias as the 'htu', including the 'jti' replay check.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
func (h *Handler) BindBackChannelAuthenticationRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT)

	if jkt != "" && !oauth2.IsValidDPoPJWKThumbprint(jkt) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is %d characters long.", oauth2.DPoPJWKThumbprintLength))
	}

	var header string

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r != nil {
		if header, err = singleDPoPHeader(r); err != nil {
			return err
		}
	}

	if header == "" && jkt == "" {
		if request.GetDeliveryMode() == consts.CIBAModePush && h.required(ctx, request.GetClient()) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The push mode requires a DPoP proof or a 'dpop_jkt' parameter at the backchannel authentication endpoint because DPoP bound access tokens are required for the client."))
		}

		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	if header == "" {
		session.SetDPoPJWKThumbprint(jkt)
		session.SetRequestedDPoPJWKThumbprint(jkt)

		return nil
	}

	return h.bindBackChannelProof(ctx, r, header, jkt, session)
}

// bindBackChannelProof validates the DPoP proof presented at the backchannel authentication endpoint and records its
// key on the session.
func (h *Handler) bindBackChannelProof(ctx context.Context, r *http.Request, header, jkt string, session oauth2.DPoPBoundSession) (err error) {
	if h.Strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The request contains a DPoP proof but the DPoP strategy needed to verify it is not configured."))
	}

	urls := h.Config.GetEndpointURLs(ctx)

	var proof *oauth2.DPoPProof

	if proof, err = h.Strategy.ValidateDPoPProof(ctx, r.Method, requestURL(r), header, h.Config.GetDPoPNonceRequired(ctx), urls.URLs(oauth2.EndpointBackChannelAuthentication)...); err != nil {
		return err
	}

	// See: https://www.rfc-editor.org/rfc/rfc9449#section-10
	if jkt != "" && jkt != proof.Thumbprint {
		return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The 'dpop_jkt' parameter does not match the thumbprint of the public key in the DPoP proof."))
	}

	if proof.JWK == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The DPoP proof carried no public key to record."))
	}

	var raw []byte

	if raw, err = proof.JWK.MarshalJSON(); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The DPoP proof key could not be recorded.").WithWrap(err).WithDebugError(err))
	}

	session.SetDPoPJWKThumbprint(proof.Thumbprint)
	session.SetRequestedDPoPJWKThumbprint(proof.Thumbprint)
	session.SetDPoPPublicKeyJWK(raw)

	return nil
}

var (
	_ oauth2.BackChannelAuthenticationEndpointBindingHandler = (*Handler)(nil)
)
