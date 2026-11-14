// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"context"
	"crypto/x509"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BindBackChannelAuthenticationRequest records the thumbprint of the mutual-TLS client certificate presented with an
// OpenID Connect CIBA push mode authentication request on the session, as push mode tokens are bound at issuance to the
// key material presented here. Poll and ping mode tokens are bound by BindAccessRequest at the token endpoint.
//
// The certificate is recorded for a client that requires certificate-bound access tokens, a client that authenticates
// with mutual-TLS, and a client that must have sender-constrained tokens and presents no DPoP proof. It is not recorded
// when the request carries DPoP key material, so the tokens are bound to one key only; a client that requires
// certificate-bound access tokens is then rejected.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
func (h *Handler) BindBackChannelAuthenticationRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) (err error) {
	if !h.Config.GetMTLSEnabled(ctx) || request.GetDeliveryMode() != consts.CIBAModePush {
		return nil
	}

	client := request.GetClient()
	required := h.required(ctx, client)

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)

	if h.hasDPoPKeyMaterial(ctx, request, r) {
		if required {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The request presents DPoP key material but certificate-bound access tokens are required for the client, and the tokens of a push mode request are bound to one key only."))
		}

		return nil
	}

	if !required && !isMutualTLSAuthenticated(client) && (r == nil || !h.requiredInsteadOfDPoP(ctx, client, r)) {
		return nil
	}

	if r == nil {
		if required {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The request requires a mutual-TLS client certificate but the HTTP request needed to read it is not available."))
		}

		return nil
	}

	var cert *x509.Certificate

	if cert, err = oauth2.ClientCertificateFromRequest(r, h.Config.GetMTLSClientCertificateHeader(ctx)); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The client certificate could not be read.").WithWrap(err).WithDebugError(err))
	}

	if cert == nil {
		if required {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The push mode requires a mutual-TLS client certificate at the backchannel authentication endpoint because certificate-bound access tokens are required for the client."))
		}

		return nil
	}

	session, ok := request.GetSession().(oauth2.MTLSBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support mutual-TLS certificate binding."))
	}

	session.SetClientCertificateSHA256Thumbprint(oauth2.X509CertificateSHA256Thumbprint(cert))

	return nil
}

// hasDPoPKeyMaterial returns true when DPoP is enabled and the request carries DPoP key material: a thumbprint already
// recorded on the session, a 'dpop_jkt' parameter, or a DPoP proof.
func (h *Handler) hasDPoPKeyMaterial(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, r *http.Request) bool {
	if c, ok := h.Config.(interface {
		GetDPoPEnabled(ctx context.Context) bool
	}); !ok || !c.GetDPoPEnabled(ctx) {
		return false
	}

	if session, ok := request.GetSession().(oauth2.DPoPBoundSession); ok && session.GetDPoPJWKThumbprint() != "" {
		return true
	}

	if request.GetRequestForm().Get(consts.FormParameterDPoPJKT) != "" {
		return true
	}

	return r != nil && len(r.Header.Values(consts.HeaderDPoP)) != 0
}

// isMutualTLSAuthenticated returns true when the client authenticates at the backchannel authentication endpoint with
// an RFC 8705 Section 2 method, which uses the 'token_endpoint_auth_method' client metadata.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func isMutualTLSAuthenticated(client oauth2.Client) bool {
	c, ok := client.(oauth2.AuthenticationMethodClient)
	if !ok {
		return false
	}

	switch c.GetTokenEndpointAuthMethod() {
	case consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth:
		return true
	default:
		return false
	}
}

var (
	_ oauth2.BackChannelAuthenticationEndpointBindingHandler = (*Handler)(nil)
)
