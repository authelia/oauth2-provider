// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Handler implements RFC 8705 Section 3 certificate-bound access tokens at the token endpoint.
//
// It is dispatched in the token binding phase, which runs only once a grant handler has accepted the request and
// restored its session, so a binding established when the grant was issued is present by the time it is checked
// against the certificate presented now. Registration order does not affect that. There is no authorize endpoint
// counterpart: RFC 8705 defines no authorization request parameter, and Section 6.4 places the implicit grant out of
// scope.
type Handler struct {
	Config interface {
		oauth2.MTLSConfigProvider
		oauth2.MTLSStrictRefreshTokenBindingProvider
	}
}

// BindAccessRequest records the thumbprint of the mutual-TLS client certificate presented with this request on the
// session, and enforces any thumbprint the session already carries. It returns nil when there is nothing to bind.
//
// A refresh by a confidential client is re-bound to the presented certificate, as RFC 8705 Section 4 binds the refresh
// tokens of public clients only. A certificate is still required. The grant of a client for which
// oauth2.MTLSStrictRefreshTokenBindingProvider or oauth2.MTLSStrictRefreshTokenBindingClient requires strict binding
// keeps its certificate.
func (h *Handler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetMTLSEnabled(ctx) {
		return nil
	}

	session, _ := request.GetSession().(oauth2.MTLSBoundSession)

	var bound string

	if session != nil {
		bound = session.GetClientCertificateSHA256Thumbprint()
	}

	// An existing binding makes a certificate mandatory regardless of policy. For a public client this is what
	// enforces Section 4: a refresh token issued under a bound session may only be redeemed by the holder of that
	// certificate.
	required := h.required(ctx, request) || bound != ""

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		// Resolved before the certificate is read so that a binding which must be enforced is never silently
		// skipped because the request needed to enforce it is absent.
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
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The request requires a mutual-TLS client certificate but none was presented."))
		}

		return nil
	}

	// A session that cannot carry a binding is an error only when a binding is required; otherwise the certificate
	// is incidental and ignored. The RFC 9449 DPoP handler differs, reporting the equivalent condition unconditionally.
	if session == nil {
		if required {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support mutual-TLS certificate binding."))
		}

		return nil
	}

	x5t := oauth2.X509CertificateSHA256Thumbprint(cert)

	if bound != "" && subtle.ConstantTimeCompare([]byte(bound), []byte(x5t)) != 1 && !h.rebindable(ctx, request) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The mutual-TLS client certificate does not match the certificate the grant is bound to."))
	}

	// Only a required binding is recorded, as a recorded binding makes the certificate mandatory on every subsequent
	// refresh.
	if !required {
		return nil
	}

	session.SetClientCertificateSHA256Thumbprint(x5t)

	return nil
}

// PopulateBoundTokenEndpointResponse does nothing. Unlike an RFC 9449 DPoP bound token, a certificate-bound token
// keeps the 'bearer' token type: RFC 8705 Section 3 has the client present it as a bearer token over a mutually
// authenticated TLS connection, and the binding is conveyed to the resource server through the 'cnf' claim rather
// than the scheme.
func (h *Handler) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

func (h *Handler) rebindable(ctx context.Context, request oauth2.AccessRequester) bool {
	if !request.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken) || h.Config.GetMTLSStrictRefreshTokenBinding(ctx) {
		return false
	}

	client := request.GetClient()
	if client == nil || client.IsPublic() {
		return false
	}

	if c, ok := client.(oauth2.MTLSStrictRefreshTokenBindingClient); ok && c.GetMTLSStrictRefreshTokenBinding() {
		return false
	}

	return true
}

func (h *Handler) required(ctx context.Context, request oauth2.AccessRequester) bool {
	if h.Config.GetMTLSEnforce(ctx) {
		return true
	}

	if client, ok := request.GetClient().(oauth2.MTLSClient); ok {
		return client.GetEnableTLSClientAuthBoundAccessTokens()
	}

	return false
}

var (
	_ oauth2.TokenEndpointBindingHandler = (*Handler)(nil)
)
