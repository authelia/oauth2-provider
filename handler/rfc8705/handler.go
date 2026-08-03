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
	"authelia.com/provider/oauth2/x/errorsx"
)

// Handler implements RFC 8705 Section 3 certificate-bound access tokens at the token endpoint.
//
// It MUST be registered after every handler that restores a session at the token endpoint, so that a binding
// established when the grant was issued is present on the session by the time it is checked against the certificate
// presented now. There is no authorize endpoint counterpart: RFC 8705 defines no authorization request parameter, and
// Section 6.4 places the implicit grant out of scope.
type Handler struct {
	Config interface {
		oauth2.MTLSConfigProvider
		oauth2.TokenEndpointHandlersProvider
	}
}

func (h *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetMTLSEnabled(ctx) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var cert *x509.Certificate

	if cert, err = oauth2.ClientCertificateFromRequest(r, h.Config.GetMTLSClientCertificateHeader(ctx)); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The client certificate could not be read.").WithWrap(err).WithDebugError(err))
	}

	session, _ := request.GetSession().(oauth2.MTLSBoundSession)

	var bound string

	if session != nil {
		bound = session.GetClientCertificateSHA256Thumbprint()
	}

	// An existing binding makes a certificate mandatory regardless of policy. This is what enforces Sections 4 and
	// 7.1: a refresh token issued under a bound session may only be redeemed by the holder of that certificate.
	required := h.required(ctx, request) || bound != ""

	if cert == nil {
		if required {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The request requires a mutual-TLS client certificate but none was presented."))
		}

		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	// A session that cannot carry a binding is only an error when a binding was actually required. This deliberately
	// differs from the RFC 9449 DPoP handler, which reports the equivalent condition unconditionally: there the trigger
	// is a 'DPoP' header the client chose to send, so a session that cannot record the proof is a misconfiguration the
	// deployment asked for. Here the trigger is a certificate that may be entirely incidental  a proxy forwarding one
	// unconditionally, or an optional-mTLS listener; so failing unconditionally would turn every request made over
	// such a connection into a 500 for any session type that does not implement oauth2.MTLSBoundSession. When nothing
	// requires a binding the certificate is simply ignored, matching how client authentication treats an incidental
	// certificate.
	if session == nil {
		if required {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support mutual-TLS certificate binding."))
		}

		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	x5t := oauth2.X509CertificateSHA256Thumbprint(cert)

	if bound != "" && subtle.ConstantTimeCompare([]byte(bound), []byte(x5t)) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The mutual-TLS client certificate does not match the certificate the grant is bound to."))
	}

	session.SetClientCertificateSHA256Thumbprint(x5t)

	// Certificate binding augments a grant, it never satisfies one. Returning nil here would set the 'found' flag in
	// oauth2.(*Fosite).NewAccessRequest, which is that method's sole record that some handler actually granted the
	// request. CanHandleTokenEndpointRequest is a claim rather than a guarantee of handling: openid handlers claim a
	// grant type and then return oauth2.ErrUnknownRequest from HandleTokenEndpointRequest, unconditionally in the case
	// of OpenIDConnectExplicitHandler, so a request can pass the gate above with no grant handler accepting it. Were
	// this to return nil such a request would proceed to NewAccessResponse having had no code or refresh token
	// validated, replacing a 'invalid_request' with a 'server_error' raised only once the populate handlers have
	// already run. The binding recorded above is retained because it was written to the session, not to the return
	// value.
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateTokenEndpointResponse does nothing. Unlike an RFC 9449 DPoP bound token, a certificate-bound token keeps the
// 'bearer' token type: RFC 8705 Section 3 has the client present it as a bearer token over a mutually authenticated
// TLS connection, and the binding is conveyed to the resource server through the 'cnf' claim rather than the scheme.
func (h *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

// CanSkipClientAuth returns true. Certificate binding augments the grant and imposes no client authentication
// requirement of its own; the real grant handler enforces whatever it requires.
func (h *Handler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return true
}

// CanHandleTokenEndpointRequest reports whether some other registered handler will process this request.
//
// Certificate binding augments all token endpoint grants rather than owning one, so it participates only when a grant
// handler will actually run. Without this, and because CanSkipClientAuth waives client authentication here, a caller
// presenting any certificate alongside a 'grant_type' nothing implements would reach the binding logic unauthenticated.
func (h *Handler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	if !h.Config.GetMTLSEnabled(ctx) {
		return false
	}

	for _, handler := range h.Config.GetTokenEndpointHandlers(ctx) {
		// Skip every augmenting handler, not just this instance, so neither a duplicate registration nor another
		// augmenting handler that delegates the same question back here can recurse. RFC 9449 is registered alongside
		// this handler by compose.ComposeAllEnabled and does exactly that.
		if _, ok := handler.(oauth2.TokenEndpointGrantAugmenter); ok {
			continue
		}

		if handler.CanHandleTokenEndpointRequest(ctx, request) {
			return true
		}
	}

	return false
}

// AugmentsTokenEndpointGrant implements oauth2.TokenEndpointGrantAugmenter. Certificate binding binds a certificate to
// a grant another handler owns; it never satisfies an access request by itself.
func (h *Handler) AugmentsTokenEndpointGrant() {}

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
	_ oauth2.TokenEndpointHandler        = (*Handler)(nil)
	_ oauth2.TokenEndpointGrantAugmenter = (*Handler)(nil)
)
