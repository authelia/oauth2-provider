// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Handler implements RFC 9449 DPoP at the token endpoint. The authorize endpoint is handled by AuthorizeHandler, which
// MUST be registered ahead of the handlers that issue an authorization code; see its documentation for why.
type Handler struct {
	Config interface {
		oauth2.DPoPConfigProvider
		oauth2.TokenEndpointHandlersProvider
	}
	Strategy oauth2.DPoPStrategy
}

func (h *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	header, err := singleDPoPHeader(r)
	if err != nil {
		return err
	}

	session, _ := request.GetSession().(oauth2.DPoPBoundSession)

	var bound string
	if session != nil {
		bound = session.GetDPoPJWKThumbprint()
	}

	required := h.required(ctx, request) || bound != ""

	if header == "" {
		if required {
			return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request requires a DPoP proof but none was provided."))
		}

		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	proof, err := h.Strategy.ValidateDPoPProof(ctx, r.Method, requestURL(r), header, h.Config.GetDPoPNonceRequired(ctx))
	if err != nil {
		return err
	}

	if bound != "" && bound != proof.Thumbprint {
		return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof key does not match the key the grant is bound to."))
	}

	session.SetDPoPJWKThumbprint(proof.Thumbprint)

	// DPoP augments a grant, it never satisfies one. Returning nil here would set the 'found' flag in
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

func (h *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	session, _ := request.GetSession().(oauth2.DPoPBoundSession)
	if session == nil || session.GetDPoPJWKThumbprint() == "" {
		return nil
	}

	// Override the token type set by the grant handler; a DPoP-bound token is of type "DPoP".
	response.SetTokenType(oauth2.DPoPAccessToken)

	return nil
}

func (h *Handler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	// DPoP augments the grant; it imposes no client-auth requirement of its own. The real grant handler enforces
	// whatever client authentication it requires (e.g. RFC 7523 JWT bearer may itself skip client auth).
	return true
}

func (h *Handler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	if !h.Config.GetDPoPEnabled(ctx) {
		return false
	}

	// DPoP augments all token-endpoint grants rather than owning one, so it participates only when some grant handler
	// will actually process the request. Without this, a caller presenting any self-signed proof alongside a
	// 'grant_type' nothing implements would reach ValidateDPoPProof, and since CanSkipClientAuth waives client
	// authentication for this handler, that caller need not be authenticated at all. Validating the proof records a
	// replay marker, so it would hand an anonymous caller a write into the replay store on every request.
	for _, handler := range h.Config.GetTokenEndpointHandlers(ctx) {
		// Skip every augmenting handler, not just this instance, so neither a duplicate registration nor another
		// augmenting handler that delegates the same question back here can recurse. RFC 8705 is registered alongside
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

// AugmentsTokenEndpointGrant implements oauth2.TokenEndpointGrantAugmenter. DPoP binds a key to a grant another
// handler owns; it never satisfies an access request by itself.
func (h *Handler) AugmentsTokenEndpointGrant() {}

func (h *Handler) required(ctx context.Context, request oauth2.AccessRequester) bool {
	if h.Config.GetDPoPEnforce(ctx) {
		return true
	}

	if client, ok := request.GetClient().(oauth2.DPoPClient); ok {
		return client.GetEnableDPoPBoundAccessTokens()
	}

	return false
}

var (
	_ oauth2.TokenEndpointHandler        = (*Handler)(nil)
	_ oauth2.TokenEndpointGrantAugmenter = (*Handler)(nil)
)
