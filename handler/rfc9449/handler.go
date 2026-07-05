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

// Handler implements RFC 9449 DPoP at the token and authorize endpoints.
type Handler struct {
	Config interface {
		oauth2.DPoPConfigProvider
	}
	Strategy oauth2.DPoPStrategy
}

// HandleAuthorizeEndpointRequest records the 'dpop_jkt' authorize-request parameter onto the session so the
// authorization code becomes bound to the client's DPoP proof-of-possession key. The bound thumbprint is later
// enforced by HandleTokenEndpointRequest against the DPoP proof presented at the token endpoint.
func (h *Handler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT)
	if jkt == "" {
		return nil
	}

	// Only record the binding for flows that issue an authorization code; an implicit-only flow never presents a
	// code at the token endpoint, so it would never pass through HandleTokenEndpointRequest's proof check and would
	// otherwise end up with an unenforceable cnf.jkt on its (directly issued) token.
	if !request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	session.SetDPoPJWKThumbprint(jkt)

	return nil
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

	return nil
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
	// DPoP augments all token-endpoint grants rather than owning one, but must not participate at all when disabled,
	// otherwise a nil HandleTokenEndpointRequest return would mask an unknown/bogus grant type as "found".
	return h.Config.GetDPoPEnabled(ctx)
}

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
	_ oauth2.TokenEndpointHandler     = (*Handler)(nil)
	_ oauth2.AuthorizeEndpointHandler = (*Handler)(nil)
)
