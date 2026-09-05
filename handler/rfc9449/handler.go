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

// Handler implements RFC 9449 DPoP at the token endpoint. The authorize endpoint is handled by AuthorizeHandler.
//
// DPoP augments a grant another handler owns rather than owning one itself, so it is dispatched in the token binding
// phase: oauth2.(*Fosite).NewAccessRequest runs it only once a grant handler has accepted the request and restored
// the session, and oauth2.(*Fosite).NewAccessResponse runs its populate after every grant handler has set a token
// type. Registration order does not affect either.
type Handler struct {
	Config interface {
		oauth2.DPoPConfigProvider
	}
	Strategy oauth2.DPoPStrategy
}

// BindAccessRequest validates the DPoP proof presented with this request, records its key thumbprint on the session,
// and enforces any thumbprint the session already carries. It returns nil when there is nothing to bind.
func (h *Handler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	session, _ := request.GetSession().(oauth2.DPoPBoundSession)

	var bound string

	if session != nil {
		if bound = session.GetDPoPJWKThumbprint(); bound == "" {
			bound = session.GetRequestedDPoPJWKThumbprint()
		}
	}

	// An existing binding makes a proof mandatory regardless of policy: a refresh token issued under a bound
	// session may only be redeemed by the holder of that key.
	required := h.required(ctx, request) || bound != ""

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		// Resolved before the header is read so that a binding which must be enforced is never silently skipped
		// because the request needed to enforce it is absent.
		if required {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The request requires a DPoP proof but the HTTP request needed to verify it is not available."))
		}

		return nil
	}

	header, err := singleDPoPHeader(r)
	if err != nil {
		return err
	}

	if header == "" {
		if required {
			return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request requires a DPoP proof but none was provided."))
		}

		return nil
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

	// Published only here, and only once every check above has passed, so a consumer may rely on a published proof
	// having satisfied RFC 9449 Section 5 and matched any binding the grant already carried.
	oauth2.PublishDPoPProof(ctx, proof)

	session.SetDPoPJWKThumbprint(proof.Thumbprint)

	return nil
}

// PopulateBoundTokenEndpointResponse overrides the token type set by the grant handler, because RFC 9449 Section 7.1
// requires a DPoP bound access token to be presented under the DPoP scheme rather than as a bearer token.
func (h *Handler) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
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
	_ oauth2.TokenEndpointBindingHandler = (*Handler)(nil)
)
