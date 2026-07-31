// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	ErrorPARNotSupported           = "The OAuth 2.0 provider does not support Pushed Authorization Requests"
	DebugPARStorageInvalid         = "The Pushed Authorization Request storage is not implemented"
	DebugPARConfigMissing          = "'PushedAuthorizeRequestConfigProvider' not implemented"
	DebugPARRequestsHandlerMissing = "'PushedAuthorizeRequestHandlersProvider' not implemented"
)

// NewPushedAuthorizeRequest validates the request and produces an AuthorizeRequester object that can be stored
func (f *Fosite) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (requester AuthorizeRequester, err error) {
	request := NewAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form
	request.State = request.Form.Get(consts.FormParameterState)

	var client Client

	// Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749]).
	if client, _, err = f.AuthenticateClient(ctx, r, r.Form); err != nil {
		var rfcerr *RFC6749Error
		if errors.As(err, &rfcerr) && rfcerr.ErrorField != ErrInvalidClient.ErrorField {
			return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebugError(err))
		}

		return request, err
	}

	request.Client = client

	// Reject the request if the "request_uri" authorization request parameter is provided.
	if r.Form.Get(consts.FormParameterRequestURI) != "" {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The request must not contain 'request_uri'."))
	}

	// For private_key_jwt or basic auth client authentication, "client_id" may not be inside the form.
	// However this is required by NewAuthorizeRequest implementation.
	if len(r.Form.Get(consts.ClaimClientIdentifier)) == 0 {
		r.Form.Set(consts.ClaimClientIdentifier, client.GetID())
	}

	var frequest AuthorizeRequester

	// Validate as if this is a new authorize request.
	if frequest, err = f.newAuthorizeRequest(ctx, r, true); err != nil {
		return frequest, err
	}

	if frequest.GetRequestedScopes().Has(consts.ScopeOpenID) && r.Form.Get(consts.FormParameterRedirectURI) == "" {
		return frequest, errorsx.WithStack(ErrInvalidRequest.WithHint("Query parameter 'redirect_uri' is required when performing an OpenID Connect flow."))
	}

	if err = f.handlePushedAuthorizeRequestDPoP(ctx, r, frequest); err != nil {
		return frequest, err
	}

	return frequest, nil
}

// handlePushedAuthorizeRequestDPoP implements RFC 9449 Section 10.1 at the pushed authorization request endpoint. A
// client may commit to a DPoP proof-of-possession key either by sending the 'dpop_jkt' parameter or by presenting a
// DPoP proof, and when a proof is presented the authorization server MUST check it and MUST then behave as if its
// public key thumbprint had been supplied via 'dpop_jkt'. It does so by writing the thumbprint into the pushed request
// form, which Request.Merge copies onto the authorization request when the 'request_uri' is later redeemed, so the
// binding reaches rfc9449.AuthorizeHandler by the same route as a directly supplied 'dpop_jkt'.
//
// This lives here rather than in a pushed authorize endpoint handler because the proof arrives in an HTTP header and
// NewPushedAuthorizeResponse, where those handlers run, is not given the request.
func (f *Fosite) handlePushedAuthorizeRequestDPoP(ctx context.Context, r *http.Request, request AuthorizeRequester) (err error) {
	if !f.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	strategy := f.Config.GetDPoPStrategy(ctx)
	if strategy == nil {
		return nil
	}

	// Validated here as well as at the authorization endpoint so a malformed value is reported against the request
	// that supplied it, rather than surfacing later as a redirect borne error against the redeemed 'request_uri'.
	if jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT); jkt != "" && !IsValidDPoPJWKThumbprint(jkt) {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is %d characters long.", DPoPJWKThumbprintLength))
	}

	// RFC 9449 Section 4.3 step 1.
	if len(r.Header.Values(consts.HeaderDPoP)) > 1 {
		return errorsx.WithStack(ErrInvalidDPoPProof.WithHint("The request contains more than one DPoP proof but only one is allowed."))
	}

	proof := r.Header.Get(consts.HeaderDPoP)
	if proof == "" {
		// A bare 'dpop_jkt' without a proof is legitimate; it is carried through to the authorization request as sent.
		return nil
	}

	var parsed *DPoPProof

	if parsed, err = strategy.ValidateDPoPProof(ctx, r.Method, RequestURL(r), proof, f.Config.GetDPoPNonceRequired(ctx)); err != nil {
		return err
	}

	// RFC 9449 Section 10.1: when both are supplied the request MUST be rejected unless they agree, otherwise the
	// authorization code would be bound to a key the client did not prove possession of.
	if jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT); jkt != "" && jkt != parsed.Thumbprint {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'dpop_jkt' parameter does not match the thumbprint of the public key in the DPoP proof."))
	}

	request.GetRequestForm().Set(consts.FormParameterDPoPJKT, parsed.Thumbprint)

	return nil
}
