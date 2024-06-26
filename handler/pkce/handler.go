// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type Handler struct {
	AuthorizeCodeStrategy hoauth2.AuthorizeCodeStrategy
	Storage               Storage
	Config                interface {
		oauth2.EnforcePKCEProvider
		oauth2.EnforcePKCEForPublicClientsProvider
		oauth2.EnablePKCEPlainChallengeMethodProvider
	}
}

func (c *Handler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) (err error) {
	// This let's us define multiple response types, for example the OpenID Connect 1.0 `id_token`.
	if !requester.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	challenge := requester.GetRequestForm().Get(consts.FormParameterCodeChallenge)
	method := requester.GetRequestForm().Get(consts.FormParameterCodeChallengeMethod)
	client := requester.GetClient()

	if err = c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	// We don't need a session if it's not enforced and the PKCE parameters are not provided by the client.
	if len(challenge) == 0 && len(method) == 0 {
		return nil
	}

	code := responder.GetCode()

	if len(code) == 0 {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The PKCE handler must be loaded after the authorize code handler."))
	}

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)

	if err = c.Storage.CreatePKCERequestSession(ctx, signature, requester.Sanitize([]string{
		consts.FormParameterCodeChallenge,
		consts.FormParameterCodeChallengeMethod,
	})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(fmt.Errorf("Error occurred attempting create PKCE request session: %w.", err)))
	}

	return nil
}

func (c *Handler) validate(ctx context.Context, challenge, method string, client oauth2.Client) (err error) {
	if len(challenge) == 0 {
		// If the server requires Proof Key for Code Exchange (PKCE) by OAuth
		// clients and the client does not send the "code_challenge" in
		// the request, the authorization endpoint MUST return the authorization
		// error response with the "error" value set to "invalid_request".  The
		// "error_description" or the response of "error_uri" SHOULD explain the
		// nature of error, e.g., code challenge required.
		return c.validateNoPKCE(ctx, consts.FormParameterCodeChallenge, client)
	}

	// If the server supporting PKCE does not support the requested
	// transformation, the authorization endpoint MUST return the
	// authorization error response with "error" value set to
	// "invalid_request".  The "error_description" or the response of
	// "error_uri" SHOULD explain the nature of error, e.g., transform
	// algorithm not supported.
	switch method {
	case consts.PKCEChallengeMethodSHA256:
		break
	case "":
		fallthrough
	case consts.PKCEChallengeMethodPlain:
		if !c.Config.GetEnablePKCEPlainChallengeMethod(ctx) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.
				WithHint("Authorization was requested with 'code_challenge_method' value 'plain', but the authorization server policy does not allow method 'plain' and requires method 'S256'.").
				WithDebug("The authorization server is configured in a way that enforces the 'S256' PKCE 'code_challenge_method' for all clients."))
		}
	default:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.
			WithHintf("Authorization was requested with 'code_challenge_method' value '%s', but the authorization server doesn't know how to handle this method, try 'S256' instead.", method))
	}

	if pkce, ok := client.(oauth2.ProofKeyCodeExchangeClient); ok {
		if pkce.GetEnforcePKCEChallengeMethod() && method != pkce.GetPKCEChallengeMethod() {
			switch cmethod := pkce.GetPKCEChallengeMethod(); {
			case method == cmethod, method == "" && cmethod == consts.PKCEChallengeMethodPlain:
				break
			default:
				return errorsx.WithStack(oauth2.ErrInvalidRequest.
					WithHintf("Authorization was requested with 'code_challenge_method' value '%s', but the authorization server policy does not allow method '%s' and requires method '%s'.", method, method, pkce.GetPKCEChallengeMethod()).
					WithDebugf("The registered client with id '%s' is configured in a way that enforces the use of 'code_challenge_method' with a value of '%s' but the authorization request included method '%s'.", client.GetID(), cmethod, method))
			}
		}
	}

	return nil
}

// HandleTokenEndpointRequest implements oauth2.TokenEndpointHandler.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	// code_verifier
	// REQUIRED.  Code verifier
	//
	// The "code_challenge_method" is bound to the Authorization Code when
	// the Authorization Code is issued.  That is the method that the token
	// endpoint MUST use to verify the "code_verifier".
	verifier := requester.GetRequestForm().Get(consts.FormParameterCodeVerifier)

	nv := len(verifier)

	code := requester.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)

	var requesterPKCE oauth2.Requester

	if requesterPKCE, err = c.Storage.GetPKCERequestSession(ctx, signature, requester.GetSession()); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			if nv == 0 {
				return c.validateNoPKCE(ctx, consts.FormParameterCodeVerifier, requester.GetClient())
			}

			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to find initial PKCE data tied to this request.").WithWrap(err).WithDebugError(err))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(fmt.Errorf("Error occurred attempting get PKCE request session: %w.", err)))
	}

	if err = c.Storage.DeletePKCERequestSession(ctx, signature); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(fmt.Errorf("Error occurred attempting delete PKCE request session: %w.", err)))
	}

	challenge := requesterPKCE.GetRequestForm().Get(consts.FormParameterCodeChallenge)
	method := requesterPKCE.GetRequestForm().Get(consts.FormParameterCodeChallengeMethod)

	if err = c.validate(ctx, challenge, method, requester.GetClient()); err != nil {
		return err
	}

	if err = c.validate(ctx, challenge, method, requesterPKCE.GetClient()); err != nil {
		return err
	}

	nc := len(challenge)

	if !c.Config.GetEnforcePKCE(ctx) && nc == 0 && nv == 0 {
		return nil
	}

	// NOTE: The code verifier SHOULD have enough entropy to make it
	// 	impractical to guess the value.  It is RECOMMENDED that the output of
	// 	a suitable random number generator be used to create a 32-octet
	// 	sequence.  The octet sequence is then base64url-encoded to produce a
	// 	43-octet URL safe string to use as the code verifier.

	// Validation
	switch {
	case nv < 43:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier must be at least 43 characters."))
	case nv > 128:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier must be no more than 128 characters."))
	case nc == 0:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier was provided but the code challenge was absent from the authorization request."))
	case verifierWrongFormat.MatchString(verifier):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'."))
	}

	// Upon receipt of the request at the token endpoint, the server
	// verifies it by calculating the code challenge from the received
	// "code_verifier" and comparing it with the previously associated
	// "code_challenge", after first transforming it according to the
	// "code_challenge_method" method specified by the client.
	//
	// 	If the "code_challenge_method" from Section 4.3 was "S256", the
	// received "code_verifier" is hashed by SHA-256, base64url-encoded, and
	// then compared to the "code_challenge", i.e.:
	//
	// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
	//
	// If the "code_challenge_method" from Section 4.3 was "plain", they are
	// compared directly, i.e.:
	//
	// code_verifier == code_challenge.
	//
	// 	If the values are equal, the token endpoint MUST continue processing
	// as normal (as defined by OAuth 2.0 [RFC6749]).  If the values are not
	// equal, an error response indicating "invalid_grant" as described in
	// Section 5.2 of [RFC6749] MUST be returned.
	switch method {
	case consts.PKCEChallengeMethodSHA256:
		sum := sha256.Sum256([]byte(verifier))

		expected := make([]byte, base64.RawURLEncoding.EncodedLen(len(sum)))

		base64.RawURLEncoding.Strict().Encode(expected, sum[:])

		if subtle.ConstantTimeCompare(expected, []byte(challenge)) == 0 {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	case consts.PKCEChallengeMethodPlain:
		fallthrough
	default:
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 0 {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	}

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	return nil
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) (skip bool) {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) (handle bool) {
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeAuthorizationCode)
}

func (c *Handler) validateNoPKCE(ctx context.Context, parameter string, client oauth2.Client) (err error) {
	if c.Config.GetEnforcePKCE(ctx) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.
			WithHintf("Clients must include a '%s' when performing the authorize code flow, but it is missing.", parameter).
			WithDebug("The authorization server is configured in a way that enforces PKCE for all clients."))
	}

	if c.Config.GetEnforcePKCEForPublicClients(ctx) {
		if client == nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The client for the request wasn't properly loaded."))
		}

		if client.IsPublic() {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.
				WithHintf("Clients must include a '%s' when performing the authorize code flow, but it is missing.", parameter).
				WithDebugf("The authorization server is configured in a way that enforces PKCE for all public client type clients and the '%s' client is using the public client type.", client.GetID()))
		}
	}

	if pkce, ok := client.(oauth2.ProofKeyCodeExchangeClient); ok {
		if pkce.GetEnforcePKCE() {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.
				WithHintf("Clients must include a '%s' when performing the authorize code flow, but it is missing.", parameter).
				WithDebugf("The client with id '%s' is registered in a way that enforces PKCE.", client.GetID()))
		}
	}

	return nil
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*Handler)(nil)
	_ oauth2.TokenEndpointHandler     = (*Handler)(nil)
)
