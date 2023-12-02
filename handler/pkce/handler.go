// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"regexp"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
)

var _ goauth2.TokenEndpointHandler = (*Handler)(nil)

type Handler struct {
	AuthorizeCodeStrategy oauth2.AuthorizeCodeStrategy
	Storage               PKCERequestStorage
	Config                interface {
		goauth2.EnforcePKCEProvider
		goauth2.EnforcePKCEForPublicClientsProvider
		goauth2.EnablePKCEPlainChallengeMethodProvider
	}
}

var _ goauth2.TokenEndpointHandler = (*Handler)(nil)

var verifierWrongFormat = regexp.MustCompile(`[^\w.~-]`)

func (c *Handler) HandleAuthorizeEndpointRequest(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Has("code") {
		return nil
	}

	challenge := ar.GetRequestForm().Get("code_challenge")
	method := ar.GetRequestForm().Get("code_challenge_method")
	client := ar.GetClient()

	if err := c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	code := resp.GetCode()
	if len(code) == 0 {
		return errorsx.WithStack(goauth2.ErrServerError.WithDebug("The PKCE handler must be loaded after the authorize code handler."))
	}

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	if err := c.Storage.CreatePKCERequestSession(ctx, signature, ar.Sanitize([]string{
		"code_challenge",
		"code_challenge_method",
	})); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *Handler) validate(ctx context.Context, challenge, method string, client goauth2.Client) error {
	if challenge == "" {
		// If the server requires Proof Key for Code Exchange (PKCE) by OAuth
		// clients and the client does not send the "code_challenge" in
		// the request, the authorization endpoint MUST return the authorization
		// error response with the "error" value set to "invalid_request".  The
		// "error_description" or the response of "error_uri" SHOULD explain the
		// nature of error, e.g., code challenge required.
		if c.Config.GetEnforcePKCE(ctx) {
			return errorsx.WithStack(goauth2.ErrInvalidRequest.
				WithHint("Clients must include a code_challenge when performing the authorize code flow, but it is missing.").
				WithDebug("The server is configured in a way that enforces PKCE for clients."))
		}
		if c.Config.GetEnforcePKCEForPublicClients(ctx) && client.IsPublic() {
			return errorsx.WithStack(goauth2.ErrInvalidRequest.
				WithHint("This client must include a code_challenge when performing the authorize code flow, but it is missing.").
				WithDebug("The server is configured in a way that enforces PKCE for this client."))
		}
		return nil
	}

	// If the server supporting PKCE does not support the requested
	// transformation, the authorization endpoint MUST return the
	// authorization error response with "error" value set to
	// "invalid_request".  The "error_description" or the response of
	// "error_uri" SHOULD explain the nature of error, e.g., transform
	// algorithm not supported.
	switch method {
	case "S256":
		break
	case "plain":
		fallthrough
	case "":
		if !c.Config.GetEnablePKCEPlainChallengeMethod(ctx) {
			return errorsx.WithStack(goauth2.ErrInvalidRequest.
				WithHint("Clients must use code_challenge_method=S256, plain is not allowed.").
				WithDebug("The server is configured in a way that enforces PKCE S256 as challenge method for clients."))
		}
	default:
		return errorsx.WithStack(goauth2.ErrInvalidRequest.
			WithHint("The code_challenge_method is not supported, use S256 instead."))
	}
	return nil
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	// code_verifier
	// REQUIRED.  Code verifier
	//
	// The "code_challenge_method" is bound to the Authorization Code when
	// the Authorization Code is issued.  That is the method that the token
	// endpoint MUST use to verify the "code_verifier".
	verifier := request.GetRequestForm().Get("code_verifier")

	code := request.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.Storage.GetPKCERequestSession(ctx, signature, request.GetSession())
	if errors.Is(err, goauth2.ErrNotFound) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("Unable to find initial PKCE data tied to this request").WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := c.Storage.DeletePKCERequestSession(ctx, signature); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	challenge := authorizeRequest.GetRequestForm().Get("code_challenge")
	method := authorizeRequest.GetRequestForm().Get("code_challenge_method")
	client := authorizeRequest.GetClient()
	if err := c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	if !c.Config.GetEnforcePKCE(ctx) && challenge == "" && verifier == "" {
		return nil
	}

	// NOTE: The code verifier SHOULD have enough entropy to make it
	// 	impractical to guess the value.  It is RECOMMENDED that the output of
	// 	a suitable random number generator be used to create a 32-octet
	// 	sequence.  The octet sequence is then base64url-encoded to produce a
	// 	43-octet URL safe string to use as the code verifier.

	// Validation
	if len(verifier) < 43 {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier must be at least 43 characters."))
	} else if len(verifier) > 128 {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The PKCE code verifier can not be longer than 128 characters."))
	} else if verifierWrongFormat.MatchString(verifier) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
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
	case "S256":
		hash := sha256.New()
		if _, err := hash.Write([]byte(verifier)); err != nil {
			return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		if base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{})) != challenge {
			return errorsx.WithStack(goauth2.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	case "plain":
		fallthrough
	default:
		if verifier != challenge {
			return errorsx.WithStack(goauth2.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	}

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester goauth2.AccessRequester, responder goauth2.AccessResponder) error {
	return nil
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
