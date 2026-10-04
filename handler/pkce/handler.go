// SPDX-FileCopyrightText: 2026 Authelia
//
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

// HandleAuthorizeEndpointRequest handles an authorize request whose 'response_type' includes 'code'. It validates the
// 'code_challenge' and 'code_challenge_method' parameters against the configuration and the client, and when a
// challenge is present persists it under the signature of the authorization code, which must already have been issued.
func (c *Handler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	challenge := request.GetRequestForm().Get(consts.FormParameterCodeChallenge)
	method := request.GetRequestForm().Get(consts.FormParameterCodeChallengeMethod)

	client := request.GetClient()

	if err = c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	if len(challenge) == 0 {
		if len(method) != 0 {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithDebug("The client requested PKCE but no challenge was provided in the authorize request."))
		}

		return nil
	}

	if err = validateChallengeSyntax(challenge, method); err != nil {
		return err
	}

	code := response.GetCode()

	if len(code) == 0 {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The PKCE handler must be loaded after the authorize code handler."))
	}

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)

	if err = c.Storage.CreatePKCERequestSession(ctx, signature, request.Sanitize([]string{
		consts.FormParameterCodeChallenge,
		consts.FormParameterCodeChallengeMethod,
	})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Error occurred attempting create PKCE request session: %s.", err.Error()))
	}

	return nil
}

func validateChallengeSyntax(challenge, method string) (err error) {
	switch n := len(challenge); {
	case n < 43:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The PKCE code challenge must be at least 43 characters."))
	case n > 128:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The PKCE code challenge must be no more than 128 characters."))
	case verifierWrongFormat.MatchString(challenge):
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The PKCE code challenge must only contain [a-Z], [0-9], '-', '.', '_', '~'."))
	}

	if method == consts.PKCEChallengeMethodSHA256 {
		if digest, err := base64.RawURLEncoding.Strict().DecodeString(challenge); err != nil || len(digest) != sha256.Size {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The PKCE code challenge for method 'S256' must be the base64url encoding of a SHA-256 hash without padding."))
		}
	}

	return nil
}

func (c *Handler) validate(ctx context.Context, challenge, method string, client oauth2.Client) (err error) {
	if len(challenge) == 0 {
		// A missing 'code_challenge' is 'invalid_request' when PKCE is required.
		// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1
		return c.validateNoPKCE(ctx, consts.FormParameterCodeChallenge, client)
	}

	// An unsupported transformation is 'invalid_request'.
	// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1
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
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Authorization was requested with 'code_challenge_method' value '%s', but the authorization server doesn't know how to handle this method, try 'S256' instead.", method))
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
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	// The method bound to the authorization code when it was issued verifies the 'code_verifier'.
	// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.5
	verifier := request.GetRequestForm().Get(consts.FormParameterCodeVerifier)

	nv := len(verifier)

	code := request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)

	var requesterPKCE oauth2.Requester

	if requesterPKCE, err = c.Storage.GetPKCERequestSession(ctx, signature, request.GetSession()); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			if nv == 0 {
				return c.validateNoPKCE(ctx, consts.FormParameterCodeVerifier, request.GetClient())
			}

			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to find initial PKCE data tied to this request.").WithWrap(err).WithDebugError(err))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(fmt.Errorf("Error occurred attempting get PKCE request session: %w.", err)))
	}

	challenge := requesterPKCE.GetRequestForm().Get(consts.FormParameterCodeChallenge)
	method := requesterPKCE.GetRequestForm().Get(consts.FormParameterCodeChallengeMethod)

	if err = c.validate(ctx, challenge, method, request.GetClient()); err != nil {
		return err
	}

	if err = c.validate(ctx, challenge, method, requesterPKCE.GetClient()); err != nil {
		return err
	}

	nc := len(challenge)

	if !c.Config.GetEnforcePKCE(ctx) && nc == 0 && nv == 0 {
		return nil
	}

	// The code verifier must have enough entropy to make it impractical to guess.
	// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.1

	// Validation
	switch {
	case nv < 43:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code verifier must be at least 43 characters."))
	case nv > 128:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code verifier must be no more than 128 characters."))
	case nc == 0:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code verifier was provided but the code challenge was absent from the authorization request."))
	case verifierWrongFormat.MatchString(verifier):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'."))
	}

	// Verify the 'code_verifier' against the stored 'code_challenge' using the stored method; a mismatch is
	// 'invalid_grant'.
	// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.6
	switch method {
	case consts.PKCEChallengeMethodSHA256:
		sum := sha256.Sum256([]byte(verifier))

		expected := make([]byte, base64.RawURLEncoding.EncodedLen(len(sum)))

		base64.RawURLEncoding.Strict().Encode(expected, sum[:])

		if subtle.ConstantTimeCompare(expected, []byte(challenge)) == 0 {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code challenge did not match the code verifier."))
		}
	case consts.PKCEChallengeMethodPlain:
		fallthrough
	default:
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 0 {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The PKCE code challenge did not match the code verifier."))
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements oauth2.TokenEndpointHandler. The PKCE request session is removed only once
// the request has been accepted, as removing it while the authorization code is still redeemable would let the code
// be redeemed without the 'code_verifier' RFC 7636 Section 4.6 requires.
//
// This handler must be registered after the authorization code grant handler, as compose.ComposeAllEnabled does, so
// the authorization code is invalidated before the PKCE request session is removed. A configuration which supplies
// its own token endpoint handlers or factory order must preserve this order. As the authorization code is already
// invalidated, a failure to remove the PKCE request session does not fail the request.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, request.GetRequestForm().Get(consts.FormParameterAuthorizationCode))

	_ = c.Storage.DeletePKCERequestSession(ctx, signature)

	return nil
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *Handler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'authorization_code'.
func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeAuthorizationCode)
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
