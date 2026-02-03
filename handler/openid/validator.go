// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

var defaultPrompts = []string{
	consts.PromptTypeLogin,
	consts.PromptTypeNone,
	consts.PromptTypeConsent,
	consts.PromptTypeSelectAccount,
}

type OpenIDConnectRequestValidatorConfigProvider interface {
	oauth2.RedirectSecureCheckerProvider
	oauth2.AllowedPromptsProvider
	oauth2.ClockConfigProvider
}

type OpenIDConnectRequestValidator struct {
	Strategy jwt.Strategy
	Config   OpenIDConnectRequestValidatorConfigProvider
}

func NewOpenIDConnectRequestValidator(strategy jwt.Strategy, config OpenIDConnectRequestValidatorConfigProvider) *OpenIDConnectRequestValidator {
	return &OpenIDConnectRequestValidator{
		Strategy: strategy,
		Config:   config,
	}
}

func (v *OpenIDConnectRequestValidator) ValidateRedirectURIs(ctx context.Context, requester oauth2.AuthorizeRequester) (err error) {
	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if requester.GetRedirectURI() == nil || len(requester.GetRequestForm().Get(consts.FormParameterRedirectURI)) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	return nil
}

// ValidatePrompt ensures the prompt is valid for the OpenID Connect 1.0 Flows.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (v *OpenIDConnectRequestValidator) ValidatePrompt(ctx context.Context, requester oauth2.AuthorizeRequester) (session Session, err error) {
	// Specification Note: prompt is case-sensitive.
	requiredPrompt := oauth2.RemoveEmpty(strings.Split(requester.GetRequestForm().Get(consts.FormParameterPrompt), " "))

	if requester.GetClient().IsPublic() {
		// Threat: Malicious Client Obtains Existing Authorization by Fraud
		// https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.3
		//
		//  Authorization servers should not automatically process repeat
		//  authorizations to public clients unless the client is validated
		//  using a pre-registered redirect URI

		// Client Impersonation
		// https://datatracker.ietf.org/doc/html/rfc8252#section-8.6#
		//
		//  As stated in Section 10.2 of OAuth 2.0 [RFC6749], the authorization
		//  server SHOULD NOT process authorization requests automatically
		//  without user consent or interaction, except when the identity of the
		//  client can be assured.  This includes the case where the user has
		//  previously approved an authorization request for a given client id --
		//  unless the identity of the client can be proven, the request SHOULD
		//  be processed as if no previous request had been approved.

		checker := v.Config.GetRedirectSecureChecker(ctx)
		if stringslice.Has(requiredPrompt, consts.PromptTypeNone) {
			if !checker(ctx, requester.GetRedirectURI()) {
				return nil, errorsx.WithStack(oauth2.ErrConsentRequired.WithHint("OAuth 2.0 Client is marked public and redirect uri is not considered secure (https missing), but 'prompt' type 'none' was requested."))
			}
		}
	}

	availablePrompts := v.Config.GetAllowedPrompts(ctx)
	if len(availablePrompts) == 0 {
		availablePrompts = defaultPrompts
	}

	if !isWhitelisted(requiredPrompt, availablePrompts) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The requested prompt value '%s' either contains unknown, unsupported, or prohibited prompt values.", strings.Join(requiredPrompt, " ")).WithDebugf("The permitted prompt values are '%s'.", strings.Join(availablePrompts, "', '")))
	}

	if stringslice.Has(requiredPrompt, consts.PromptTypeNone) && len(requiredPrompt) > 1 {
		// If this parameter contains none with any other value, an error is returned.
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
	}

	maxAge, err := strconv.ParseInt(requester.GetRequestForm().Get(consts.FormParameterMaximumAge), 10, 64)
	if err != nil {
		maxAge = 0
	}

	session, ok := requester.GetSession().(Session)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because the session is not of type 'openid.Session' which is required."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because the session subject is empty."))
	}

	// Adds a bit of wiggle room for timing issues
	if claims.GetAuthTimeSafe().After(v.Config.GetClock(ctx).Now().UTC().Add(time.Second * 5)) {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because authentication time is in the future."))
	}

	rat := session.GetRequestedAt()

	if maxAge > 0 {
		switch {
		case claims.AuthTime == nil, claims.AuthTime.IsZero():
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when max_age is set."))
		case rat.IsZero():
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at claim is required when max_age is set."))
		case claims.GetAuthTimeSafe().Add(time.Second * time.Duration(maxAge)).Before(rat):
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithDebug("Failed to validate OpenID Connect request because authentication time does not satisfy max_age time."))
		}
	}

	if stringslice.Has(requiredPrompt, consts.PromptTypeNone) {
		if claims.AuthTime == nil || claims.AuthTime.IsZero() {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because because auth_time is missing from session."))
		}

		if !claims.GetAuthTimeSafe().Equal(rat) && claims.GetAuthTimeSafe().After(rat) {
			// !claims.AuthTime.Truncate(time.Second).Equal(claims.RequestedAt) && claims.AuthTime.Truncate(time.Second).Before(claims.RequestedAt) {
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('%s') happened after the authorization request ('%s') was registered, indicating that the user was logged in during this request which is not allowed.", claims.GetAuthTimeSafe(), rat))
		}
	}

	if stringslice.Has(requiredPrompt, consts.PromptTypeLogin) {
		if claims.GetAuthTimeSafe().Before(rat) {
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('%s') happened before the authorization request ('%s') was registered, indicating that the user was not re-authenticated which is forbidden.", claims.GetAuthTimeSafe(), rat))
		}
	}

	idTokenHint := requester.GetRequestForm().Get(consts.FormParameterIDTokenHint)
	if idTokenHint == "" {
		return session, nil
	}

	var tokenHint *jwt.Token

	tokenHint, err = v.Strategy.Decode(ctx, idTokenHint, jwt.WithIDTokenClient(requester.GetClient()))

	var ve *jwt.ValidationError
	if errors.As(err, &ve) && ve.Has(jwt.ValidationErrorExpired) {
		// Expired tokens are ok
	} else if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request as decoding ID Token from id_token_hint parameter failed.").WithWrap(err).WithDebugError(err))
	}

	var subHint string

	if subHint, err = tokenHint.Claims.GetSubject(); subHint == "" || err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request because provided ID Token from id_token_hint does not have a subject."))
	} else if subHint != claims.Subject {
		return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHint("Failed to validate OpenID Connect request because the subject from provided ID Token from id_token_hint does not match the current session's subject."))
	}

	return session, nil
}

func isWhitelisted(items []string, whiteList []string) bool {
	for _, item := range items {
		if !stringslice.Has(whiteList, item) {
			return false
		}
	}
	return true
}
