// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type openIDConnectRequestValidatorConfigProvider interface {
	oauth2.AllowedPromptsProvider
	oauth2.IssuerProvider
}

// OpenIDConnectRequestValidator validates the OpenID Connect parameters of authorization requests.
type OpenIDConnectRequestValidator struct {
	Strategy jwt.Strategy
	Config   openIDConnectRequestValidatorConfigProvider
}

// NewOpenIDConnectRequestValidator returns an OpenIDConnectRequestValidator using the given strategy and config.
func NewOpenIDConnectRequestValidator(strategy jwt.Strategy, config openIDConnectRequestValidatorConfigProvider) *OpenIDConnectRequestValidator {
	return &OpenIDConnectRequestValidator{
		Strategy: strategy,
		Config:   config,
	}
}

func (v *OpenIDConnectRequestValidator) getPublicClientIdentityChecker(ctx context.Context) (checker func(context.Context, oauth2.AuthorizeRequester) bool) {
	if provider, ok := v.Config.(oauth2.PublicClientIdentityCheckerProvider); ok {
		if checker = provider.GetPublicClientIdentityChecker(ctx); checker != nil {
			return checker
		}
	}

	return oauth2.IsPublicClientIdentityAssured
}

// ValidateRedirectURIs returns an error when the authorize request has no 'redirect_uri' parameter, which OpenID
// Connect 1.0 requires.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func (v *OpenIDConnectRequestValidator) ValidateRedirectURIs(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if request.GetRedirectURI() == nil || len(request.GetRequestForm().Get(consts.FormParameterRedirectURI)) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	return nil
}

// ValidateClaims enforces the requirements the 'claims' request parameter places on the authorization server. It does
// nothing unless the config enables the enforcement.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
func (v *OpenIDConnectRequestValidator) ValidateClaims(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	if !isClaimsParameterEnforced(ctx, v.Config) {
		return nil
	}

	claims := request.GetClaims()
	if claims == nil {
		return nil
	}

	// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
	if claims.UserInfo != nil && !request.GetResponseTypes().HasOneOf(consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'claims' parameter member 'userinfo' requires a 'response_type' which results in an Access Token being issued."))
	}

	session, ok := request.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because the session is not of type 'openid.Session' which is required."))
	}

	actual := session.IDTokenClaims()

	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
	if sub := claims.IDToken[consts.ClaimSubject]; sub.HasValues() && !sub.Matches(actual.Subject) {
		return errorsx.WithStack(oauth2.ErrLoginRequired.WithHint("The subject requested by the 'claims' parameter does not match the current session's subject."))
	}

	// See: https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
	if acr := claims.IDToken[consts.ClaimAuthenticationContextClassReference]; acr != nil && acr.Essential && acr.HasValues() {
		if actual.AuthenticationContextClassReference == "" || !acr.Matches(actual.AuthenticationContextClassReference) {
			return errorsx.WithStack(oauth2.ErrUnmetAuthenticationRequirements.WithHint("The Authentication Context Class Reference requested as an Essential Claim by the 'claims' parameter was not met."))
		}
	}

	// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	if isAuthTimeEssential(request) && isAuthTimeUnknown(actual) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when the 'claims' parameter requests it as an Essential Claim."))
	}

	return nil
}

// ValidatePrompt ensures the prompt is valid for the OpenID Connect 1.0 Flows.
func (v *OpenIDConnectRequestValidator) ValidatePrompt(ctx context.Context, request oauth2.AuthorizeRequester) (session Session, err error) {
	if err = v.validatePromptParameters(ctx, request); err != nil {
		return nil, err
	}

	return v.ValidateSession(ctx, request)
}

// ValidateSession ensures the End-User authentication recorded on the session of the request meets the request: the
// session has a subject, an 'auth_time' when the client registered 'require_auth_time', an 'auth_time' within the
// 'max_age' parameter or the 'default_max_age' of the client, an 'auth_time' the 'prompt' parameter values 'none' and
// 'login' allow, and the subject of the 'id_token_hint' parameter. It reads nothing specific to the authorization
// endpoint, so it applies to any request an End-User approves. A 'max_age' which is not a non-negative integer is
// refused with oauth2.ErrInvalidRequest. The 'max_age' and the 'prompt' values 'none' and 'login' are measured from the
// requested at time of the session, and a session without one is refused with oauth2.ErrServerError.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
//
//nolint:gocyclo
func (v *OpenIDConnectRequestValidator) ValidateSession(ctx context.Context, request oauth2.Requester) (session Session, err error) {
	// Specification Note: prompt is case-sensitive.
	requiredPrompt := oauth2.RemoveEmpty(strings.Split(request.GetRequestForm().Get(consts.FormParameterPrompt), " "))

	maxAge, hasMaxAge, err := oauth2.GetRequestedMaxAge(request)
	if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'max_age' must be a non-negative integer.").WithWrap(err).WithDebugError(err))
	}

	session, ok := request.GetSession().(Session)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because the session is not of type 'openid.Session' which is required."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because the session subject is empty."))
	}

	// Adds a bit of wiggle room for timing issues.
	if claims.GetAuthTimeSafe().After(time.Now().UTC().Add(time.Second * 5)) {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect 1.0 request because authentication time is in the future."))
	}

	// The auth_time claim has jwt.TimePrecision, so the request time is compared at the same precision.
	rat := session.GetRequestedAt().Truncate(jwt.TimePrecision)

	if isAuthTimeRequired(request.GetClient()) && (claims.AuthTime == nil || claims.AuthTime.IsZero()) {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when the client registered require_auth_time."))
	}

	if hasMaxAge {
		switch {
		case claims.AuthTime == nil, claims.AuthTime.IsZero():
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when max_age is set."))
		case rat.IsZero():
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at claim is required when max_age is set."))
		case !oauth2.IsAuthenticationWithinMaxAge(claims.GetAuthTimeSafe(), rat, maxAge):
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithDebug("Failed to validate OpenID Connect request because authentication time does not satisfy max_age time."))
		}
	}

	if slices.Contains(requiredPrompt, consts.PromptTypeNone) {
		if claims.AuthTime == nil || claims.AuthTime.IsZero() {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because because auth_time is missing from session."))
		}

		if rat.IsZero() {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at value is required when prompt is set to 'none'."))
		}

		if !claims.GetAuthTimeSafe().Equal(rat) && claims.GetAuthTimeSafe().After(rat) {
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('%s') happened after the authorization request ('%s') was registered, indicating that the user was logged in during this request which is not allowed.", claims.GetAuthTimeSafe(), rat))
		}
	}

	if slices.Contains(requiredPrompt, consts.PromptTypeLogin) {
		if rat.IsZero() {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at value is required when prompt is set to 'login'."))
		}

		if claims.GetAuthTimeSafe().Before(rat) {
			return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('%s') happened before the authorization request ('%s') was registered, indicating that the user was not re-authenticated which is forbidden.", claims.GetAuthTimeSafe(), rat))
		}
	}

	if request.GetRequestForm().Get(consts.FormParameterIDTokenHint) == "" {
		return session, nil
	}

	var subHint string

	if subHint, err = v.getIDTokenHintSubject(ctx, request); err != nil {
		return nil, err
	} else if subHint != claims.Subject {
		return nil, errorsx.WithStack(oauth2.ErrLoginRequired.WithHint("Failed to validate OpenID Connect request because the subject from provided ID Token from id_token_hint does not match the current session's subject."))
	}

	return session, nil
}

func (v *OpenIDConnectRequestValidator) getIDTokenHintSubject(ctx context.Context, request oauth2.Requester) (subject string, err error) {
	if subject, err = validateIDTokenHint(ctx, v.Strategy, v.Config, v.Config.GetIssuer(ctx), request.GetClient(), request.GetRequestForm().Get(consts.FormParameterIDTokenHint)); err != nil {
		return "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request as the ID Token from the id_token_hint parameter is not valid.").WithWrap(err).WithDebugError(err))
	}

	return subject, nil
}

func (v *OpenIDConnectRequestValidator) validatePromptParameters(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	var requiredPrompt []string

	if requiredPrompt, err = v.validatePromptValues(ctx, request); err != nil {
		return err
	}

	if request.GetClient().IsPublic() {
		// Threat: Malicious Client Obtains Existing Authorization by Fraud
		// https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.3
		//
		//  Authorization servers should not automatically process repeat
		//  authorizations to public clients unless the client is validated
		//  using a pre-registered redirect URI

		// Client Impersonation: a request is not processed without user interaction unless the client's identity is
		// assured.
		// See: https://datatracker.ietf.org/doc/html/rfc8252#section-8.6
		if slices.Contains(requiredPrompt, consts.PromptTypeNone) && !v.getPublicClientIdentityChecker(ctx)(ctx, request) {
			return errorsx.WithStack(oauth2.ErrConsentRequired.WithHint("OAuth 2.0 Client is marked public and the redirect uri does not assure the identity of the client, but 'prompt' type 'none' was requested."))
		}
	}

	return validateMaxAge(request)
}

func (v *OpenIDConnectRequestValidator) validatePromptValues(ctx context.Context, request oauth2.Requester) (requiredPrompt []string, err error) {
	// Specification Note: prompt is case-sensitive.
	requiredPrompt = oauth2.RemoveEmpty(strings.Split(request.GetRequestForm().Get(consts.FormParameterPrompt), " "))

	availablePrompts := oauth2.SupportedPromptValues(ctx, v.Config)

	if !isWhitelisted(requiredPrompt, availablePrompts) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'prompt' parameter either contains unknown, unsupported, or prohibited prompt values.").WithDebugf("The requested prompt value '%s' is not permitted, the permitted prompt values are '%s'.", strings.Join(requiredPrompt, " "), strings.Join(availablePrompts, "', '")))
	}

	if slices.Contains(requiredPrompt, consts.PromptTypeNone) && len(requiredPrompt) > 1 {
		// If this parameter contains none with any other value, an error is returned.
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
	}

	return requiredPrompt, nil
}

// ValidateParameters returns an error when the 'prompt', 'max_age' or 'id_token_hint' parameter of a request which is
// not made at the authorization endpoint is malformed: an unknown 'prompt' value, the 'prompt' value 'none' with any
// other value, a 'max_age' which is not a non-negative integer, or an 'id_token_hint' which cannot be decoded as an ID
// Token of the client or has no subject. It does not read the session.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func (v *OpenIDConnectRequestValidator) ValidateParameters(ctx context.Context, request oauth2.Requester) (err error) {
	if _, err = v.validatePromptValues(ctx, request); err != nil {
		return err
	}

	if err = validateMaxAge(request); err != nil {
		return err
	}

	if request.GetRequestForm().Get(consts.FormParameterIDTokenHint) == "" {
		return nil
	}

	_, err = v.getIDTokenHintSubject(ctx, request)

	return err
}

func validateMaxAge(request oauth2.Requester) (err error) {
	if _, _, err = oauth2.GetRequestedMaxAge(request); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'max_age' must be a non-negative integer.").WithWrap(err).WithDebugError(err))
	}

	return nil
}

func isWhitelisted(items []string, whiteList []string) bool {
	for _, item := range items {
		if !slices.Contains(whiteList, item) {
			return false
		}
	}

	return true
}
