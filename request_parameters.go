// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ValidateRequestParametersNotRepeated returns ErrInvalidRequest naming the first single-valued request parameter
// interpreted by this library that the form includes more than once. The 'resource' and 'audience' parameters are
// defined as repeatable and are not checked, nor are parameters this library does not interpret.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1, https://www.rfc-editor.org/rfc/rfc6749#section-3.2,
// https://www.rfc-editor.org/rfc/rfc8707#section-2 and https://www.rfc-editor.org/rfc/rfc8693#section-2.1
func ValidateRequestParametersNotRepeated(form url.Values) (err error) {
	return validateRequestParametersNotRepeated(form, singleValuedRequestParameters)
}

// validateRequestQueryAndBodyParametersNotRepeated returns ErrInvalidRequest naming the first single-valued request
// parameter which the query or the body of r includes more than once, or which the parsed form of r includes more times
// than the query and the body together. A parameter both the query and the body include once is not refused, and the
// value of the body is the one used.
func validateRequestQueryAndBodyParametersNotRepeated(r *http.Request) (err error) {
	query := url.Values{}

	if r.URL != nil {
		query = r.URL.Query()
	}

	for _, parameter := range singleValuedRequestParameters {
		inQuery, inBody, inForm := len(query[parameter]), len(r.PostForm[parameter]), len(r.Form[parameter])

		if inQuery > 1 || inBody > 1 || (inForm > 1 && inForm > inQuery+inBody) {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' parameter must not be included more than once.", parameter))
		}
	}

	return nil
}

func validateRequestParametersNotRepeatedWithin(form url.Values, recognized []string) (err error) {
	return validateRequestParametersNotRepeated(form, slices.DeleteFunc(slices.Clone(singleValuedRequestParameters), func(parameter string) bool {
		return !slices.Contains(recognized, parameter)
	}))
}

func validateRequestParametersNotRepeated(form url.Values, parameters []string) (err error) {
	for _, parameter := range parameters {
		if len(form[parameter]) > 1 {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' parameter must not be included more than once.", parameter))
		}
	}

	return nil
}

var authorizeRedirectRequestParameters = []string{
	consts.FormParameterClientID,
	consts.FormParameterRedirectURI,
	consts.FormParameterResponseType,
	consts.FormParameterResponseMode,
	consts.FormParameterState,
	consts.FormParameterRequest,
	consts.FormParameterRequestURI,
}

var singleValuedRequestParameters = append(append([]string{}, authorizeRedirectRequestParameters...),
	consts.FormParameterScope,
	consts.FormParameterNonce,
	consts.FormParameterCodeChallenge,
	consts.FormParameterCodeChallengeMethod,
	consts.FormParameterClaims,
	consts.FormParameterAuthorizationDetails,
	consts.FormParameterRegistration,
	consts.FormParameterPrompt,
	consts.FormParameterMaximumAge,
	consts.FormParameterDisplay,
	consts.FormParameterUILocales,
	consts.FormParameterAuthenticationContextClassReferenceValues,
	consts.FormParameterIDTokenHint,
	consts.FormParameterDPoPJKT,
	consts.FormParameterGrantType,
	consts.FormParameterAuthorizationCode,
	consts.FormParameterCodeVerifier,
	consts.FormParameterRefreshToken,
	consts.FormParameterUsername,
	consts.FormParameterPassword,
	consts.FormParameterAssertion,
	consts.FormParameterClientSecret,
	consts.FormParameterClientAssertion,
	consts.FormParameterClientAssertionType,
	consts.FormParameterDeviceCode,
	consts.FormParameterUserCode,
	consts.FormParameterSubjectToken,
	consts.FormParameterSubjectTokenType,
	consts.FormParameterActorToken,
	consts.FormParameterActorTokenType,
	consts.FormParameterRequestedTokenType,
	consts.FormParameterRequestContext,
	consts.FormParameterRequestDetails,
	consts.FormParameterToken,
	consts.FormParameterTokenTypeHint,
	consts.FormParameterAccessToken,
	consts.FormParameterAuthReqID,
	consts.FormParameterLoginHint,
	consts.FormParameterLoginHintToken,
	consts.FormParameterBindingMessage,
	consts.FormParameterRequestedExpiry,
	consts.FormParameterClientNotificationToken,
	consts.FormParameterLogoutHint,
	consts.FormParameterPostLogoutRedirectURI,
)
