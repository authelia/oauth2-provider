// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// FormParameterState is the state authorization request and response parameter from RFC 6749.
	FormParameterState = "state"
	// FormParameterAuthorizationCode is the code parameter carrying an authorization code, from RFC 6749.
	FormParameterAuthorizationCode = valueCode
	// FormParameterClientID is the client_id parameter from RFC 6749.
	FormParameterClientID = valueClientID
	// FormParameterClientSecret is the client_secret parameter from RFC 6749.
	FormParameterClientSecret = "client_secret"
	// FormParameterRequest is the request authorization request parameter carrying a request object, from OpenID Connect Core 1.0.
	FormParameterRequest = "request"
	// FormParameterRequestURI is the request_uri authorization request parameter from OpenID Connect Core 1.0.
	FormParameterRequestURI = "request_uri"
	// FormParameterRedirectURI is the redirect_uri parameter from RFC 6749.
	FormParameterRedirectURI = "redirect_uri"
	// FormParameterNonce is the nonce authorization request parameter from OpenID Connect Core 1.0.
	FormParameterNonce = valueNonce
	// FormParameterResponse is the response parameter used by JWT Secured Authorization Response Mode (JARM).
	FormParameterResponse = "response"
	// FormParameterResponseMode is the response_mode authorization request parameter from OAuth 2.0 Multiple Response Type Encoding Practices.
	FormParameterResponseMode = "response_mode"
	// FormParameterResponseType is the response_type authorization request parameter from RFC 6749.
	FormParameterResponseType = "response_type"
	// FormParameterCodeChallenge is the code_challenge parameter from RFC 7636.
	FormParameterCodeChallenge = "code_challenge"
	// FormParameterCodeVerifier is the code_verifier parameter from RFC 7636.
	FormParameterCodeVerifier = "code_verifier"
	// FormParameterCodeChallengeMethod is the code_challenge_method parameter from RFC 7636.
	FormParameterCodeChallengeMethod = "code_challenge_method"
	// FormParameterClientAssertionType is the client_assertion_type parameter from RFC 7521.
	FormParameterClientAssertionType = "client_assertion_type"
	// FormParameterClientAssertion is the client_assertion parameter from RFC 7521.
	FormParameterClientAssertion = "client_assertion"
	// FormParameterAssertion is the assertion parameter from RFC 7521.
	FormParameterAssertion = "assertion"
	// FormParameterGrantType is the grant_type parameter from RFC 6749.
	FormParameterGrantType = "grant_type"
	// FormParameterScope is the scope parameter from RFC 6749.
	FormParameterScope = valueScope
	// FormParameterRegistration is the registration parameter from OpenID Connect Core 1.0.
	FormParameterRegistration = "registration"
	// FormParameterAudience is the audience parameter from RFC 8693.
	FormParameterAudience = "audience"
	// FormParameterResource is the resource parameter from RFC 8707.
	FormParameterResource = "resource"
	// FormParameterAuthorizationDetails is the authorization_details parameter from RFC 9396.
	FormParameterAuthorizationDetails = valueAuthorizationDetails
	// FormParameterClaims is the claims authorization request parameter from OpenID Connect Core 1.0.
	FormParameterClaims = "claims"
	// FormParameterRefreshToken is the refresh_token parameter from RFC 6749.
	FormParameterRefreshToken = valueRefreshToken
	// FormParameterIssuer is the iss authorization response parameter from RFC 9207.
	FormParameterIssuer = valueIss
	// FormParameterToken is the token parameter from RFC 7009 and RFC 7662.
	FormParameterToken = "token"
	// FormParameterTokenTypeHint is the token_type_hint parameter from RFC 7009 and RFC 7662.
	FormParameterTokenTypeHint = "token_type_hint"
	// FormParameterError is the error parameter from RFC 6749.
	FormParameterError = "error"
	// FormParameterErrorHint is the error_hint parameter, a non-standard extension carrying additional error detail.
	FormParameterErrorHint = "error_hint"
	// FormParameterErrorDescription is the error_description parameter from RFC 6749.
	FormParameterErrorDescription = "error_description"
	// FormParameterErrorURI is the error_uri parameter from RFC 6749.
	FormParameterErrorURI = "error_uri"
	// FormParameterSessionState is the session_state parameter from OpenID Connect Session Management 1.0.
	FormParameterSessionState = "session_state"
	// FormParameterUsername is the username parameter from RFC 6749.
	FormParameterUsername = "username"
	// FormParameterPassword is the password parameter from RFC 6749.
	FormParameterPassword = valuePassword
	// FormParameterAccessToken is the access_token parameter from RFC 6749.
	FormParameterAccessToken = valueAccessToken
	// FormParameterMaximumAge is the max_age authorization request parameter from OpenID Connect Core 1.0.
	FormParameterMaximumAge = "max_age"
	// FormParameterPrompt is the prompt authorization request parameter from OpenID Connect Core 1.0.
	FormParameterPrompt = "prompt"
	// FormParameterDisplay is the display authorization request parameter from OpenID Connect Core 1.0.
	FormParameterDisplay = "display"
	// FormParameterAuthenticationContextClassReferenceValues is the acr_values authorization request parameter from OpenID Connect Core 1.0.
	FormParameterAuthenticationContextClassReferenceValues = "acr_values"
	// FormParameterIDTokenHint is the id_token_hint parameter from OpenID Connect Core 1.0 and OpenID Connect RP-Initiated Logout 1.0.
	FormParameterIDTokenHint = "id_token_hint"
	// FormParameterLogoutHint is the logout_hint parameter from OpenID Connect RP-Initiated Logout 1.0.
	FormParameterLogoutHint = "logout_hint"
	// FormParameterPostLogoutRedirectURI is the post_logout_redirect_uri parameter from OpenID Connect RP-Initiated Logout 1.0.
	FormParameterPostLogoutRedirectURI = "post_logout_redirect_uri"
	// FormParameterUILocales is the ui_locales parameter from OpenID Connect Core 1.0.
	FormParameterUILocales = "ui_locales"
	// FormParameterLogoutToken is the logout_token parameter from OpenID Connect Back-Channel Logout 1.0.
	FormParameterLogoutToken = "logout_token"
	// FormParameterRequestedTokenType is the requested_token_type parameter from RFC 8693.
	FormParameterRequestedTokenType = "requested_token_type"
	// FormParameterIssuedTokenType is the issued_token_type parameter from RFC 8693.
	FormParameterIssuedTokenType = "issued_token_type"
	// FormParameterSubjectTokenType is the subject_token_type parameter from RFC 8693.
	FormParameterSubjectTokenType = "subject_token_type"
	// FormParameterSubjectToken is the subject_token parameter from RFC 8693.
	FormParameterSubjectToken = "subject_token"
	// FormParameterActorTokenType is the actor_token_type parameter from RFC 8693.
	FormParameterActorTokenType = "actor_token_type"
	// FormParameterActorToken is the actor_token parameter from RFC 8693.
	FormParameterActorToken = "actor_token"
	// FormParameterDeviceCode is the device_code parameter from RFC 8628.
	FormParameterDeviceCode = valueDeviceCode
	// FormParameterUserCode is the user_code parameter from RFC 8628.
	FormParameterUserCode = valueUserCode
	// FormParameterDPoPJKT is the dpop_jkt authorization request parameter from RFC 9449.
	FormParameterDPoPJKT = "dpop_jkt"
	// FormParameterAuthReqID is the auth_req_id parameter from OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0.
	FormParameterAuthReqID = "auth_req_id"
	// FormParameterClientNotificationToken is the client_notification_token parameter from OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0.
	FormParameterClientNotificationToken = "client_notification_token"
	// FormParameterBindingMessage is the binding_message parameter from OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0.
	FormParameterBindingMessage = "binding_message"
	// FormParameterRequestedExpiry is the requested_expiry parameter from OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0.
	FormParameterRequestedExpiry = "requested_expiry"
	// FormParameterLoginHint is the login_hint parameter from OpenID Connect Core 1.0.
	FormParameterLoginHint = "login_hint"
	// FormParameterLoginHintToken is the login_hint_token parameter from OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0.
	FormParameterLoginHintToken = "login_hint_token"
	// FormParameterRequestContext is the request_context parameter, a non-standard extension.
	FormParameterRequestContext = "request_context"
	// FormParameterRequestDetails is the request_details parameter, a non-standard extension.
	FormParameterRequestDetails = "request_details"
)
