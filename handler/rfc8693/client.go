// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import "authelia.com/provider/oauth2"

// Client is a representation of a client that may support RFC8693.
type Client interface {
	// GetSupportedSubjectTokenTypes indicates the token types allowed for subject_token.
	GetSupportedSubjectTokenTypes() (types []string)

	// GetSupportedActorTokenTypes indicates the token types allowed for subject_token.
	GetSupportedActorTokenTypes() (types []string)

	// GetSupportedRequestTokenTypes indicates the token types allowed for requested_token_type.
	GetSupportedRequestTokenTypes() (types []string)

	// GetSupportedSubjectTokenIssuers indicates the JWT 'iss' claim values this client is permitted
	// to submit as a custom JWT subject_token. A non-empty slice replaces JWTValidationConfig.Issuer, so it must only list
	// issuers whose keys the JWTValidationConfig.ValidateFunc of the type returns. Returning an empty slice falls back to
	// JWTValidationConfig.Issuer, and no issuer is accepted when that is also empty. An ID Token is always checked against
	// the ID Token issuer.
	GetSupportedSubjectTokenIssuers() (issuers []string)

	// GetSupportedActorTokenIssuers indicates the JWT 'iss' claim values this client is permitted
	// to submit as a custom JWT actor_token. A non-empty slice replaces JWTValidationConfig.Issuer, so it must only list
	// issuers whose keys the JWTValidationConfig.ValidateFunc of the type returns. Returning an empty slice falls back to
	// JWTValidationConfig.Issuer, and no issuer is accepted when that is also empty. An ID Token is always checked against
	// the ID Token issuer.
	GetSupportedActorTokenIssuers() (issuers []string)

	// GetTokenExchangePermitted reports whether the original client of an access token presented as a 'subject_token' or
	// 'actor_token' authorizes the given requesting client to perform a token exchange targeting the supplied
	// requestedTokenType, which is the resolved 'requested_token_type' (or the configured default when omitted) and is
	// non-nil at the call site. This restricts, and does not replace, the rule that the token's audience includes the
	// requesting client. A refresh token is only ever exchanged by its original client.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-5
	GetTokenExchangePermitted(client oauth2.Client, requestedTokenType oauth2.RFC8693TokenType) (allowed bool)

	// GetAllowActorTokenWithoutMayAct reports whether the client may perform delegation with an actor_token on
	// subject tokens that do not include a 'may_act' claim. Set to true only when an out-of-band authorization
	// mechanism (e.g. a policy database or external IGA system) verifies that the actor is permitted to act on
	// behalf of the subject.
	GetAllowActorTokenWithoutMayAct() (allow bool)
}

// ActorTokenExchangeClient is an optional client interface for a client whose GetTokenExchangePermitted permits clients
// it has not named. An access token of such a client is only accepted as an 'actor_token' when
// GetActorTokenExchangePermitted permits the requesting client. A client which does not implement this interface uses
// GetTokenExchangePermitted, and one which does not implement Client permits no other client.
type ActorTokenExchangeClient interface {
	// GetActorTokenExchangePermitted reports whether this client explicitly permits the given requesting client to
	// present an access token issued to this client as an 'actor_token'.
	GetActorTokenExchangePermitted(client oauth2.Client, requestedTokenType oauth2.RFC8693TokenType) (allowed bool)
}

// OwnAccessTokenExchangeTargetClient is an optional client interface. A client which does not implement it may request
// any audience or resource its registration permits when it exchanges an access token issued to itself.
type OwnAccessTokenExchangeTargetClient interface {
	// GetRestrictOwnAccessTokenExchangeTargets reports whether the exchange of an access token issued to the client is
	// limited to the audience and resources that access token was granted. RFC 8693 Section 2.1 leaves this to policy.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
	GetRestrictOwnAccessTokenExchangeTargets() (restrict bool)
}

// OwnAccessTokenExchangeClient is an optional client interface. A client which does not implement it may not exchange
// an access token issued to itself.
type OwnAccessTokenExchangeClient interface {
	// GetAllowOwnAccessTokenExchange reports whether the client may exchange an access token issued to itself as a
	// 'subject_token'. Returning true is NOT RECOMMENDED: each exchange leaves another live token for the same grant with
	// nothing linking it for revocation, and an attacker holding the client's credentials and one of its access tokens
	// can use it to mint further tokens. A client which only needs a JWT authorization grant does not need this.
	GetAllowOwnAccessTokenExchange() (allow bool)
}

// OwnRefreshTokenExchangeClient is an optional client interface. A client which does not implement it may not exchange
// a refresh token issued to itself, which RFC 8693 Section 2.2.2 refuses with 'invalid_request', other than for an
// Identity Assertion JWT Authorization Grant or a JWT authorization grant, which AuthorizationGrantIssuanceClient
// permits. A refresh token is never exchanged by any other client.
//
// A client which opts in may only request the audience and resources the refresh token was granted, per RFC 8707
// Section 2.2. The issued access token or refresh token belongs to the request the refresh token was issued for, so
// revoking that grant revokes it as RFC 7009 Section 2.1 describes. An issued refresh token keeps the session of that
// request, with the RFC 8693 Section 4.1 'act' claim of the exchange.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-5.3
type OwnRefreshTokenExchangeClient interface {
	// GetAllowOwnRefreshTokenExchange reports whether the client may exchange a refresh token issued to itself as a
	// 'subject_token'. An attacker holding the client's credentials and one of its refresh tokens can otherwise use it
	// to mint tokens of another type without rotating it.
	GetAllowOwnRefreshTokenExchange() (allow bool)
}

// OwnIDTokenExchangeClient is an optional client interface. A client which does not implement it may not exchange an
// ID Token as a 'subject_token', which RFC 8693 Section 2.2.2 refuses with 'invalid_request', other than for an
// Identity Assertion JWT Authorization Grant or a JWT authorization grant, which AuthorizationGrantIssuanceClient
// permits. An ID Token is only ever exchanged by the client it was issued to, and may always be presented as an
// 'actor_token'.
//
// OpenID Connect Core 1.0 Section 2 makes an ID Token a statement about an authentication for the client, not an
// authorization, so no grant limits the audience and resources a client which opts in may request other than its
// registration, and nothing links the issued token to a grant for revocation.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
type OwnIDTokenExchangeClient interface {
	// GetAllowOwnIDTokenExchange reports whether the client may exchange an ID Token issued to itself as a
	// 'subject_token'. An attacker holding the client's credentials and one of its ID Tokens can otherwise use it to
	// mint tokens for the End-User.
	GetAllowOwnIDTokenExchange() (allow bool)
}

// RefreshTokenIssuanceClient is an optional client interface. A client which does not implement it is not issued a
// refresh token by a token exchange.
type RefreshTokenIssuanceClient interface {
	// GetAllowTokenExchangeRefreshToken reports whether a token exchange may issue a refresh token to the client. An
	// issued refresh token also requires a refresh token 'subject_token', which OwnRefreshTokenExchangeClient permits,
	// the 'refresh_token' grant type, and one of the configured refresh token scopes.
	GetAllowTokenExchangeRefreshToken() (allow bool)
}

// RefreshTokenRotationOverrideClient is an optional client interface. A token exchange which issues a refresh token
// rotates a refresh token 'subject_token' unless oauth2.IsRefreshTokenRotationDisabledForRequest disables rotation, and
// this interface lets a client decide that for itself instead. It does not change the refresh token grant.
type RefreshTokenRotationOverrideClient interface {
	// GetOverrideTokenExchangeRefreshTokenRotation reports whether GetTokenExchangeRefreshTokenRotation decides if the
	// token exchange rotates the client's refresh token 'subject_token'.
	GetOverrideTokenExchangeRefreshTokenRotation() (override bool)

	// GetTokenExchangeRefreshTokenRotation reports whether the token exchange rotates the client's refresh token
	// 'subject_token' when GetOverrideTokenExchangeRefreshTokenRotation returns true.
	GetTokenExchangeRefreshTokenRotation() (rotate bool)
}

// AuthorizationGrantIssuanceClient is an optional client interface. A client which does not implement it is not issued
// a JWT authorization grant by a token exchange.
type AuthorizationGrantIssuanceClient interface {
	// GetAllowTokenExchangeAuthorizationGrant reports whether a token exchange may issue a JWT authorization grant to the
	// client. The client's audience and resources then determine the authorization servers a grant may identify.
	GetAllowTokenExchangeAuthorizationGrant() (allow bool)
}

// TokenExchangePermittedClientsClient is an optional interface a client may implement to list the clients permitted to
// exchange a token issued to it. A client resolved from a Client ID Metadata Document permits only the clients it lists,
// and none when it does not implement this interface. The list of such a client is never taken from its document, so
// it is empty unless the operator sets it, for example with cimd.Config.Filter.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-5
type TokenExchangePermittedClientsClient interface {
	// GetTokenExchangePermittedClientIDs returns the identifiers of the clients permitted to exchange a token issued
	// to this client.
	GetTokenExchangePermittedClientIDs() (ids []string)
}

// ActorTokenPolicyClient is an optional Client subset that controls actor-token authorization for RFC 8693 delegation.
// When the request supplies an actor_token but the subject_token carries no 'may_act' (§4.4) claim authorizing
// delegation, the authorization server has no in-token signal that the actor is permitted to act on behalf of the
// subject. By default such requests are rejected with invalid_grant; a client may opt into externally-gated
// authorization by implementing this interface and returning true from GetAllowActorTokenWithoutMayAct.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-4.4.
type ActorTokenPolicyClient interface {
	// GetAllowActorTokenWithoutMayAct reports whether the client may perform delegation with an actor_token on
	// subject tokens that do not include a 'may_act' claim. Set to true only when an out-of-band authorization
	// mechanism (e.g. a policy database or external IGA system) verifies that the actor is permitted to act on
	// behalf of the subject.
	GetAllowActorTokenWithoutMayAct() (allow bool)
}
