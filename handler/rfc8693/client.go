// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import "authelia.com/provider/oauth2"

// Client is a representation of a client that may support RFC8693.
type Client interface {
	// GetSupportedSubjectTokenTypes indicates the token types allowed for subject_token
	GetSupportedSubjectTokenTypes() (types []string)

	// GetSupportedActorTokenTypes indicates the token types allowed for subject_token
	GetSupportedActorTokenTypes() (types []string)

	// GetSupportedRequestTokenTypes indicates the token types allowed for requested_token_type
	GetSupportedRequestTokenTypes() (types []string)

	// GetSupportedSubjectTokenIssuers indicates the JWT 'iss' claim values this client is permitted
	// to submit as subject_token. Returning an empty slice disables the per-client issuer check and
	// falls back to the token type's global Issuer setting (e.g. JWTType.Issuer).
	GetSupportedSubjectTokenIssuers() (issuers []string)

	// GetSupportedActorTokenIssuers indicates the JWT 'iss' claim values this client is permitted
	// to submit as actor_token. Returning an empty slice disables the per-client issuer check and
	// falls back to the token type's global Issuer setting (e.g. JWTType.Issuer).
	GetSupportedActorTokenIssuers() (issuers []string)

	// GetTokenExchangePermitted reports whether the subject token's original client authorizes the given requesting
	// client to perform a token exchange targeting the supplied requestedTokenType. Both inputs are passed so the
	// policy can encode rules like "client X may mint id_tokens from my tokens but not refresh_tokens".
	//
	// requestedTokenType is the resolved oauth2.RFC8693TokenType corresponding to the request's
	// 'requested_token_type' parameter (or the configured default when omitted). It is non-nil at the call site.
	//
	// See RFC 8693 §5: "Authorization servers SHOULD restrict the use of token exchange to only those clients
	// explicitly authorized to perform the exchange operation."
	GetTokenExchangePermitted(client oauth2.Client, requestedTokenType oauth2.RFC8693TokenType) (allowed bool)

	// GetAllowActorTokenWithoutMayAct reports whether the client may perform delegation with an actor_token on
	// subject tokens that do not include a 'may_act' claim. Set to true only when an out-of-band authorization
	// mechanism (e.g. a policy database or external IGA system) verifies that the actor is permitted to act on
	// behalf of the subject.
	GetAllowActorTokenWithoutMayAct() (allow bool)
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
