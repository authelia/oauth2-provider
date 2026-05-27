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

	// GetTokenExchangePermitted checks if the subject token client allows the specified client
	// to perform the exchange
	GetTokenExchangePermitted(client oauth2.Client) (allowed bool)
}
