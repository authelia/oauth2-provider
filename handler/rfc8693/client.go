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

	// GetTokenExchangePermitted checks if the subject token client allows the specified client
	// to perform the exchange
	GetTokenExchangePermitted(client oauth2.Client) (allowed bool)
}
