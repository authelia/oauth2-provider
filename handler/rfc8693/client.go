package rfc8693

import "authelia.com/provider/oauth2"

type Client interface {
	// GetSupportedSubjectTokenTypes indicates the token types allowed for subject_token
	GetSupportedSubjectTokenTypes() []string
	// GetSupportedActorTokenTypes indicates the token types allowed for subject_token
	GetSupportedActorTokenTypes() []string
	// GetSupportedRequestTokenTypes indicates the token types allowed for requested_token_type
	GetSupportedRequestTokenTypes() []string
	// TokenExchangeAllowed checks if the subject token client allows the specified client
	// to perform the exchange
	TokenExchangeAllowed(client oauth2.Client) bool
}
