package consts

const (
	FormParameterState                                     = "state"
	FormParameterAuthorizationCode                         = valueCode
	FormParameterClientID                                  = valueClientID
	FormParameterClientSecret                              = "client_secret"
	FormParameterRequest                                   = "request"
	FormParameterRequestURI                                = "request_uri"
	FormParameterRedirectURI                               = "redirect_uri"
	FormParameterNonce                                     = valueNonce
	FormParameterResponse                                  = "response"
	FormParameterResponseMode                              = "response_mode"
	FormParameterResponseType                              = "response_type"
	FormParameterCodeChallenge                             = "code_challenge"
	FormParameterCodeVerifier                              = "code_verifier"
	FormParameterCodeChallengeMethod                       = "code_challenge_method"
	FormParameterClientAssertionType                       = "client_assertion_type"
	FormParameterClientAssertion                           = "client_assertion"
	FormParameterAssertion                                 = "assertion"
	FormParameterGrantType                                 = "grant_type"
	FormParameterScope                                     = valueScope
	FormParameterRegistration                              = "registration"
	FormParameterAudience                                  = "audience"
	FormParameterRefreshToken                              = valueRefreshToken
	FormParameterIssuer                                    = valueIss
	FormParameterToken                                     = "token"
	FormParameterTokenTypeHint                             = "token_type_hint"
	FormParameterError                                     = "error"
	FormParameterErrorHint                                 = "error_hint"
	FormParameterErrorDescription                          = "error_description"
	FormParameterUsername                                  = "username"
	FormParameterPassword                                  = valuePassword
	FormParameterAccessToken                               = valueAccessToken
	FormParameterMaximumAge                                = "max_age"
	FormParameterPrompt                                    = "prompt"
	FormParameterDisplay                                   = "display"
	FormParameterAuthenticationContextClassReferenceValues = "acr_values"
	FormParameterIDTokenHint                               = "id_token_hint"
	FormParameterRequestedTokenType                        = "requested_token_type"
	FormParameterIssuedTokenType                           = "issued_token_type" //nolint:gosec // This is a credential type, not a credential.
	FormParameterSubjectTokenType                          = "subject_token_type"
	FormParameterSubjectToken                              = "subject_token"
	FormParameterActorTokenType                            = "actor_token_type"
	FormParameterActorToken                                = "actor_token"
	FormParameterDeviceCode                                = valueDeviceCode
	FormParameterUserCode                                  = valueUserCode
)
