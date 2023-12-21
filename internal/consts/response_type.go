package consts

// Response Type strings.
const (
	ResponseTypeAuthorizationCodeFlow = "code"
	ResponseTypeImplicitFlowIDToken   = "id_token"
	ResponseTypeImplicitFlowToken     = "token"
	ResponseTypeImplicitFlowBoth      = "id_token token"
	ResponseTypeHybridFlowIDToken     = "code id_token"
	ResponseTypeHybridFlowToken       = "code token"
	ResponseTypeHybridFlowBoth        = "code id_token token"
)
