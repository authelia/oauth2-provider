package oauth2

type contextKey int

var (
	// ContextKeySkipStatelessIntrospection is utilzed to communicate skipping StatelessJWTValidator which is useful for
	// the UserInfo endpoint.
	ContextKeySkipStatelessIntrospection = contextKey(0)
)
