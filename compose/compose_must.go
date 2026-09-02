package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// mustOrderTokenEndpointBindingHandlers panics when both key binding token endpoint binding handlers are registered
// and oidckb.Handler precedes rfc9449.Handler.
//
// oidckb.Handler performs no proof validation of its own; it consumes the proof rfc9449.Handler publishes once every
// RFC 9449 Section 5 check has passed. Registered first it would find nothing published, so a grant that asked to be
// key bound would fail with a server error on every token request.
//
// rfc9449.Handler alone is a legitimate configuration. oidckb.Handler alone is legitimate only when some other
// handler publishes a validated proof via oauth2.PublishDPoPProof; with no publisher registered at all, every grant
// whose authentication request carried 'dpop_jkt' fails with a server error at the token endpoint.
func mustOrderTokenEndpointBindingHandlers(config *oauth2.Config) {
	var dpop, unordered bool

	// Every oidckb.Handler must be preceded by an rfc9449.Handler, so the list is walked in order rather than
	// reduced to one index per type: a list carrying more than one of either would report only the last of each,
	// and a misordered earlier pair would go unseen. Config.TokenEndpointBindingHandlers is exported and can be
	// assigned directly, so the Append deduplication cannot be relied on here.
	for _, handler := range config.TokenEndpointBindingHandlers {
		switch handler.(type) {
		case *rfc9449.Handler:
			dpop = true
		case *oidckb.Handler:
			if !dpop {
				unordered = true
			}
		}
	}

	// An oidckb.Handler with no rfc9449.Handler registered at all is the custom publisher configuration described
	// above, not an ordering fault.
	if !unordered || !dpop {
		return
	}

	panic("oauth2: DPoPTokenFactory must be registered before OpenIDConnectKeyBindingFactory, but OpenIDConnectKeyBindingFactory was registered first, and it consumes the DPoP proof that DPoPTokenFactory publishes")
}

// mustOrderRFC8628UserAuthorizeHandlers panics when oidckb.UserAuthorizeHandler is registered after
// rfc8628.UserAuthorizeHandler.
//
// Both populate the user authorization response in registration order. rfc8628.UserAuthorizeHandler persists the
// device code session, and oidckb.UserAuthorizeHandler records onto that session that the 'bound_key' scope was
// granted; consent decides that here, so it cannot be recorded any earlier. Registered second it would mutate a
// session already written, and every store that serializes on write would drop the marker, leaving the device flow to
// issue an ID Token with no 'cnf' claim and no error anywhere to say why.
func mustOrderRFC8628UserAuthorizeHandlers(config *oauth2.Config) {
	var device, unordered bool

	// Walked in order for the reason mustOrderTokenEndpointBindingHandlers is: no oidckb.UserAuthorizeHandler may
	// follow an rfc8628.UserAuthorizeHandler, which one index per type cannot express for a list carrying more
	// than one of either.
	for _, handler := range config.RFC8628UserAuthorizeEndpointHandlers {
		switch handler.(type) {
		case *rfc8628.UserAuthorizeHandler:
			device = true
		case *oidckb.UserAuthorizeHandler:
			if device {
				unordered = true
			}
		}
	}

	if !unordered {
		return
	}

	panic("oauth2: OpenIDConnectKeyBindingUserAuthorizeFactory must be registered before RFC8628UserAuthorizeFactory, but RFC8628UserAuthorizeFactory was registered first, and it persists the device code session before OpenIDConnectKeyBindingUserAuthorizeFactory records the granted key binding onto it")
}
