// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	HeaderContentType     = "Content-Type"
	HeaderCacheControl    = "Cache-Control"
	HeaderPragma          = "Pragma"
	HeaderAuthorization   = "Authorization"
	HeaderLocation        = "Location"
	HeaderAcceptLanguage  = "Accept-Language"
	HeaderWWWAuthenticate = "WWW-Authenticate"
	HeaderXForwardedProto = "X-Forwarded-Proto"
	HeaderDPoP            = "DPoP"
	HeaderDPoPNonce       = "DPoP-Nonce"
)

const (
	ContentTypeApplicationURLEncodedForm        = "application/x-www-form-urlencoded"
	ContentTypeApplicationJSON                  = "application/json; charset=utf-8"
	ContentTypeApplicationTokenIntrospectionJWT = "application/token-introspection+jwt; charset=utf-8"
	ContentTypeTextHTML                         = "text/html; charset=utf-8"
)

const (
	// MediaTypeApplicationJSON is the bare "application/json" media type, without a charset parameter. It is used to
	// validate an incoming request's Content-Type header via mime.ParseMediaType, which strips any parameters before
	// comparison.
	MediaTypeApplicationJSON = "application/json"
)

const (
	PragmaNoCache       = "no-cache"
	CacheControlNoStore = "no-store"
)

const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

const (
	// AuthSchemeBearer is the HTTP authentication scheme name used in the 'WWW-Authenticate' response header, per
	// RFC 6750 Section 3. It is distinct from BearerAccessToken (the lowercase 'token_type' value used elsewhere in
	// OAuth 2.0 responses): the scheme name in a challenge is conventionally capitalized.
	AuthSchemeBearer = "Bearer"

	// AuthSchemeDPoP is the HTTP authentication scheme name used in the 'WWW-Authenticate' response header, per
	// RFC 9449 Section 7.1. Unlike the Bearer scheme it is spelled identically to the DPoP 'token_type' value, so
	// there is no case distinction to preserve between the two uses.
	AuthSchemeDPoP = "DPoP"
)
