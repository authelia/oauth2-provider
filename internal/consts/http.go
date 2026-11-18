// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// HeaderContentType is the Content-Type HTTP header.
	HeaderContentType = "Content-Type"
	// HeaderCacheControl is the Cache-Control HTTP header.
	HeaderCacheControl = "Cache-Control"
	// HeaderAllow is the Allow HTTP header.
	HeaderAllow = "Allow"
	// HeaderPragma is the Pragma HTTP header.
	HeaderPragma = "Pragma"
	// HeaderAuthorization is the Authorization HTTP header.
	HeaderAuthorization = "Authorization"
	// HeaderLocation is the Location HTTP header.
	HeaderLocation = "Location"
	// HeaderAccept is the Accept HTTP header.
	HeaderAccept = "Accept"
	// HeaderAcceptLanguage is the Accept-Language HTTP header.
	HeaderAcceptLanguage = "Accept-Language"
	// HeaderWWWAuthenticate is the WWW-Authenticate HTTP header.
	HeaderWWWAuthenticate = "WWW-Authenticate"
	// HeaderXForwardedProto is the X-Forwarded-Proto HTTP header.
	HeaderXForwardedProto = "X-Forwarded-Proto"
	// HeaderDPoP is the DPoP HTTP header from RFC 9449.
	HeaderDPoP = "DPoP"
	// HeaderDPoPNonce is the DPoP-Nonce HTTP header from RFC 9449.
	HeaderDPoPNonce = "DPoP-Nonce"
)

const (
	// ContentTypeApplicationURLEncodedForm is the application/x-www-form-urlencoded content type.
	ContentTypeApplicationURLEncodedForm = "application/x-www-form-urlencoded"
	// ContentTypeApplicationJSON is the application/json content type with a UTF-8 charset.
	ContentTypeApplicationJSON = "application/json; charset=utf-8"
	// ContentTypeApplicationTokenIntrospectionJWT is the application/token-introspection+jwt content type from RFC 9701 with a UTF-8 charset.
	ContentTypeApplicationTokenIntrospectionJWT = "application/token-introspection+jwt; charset=utf-8"
	// ContentTypeTextHTML is the text/html content type with a UTF-8 charset.
	ContentTypeTextHTML = "text/html; charset=utf-8"
)

const (
	// MediaTypeApplicationJSON is the bare "application/json" media type, without a charset parameter. It is used to
	// validate an incoming request's Content-Type header via [mime.ParseMediaType], which strips any parameters before
	// comparison.
	MediaTypeApplicationJSON = "application/json"
)

const (
	// WellKnownOpenIDConfiguration is the path suffix of the OpenID Connect Discovery 1.0 metadata of an issuer.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
	WellKnownOpenIDConfiguration = "/.well-known/openid-configuration"

	// WellKnownOAuthAuthorizationServerSuffix is the RFC 8414 well-known URI suffix of the authorization server
	// metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3
	WellKnownOAuthAuthorizationServerSuffix = "oauth-authorization-server"

	// WellKnownOpenIDConfigurationSuffix is the well-known URI suffix of the OpenID Provider Configuration.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
	WellKnownOpenIDConfigurationSuffix = "openid-configuration"

	// WellKnownOAuthProtectedResourceSuffix is the RFC 9728 well-known URI suffix of the protected resource metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9728#section-3
	WellKnownOAuthProtectedResourceSuffix = "oauth-protected-resource"
)

const (
	// PragmaNoCache is the no-cache Pragma header value.
	PragmaNoCache = "no-cache"
	// CacheControlNoStore is the no-store Cache-Control header value from RFC 9111.
	CacheControlNoStore = "no-store"
	// CacheControlNoCacheNoStore is the Cache-Control header value of a Grant Management API response.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
	CacheControlNoCacheNoStore = "no-cache, no-store"
)

const (
	// SchemeHTTP is the http URI scheme.
	SchemeHTTP = "http"
	// SchemeHTTPS is the https URI scheme.
	SchemeHTTPS = "https"
)

const (
	// AuthSchemeBearer is the HTTP authentication scheme name used in the 'WWW-Authenticate' response header, per
	// RFC 6750 Section 3. It is distinct from BearerAccessToken (the lowercase 'token_type' value used elsewhere in
	// OAuth 2.0 responses): the scheme name in a challenge is conventionally capitalized.
	AuthSchemeBearer = "Bearer"

	// AuthSchemeDPoP is the HTTP authentication scheme name used in the 'WWW-Authenticate' response header, per
	// RFC 9449 Section 7.1.
	AuthSchemeDPoP = "DPoP"
)

const (
	// ChallengeParameterResourceMetadata is the 'WWW-Authenticate' challenge parameter carrying the URL of the
	// protected resource metadata, per RFC 9728 Section 5.1.
	ChallengeParameterResourceMetadata = "resource_metadata"
)
