// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientIDMetadataDocumentSupportedMetadataName is the authorization server metadata name an authorization server
// which resolves Client ID Metadata Documents publishes with the value true.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-8
//
// Deprecated: use the DraftClientIDMetadataDocumentMetadata.ClientIDMetadataDocumentSupported field.
const ClientIDMetadataDocumentSupportedMetadataName = consts.DiscoveryClientIDMetadataDocumentSupported

// IsClientIdentifierURL reports whether id is a valid Client Identifier URL.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-3
func IsClientIdentifierURL(id string) (ok bool) {
	return ValidateClientIdentifierURL(id) == nil
}

// ValidateClientIdentifierURL returns an error wrapping ErrInvalidClient unless id is a valid Client Identifier URL:
// the 'https' scheme, no userinfo, a path other than '/', no single-dot or double-dot path segment, and no fragment. A port and a
// query are permitted. The value is not normalized, so a value which is not the URL a request for it is made to, such
// as one with a character which must be percent-encoded or an empty port, is refused.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4
func ValidateClientIdentifierURL(id string) (err error) {
	if !strings.HasPrefix(id, consts.SchemeHTTPS+"://") {
		return errClientIdentifierURL("The client identifier '%s' does not use the 'https' scheme.", id)
	}

	if strings.Contains(id, "#") {
		return errClientIdentifierURL("The client identifier '%s' contains a fragment component.", id)
	}

	for i := 0; i < len(id); i++ {
		if id[i] <= ' ' || id[i] > '~' {
			return errClientIdentifierURL("The client identifier %q contains a character which must be percent-encoded.", id)
		}
	}

	var parsed *url.URL

	if parsed, err = url.Parse(id); err != nil {
		return errClientIdentifierURL("The client identifier '%s' could not be parsed as a URL: %v.", id, err)
	}

	// The document must be fetched from the client identifier itself.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4
	if parsed.String() != id || strings.HasSuffix(parsed.Host, ":") {
		return errClientIdentifierURL("The client identifier %q is not the URL a request for it is made to.", id)
	}

	switch {
	case parsed.Opaque != "", parsed.Hostname() == "":
		return errClientIdentifierURL("The client identifier '%s' does not contain a host.", id)
	case parsed.User != nil:
		return errClientIdentifierURL("The client identifier '%s' contains a userinfo component.", id)
	case parsed.EscapedPath() == "":
		return errClientIdentifierURL("The client identifier '%s' does not contain a path component.", id)
	case parsed.EscapedPath() == "/":
		return errClientIdentifierURL("The client identifier '%s' has the path component '/'.", id)
	}

	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		var decoded string

		if decoded, err = url.PathUnescape(segment); err != nil {
			return errClientIdentifierURL("The client identifier '%s' contains a path segment which could not be decoded: %v.", id, err)
		}

		if decoded == "." || decoded == ".." {
			return errClientIdentifierURL("The client identifier '%s' contains a single-dot or double-dot path segment.", id)
		}
	}

	return nil
}

func errClientIdentifierURL(debug string, args ...any) (err error) {
	return errorsx.WithStack(ErrInvalidClient.WithHint("The client identifier is not a valid Client Identifier URL.").WithDebugf(debug, args...))
}

// ClientIDMetadataDocumentResolver resolves a Client Identifier URL to a Client.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
type ClientIDMetadataDocumentResolver interface {
	// ResolveClientIDMetadataDocumentClient returns the client the Client ID Metadata Document at id describes. The
	// returned client must implement ClientIDMetadataDocumentClient and report true.
	ResolveClientIDMetadataDocumentClient(ctx context.Context, id string) (client Client, err error)
}

// ClientIDMetadataDocumentConfigProvider is the optional provider which enables Client ID Metadata Documents. The
// feature is disabled when the Configurator does not implement it or the resolver is nil.
type ClientIDMetadataDocumentConfigProvider interface {
	// GetClientIDMetadataDocumentResolver returns the resolver, or nil when the feature is disabled.
	GetClientIDMetadataDocumentResolver(ctx context.Context) (resolver ClientIDMetadataDocumentResolver)

	// GetClientIDMetadataDocumentHTTPClient returns the HTTP client used to fetch a URL taken from a Client ID
	// Metadata Document, which must refuse special-use addresses. Such a fetch fails when it is nil.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
	GetClientIDMetadataDocumentHTTPClient(ctx context.Context) (client *retryablehttp.Client)

	// GetClientIDMetadataDocumentJWKSFetcherStrategy returns the strategy used to fetch the 'jwks_uri' of a Client ID
	// Metadata Document, which must refuse special-use addresses. Such a fetch fails when it is nil.
	GetClientIDMetadataDocumentJWKSFetcherStrategy(ctx context.Context) (strategy jwt.JWKSFetcherStrategy)

	// GetClientIDMetadataDocumentAllowedDomainSuffixes returns the domain suffixes a Client Identifier URL host must
	// have for its Client ID Metadata Document to be resolved. A suffix matches the domain itself and its subdomains,
	// or only its subdomains when it begins with a dot. Every host is permitted when there are none.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.8
	GetClientIDMetadataDocumentAllowedDomainSuffixes(ctx context.Context) (suffixes []string)
}

// ClientIDMetadataDocumentClient is implemented by a client resolved from a Client ID Metadata Document. A type which
// wraps such a client must forward IsClientIDMetadataDocumentClient, and GetTokenExchangePermittedClientIDs when the
// wrapped client implements it, as without it no other client may exchange a token issued to the client.
type ClientIDMetadataDocumentClient interface {
	Client

	// IsClientIDMetadataDocumentClient returns true when the client was resolved from a Client ID Metadata Document.
	IsClientIDMetadataDocumentClient() (is bool)
}

// ClientIDMetadataDocumentRecord is a validated Client ID Metadata Document and its cache lifetime.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.2
type ClientIDMetadataDocumentRecord struct {
	ID string `json:"id"`

	// Domain is the domain the record counts against for a limit on the records stored for one domain.
	Domain string `json:"domain,omitempty"`

	Metadata  *ClientRegistrationMetadata `json:"metadata"`
	FetchedAt time.Time                   `json:"fetched_at"`
	ExpiresAt time.Time                   `json:"expires_at"`

	// MustRevalidate is true when the response forbade serving the document after ExpiresAt, so a storage must persist
	// it with the record.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4
	MustRevalidate bool `json:"must_revalidate,omitempty"`
}

// ClientIDMetadataDocumentStorage persists validated Client ID Metadata Documents by Client Identifier URL. It is
// separate from ClientManager so that a client resolved from a document is never a registered client.
type ClientIDMetadataDocumentStorage interface {
	// GetClientIDMetadataDocument returns the record for id, or an error matching ErrNotFound.
	GetClientIDMetadataDocument(ctx context.Context, id string) (record *ClientIDMetadataDocumentRecord, err error)

	// SetClientIDMetadataDocument creates or replaces the record for record.ID.
	SetClientIDMetadataDocument(ctx context.Context, record *ClientIDMetadataDocumentRecord) (err error)

	// DeleteClientIDMetadataDocument removes the record for id. It returns nil when no record exists.
	DeleteClientIDMetadataDocument(ctx context.Context, id string) (err error)

	// DeleteExpiredClientIDMetadataDocuments removes every record whose ExpiresAt is before the given time. A record
	// is only removed when its ExpiresAt is before the given time at the moment it is removed, so a record replaced
	// concurrently is kept.
	DeleteExpiredClientIDMetadataDocuments(ctx context.Context, before time.Time) (err error)

	// RevokeClientIDMetadataDocumentRefreshTokens revokes every refresh token issued to the client with the identifier
	// id. It is called when the document fetched from id has another 'client_id', and returns nil when there are none.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.1
	RevokeClientIDMetadataDocumentRefreshTokens(ctx context.Context, id string) (err error)

	// CountClientIDMetadataDocuments returns the number of stored records whose Domain is domain, expired or not.
	CountClientIDMetadataDocuments(ctx context.Context, domain string) (count int, err error)
}

// GetClient returns the client with the given id. The store is consulted first, so a registered client always takes
// precedence. When the store reports the client as not found, the config provides a
// ClientIDMetadataDocumentResolver, and id is a valid Client Identifier URL whose host has one of the allowed domain
// suffixes when there are any, the client is resolved from its Client ID Metadata Document. A resolved client which is nil, has another identifier, or does not report
// IsClientIDMetadataDocumentClient is refused. A store which rebuilds the client of a persisted session from its
// identifier should use it.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-9.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-9.2
func GetClient(ctx context.Context, config any, store ClientGetter, id string) (client Client, err error) {
	if client, err = store.GetClient(ctx, id); err == nil {
		return client, nil
	}

	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	provider, ok := config.(ClientIDMetadataDocumentConfigProvider)
	if !ok {
		return nil, err
	}

	resolver := provider.GetClientIDMetadataDocumentResolver(ctx)

	if resolver == nil || !IsClientIdentifierURL(id) {
		return nil, err
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-7
	if len(getAuthorizationServerIdentificationIssuer(ctx, config)) == 0 {
		return nil, errorsx.WithStack(ErrServerError.WithDebugf("The Client ID Metadata Document for the client identifier '%s' was not resolved as RFC 9207 authorization server issuer identification is disabled or no issuer is configured.", id))
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.8
	if !isClientIdentifierURLDomainAllowed(id, provider.GetClientIDMetadataDocumentAllowedDomainSuffixes(ctx)) {
		return nil, err
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.1
	if slices.Contains(reservedClientIdentifierURLs(ctx, config), id) {
		return nil, errClientIdentifierURL("The client identifier '%s' is the identifier of this authorization server or of a party it trusts.", id)
	}

	if client, err = resolver.ResolveClientIDMetadataDocumentClient(ctx, id); err != nil {
		return nil, err
	}

	if client == nil || client.GetID() != id || !jwt.IsClientIDMetadataDocumentClient(client) {
		return nil, errorsx.WithStack(ErrServerError.WithDebugf("The Client ID Metadata Document resolver did not return a Client ID Metadata Document client with the identifier '%s'.", id))
	}

	return client, nil
}

// ClientIDMetadataDocumentReservedIdentifiersProvider is the optional provider of the identifiers of the authorization
// servers and resource servers this authorization server trusts, which a Client Identifier URL may not equal. The
// identifiers of the configuration and of the token exchange token types are reserved without it, so it must supply
// the trust the library can not enumerate: the issuers and audiences of Identity Assertion JWT Authorization Grant
// relationships and trusted issuers held in storage, the issuers a client may present tokens from, and the resource
// servers this authorization server issues tokens for.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.1
type ClientIDMetadataDocumentReservedIdentifiersProvider interface {
	// GetClientIDMetadataDocumentReservedIdentifiers returns the identifiers of the authorization servers and resource
	// servers this authorization server trusts.
	GetClientIDMetadataDocumentReservedIdentifiers(ctx context.Context) (identifiers []string)
}

// reservedClientIdentifierURLs returns the identifiers a Client Identifier URL may not equal: the issuer identifier,
// accepted assertion audiences and accepted bearer audiences of this authorization server, the identifiers its token
// exchange token types configure, and the identifiers of the parties it trusts.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.1
func reservedClientIdentifierURLs(ctx context.Context, config any) (identifiers []string) {
	if p, ok := config.(IssuerProvider); ok {
		identifiers = append(identifiers, p.GetIssuer(ctx))
	}

	if p, ok := config.(AllowedJWTAssertionAudiencesProvider); ok {
		identifiers = append(identifiers, p.GetAllowedJWTAssertionAudiences(ctx)...)
	}

	if p, ok := config.(AllowedIntrospectionAudiencesProvider); ok {
		identifiers = append(identifiers, p.GetAllowedIntrospectionAudiences(ctx)...)
	}

	if p, ok := config.(EndpointURLsProvider); ok {
		urls := p.GetEndpointURLs(ctx)

		identifiers = append(identifiers, urls.URLs(EndpointToken)...)
		identifiers = append(identifiers, urls.URLs(EndpointIntrospection)...)
		identifiers = append(identifiers, urls.URLs(EndpointRegistration)...)
	}

	if p, ok := config.(interface {
		GetRFC7591ClientRegistrationEndpointAudiences(ctx context.Context) (audiences []string)
	}); ok {
		identifiers = append(identifiers, p.GetRFC7591ClientRegistrationEndpointAudiences(ctx)...)
	}

	if p, ok := config.(interface {
		GetRFC8693TokenTypes(ctx context.Context) (types map[string]RFC8693TokenType)
	}); ok {
		for _, tokenType := range p.GetRFC8693TokenTypes(ctx) {
			if provider, ok := tokenType.(RFC8693TokenTypeIdentifiersProvider); ok {
				identifiers = append(identifiers, provider.GetIdentifiers(ctx)...)
			}
		}
	}

	if p, ok := config.(ClientIDMetadataDocumentReservedIdentifiersProvider); ok {
		identifiers = append(identifiers, p.GetClientIDMetadataDocumentReservedIdentifiers(ctx)...)
	}

	return identifiers
}

func isClientIdentifierURLDomainAllowed(id string, suffixes []string) (allowed bool) {
	parsed, err := url.Parse(id)
	if err != nil {
		return false
	}

	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")

	_, err = netip.ParseAddr(host)
	literal := err == nil

	restricted := false

	for _, suffix := range suffixes {
		suffix = strings.TrimSuffix(strings.ToLower(suffix), ".")

		subdomains := strings.HasPrefix(suffix, ".")

		if suffix = strings.TrimPrefix(suffix, "."); suffix == "" {
			continue
		}

		restricted = true

		if literal {
			continue
		}

		if strings.HasSuffix(host, "."+suffix) || (!subdomains && host == suffix) {
			return true
		}
	}

	return !restricted
}

// isClientIDMetadataDocumentFetchClient reports whether a URL taken from the metadata of client must be fetched with the
// Client ID Metadata Document fetchers: the client reports IsClientIDMetadataDocumentClient, or the feature is enabled
// and the client identifier is a Client Identifier URL.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
func isClientIDMetadataDocumentFetchClient(ctx context.Context, config any, client any) (is bool) {
	if jwt.IsClientIDMetadataDocumentClient(client) {
		return true
	}

	provider, ok := config.(ClientIDMetadataDocumentConfigProvider)
	if !ok || provider.GetClientIDMetadataDocumentResolver(ctx) == nil {
		return false
	}

	c, ok := client.(interface{ GetID() string })

	return ok && IsClientIdentifierURL(c.GetID())
}

func httpClientForClient(ctx context.Context, config any, base *retryablehttp.Client, client any) (hc *retryablehttp.Client, err error) {
	if !isClientIDMetadataDocumentFetchClient(ctx, config, client) {
		if hc, err = SpecialUseAddressGuardHTTPClient(ctx, config, base); err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
		}

		return hc, nil
	}

	if provider, ok := config.(ClientIDMetadataDocumentConfigProvider); ok {
		if hc = provider.GetClientIDMetadataDocumentHTTPClient(ctx); hc != nil {
			return hc, nil
		}
	}

	return nil, errorsx.WithStack(ErrServerError.WithDebug("The client was resolved from a Client ID Metadata Document but no HTTP client is configured to fetch the URLs of such a client."))
}
