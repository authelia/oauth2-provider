// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/net/publicsuffix"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// DefaultMaxBodyBytes is the default number of bytes read from a Client ID Metadata Document response.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.11
	DefaultMaxBodyBytes = 5120

	// DefaultMaxLifespan is the default upper bound on how long a Client ID Metadata Document is cached.
	DefaultMaxLifespan = 24 * time.Hour

	// DefaultLifespan is the default cache lifetime of a Client ID Metadata Document served without cache headers.
	DefaultLifespan = time.Hour

	// DefaultMaxConcurrentFetches is the default number of Client ID Metadata Document fetches in progress at once.
	DefaultMaxConcurrentFetches = 16

	// DefaultMaxConcurrentFetchesPerDomain is the default number of Client ID Metadata Document fetches in progress at
	// once from one registrable domain.
	DefaultMaxConcurrentFetchesPerDomain = 4

	// DefaultFetchTimeout is the default time a Client ID Metadata Document fetch may take.
	DefaultFetchTimeout = 5 * time.Second

	// DefaultFetchRatePerDomain is the default number of Client ID Metadata Document fetches started per second from
	// one registrable domain.
	DefaultFetchRatePerDomain = 10

	// DefaultFetchBurstPerDomain is the default number of Client ID Metadata Document fetches which may be started at
	// once from one registrable domain before DefaultFetchRatePerDomain applies.
	DefaultFetchBurstPerDomain = 20

	// DefaultMaxDocumentsPerDomain is the default number of Client ID Metadata Documents stored for one registrable
	// domain.
	DefaultMaxDocumentsPerDomain = 100

	// DefaultStaleGracePeriod is the default time after its cache lifetime that a Client ID Metadata Document is still
	// served when fetching it again fails transiently.
	DefaultStaleGracePeriod = 24 * time.Hour

	pruneInterval = 5 * time.Minute
)

// DefaultTokenEndpointAuthMethods is the default value of Config.TokenEndpointAuthMethods.
var DefaultTokenEndpointAuthMethods = []string{
	consts.ClientAuthMethodPrivateKeyJWT,
	consts.ClientAuthMethodSelfSignedTLSClientAuth,
	consts.ClientAuthMethodTLSClientAuth,
	consts.ClientAuthMethodNone,
}

// Config configures a Resolver.
type Config struct {
	// Storage persists validated documents. Required.
	Storage oauth2.ClientIDMetadataDocumentStorage

	// HTTPClient fetches documents. Required. It must refuse special-use addresses, see
	// oauth2.NewSpecialUseAddressGuardedHTTPClient.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
	HTTPClient *retryablehttp.Client

	// Policy decides whether a valid Client Identifier URL may be resolved, before storage is read or a request is
	// made. A nil Policy allows every Client Identifier URL.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.8
	Policy func(ctx context.Context, id *url.URL) (err error)

	// Filter adjusts the metadata of a fetched document before Validators run. Optional. It runs after the document
	// is reduced to Scopes, GrantTypes and ResponseTypes and its token endpoint authentication method is selected from
	// TokenEndpointAuthMethods, and a value it adds is kept, except a scope, grant type or response type which is not
	// in Scopes, GrantTypes or ResponseTypes.
	//
	// The 'audience', 'resource', 'authorization_details_types', 'token_exchange_permitted_client_ids' and
	// 'sector_identifier_uri' of a document are discarded before Filter runs, as a document can not grant itself a
	// privilege at this authorization server. Filter is where the operator grants them. In particular, no other client
	// may exchange a token issued to a document client unless Filter lists it in TokenExchangePermittedClientIDs.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-5
	Filter oauth2.ClientRegistrationMetadataStrategy

	// Validators run in order against the metadata of a fetched document. When nil, a single rfc7591.LocalValidator
	// built from ValidatorConfig is used. An empty non-nil slice runs none.
	//
	// A validator which fetches a URL from the document, such as rfc7591.SectorIdentifierValidator, must be built
	// with a provider of an HTTP client which refuses special-use addresses.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
	Validators []oauth2.ClientRegistrationValidator

	// ValidatorConfig configures the default validator. Required when Validators is nil.
	ValidatorConfig rfc7591.LocalValidatorConfig

	// Strategy builds the client. Defaults to DefaultClientStrategy.
	Strategy ClientStrategy

	// Scopes is the complete set of scopes a document client may have. The document 'scope' is reduced to the values
	// also present here, when it is fetched and again whenever a stored document is served. Empty permits none.
	Scopes []string

	// GrantTypes is the complete set of grant types a document client may use. The document 'grant_types' is reduced
	// to the values also present here, when it is fetched and again whenever a stored document is served. Defaults to
	// authorization_code and refresh_token.
	GrantTypes []string

	// ResponseTypes is the complete set of response types a document client may use. The document 'response_types' is
	// reduced to the values also present here, each compared as an unordered set of space-delimited values, when it is
	// fetched and again whenever a stored document is served. A document left with no response type is rejected
	// unless none of its grant types uses the authorization endpoint. Defaults to code.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
	// See: https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2
	ResponseTypes []string

	// TokenEndpointAuthMethods is the set of token endpoint authentication methods a document client may use, in order
	// of preference. A document which declares 'private_key_jwt' in 'token_endpoint_auth_methods_supported' uses it when
	// it is one of them, and otherwise the first of them the document declares is used. A document which declares none
	// of them, or without that member has a 'token_endpoint_auth_method' which is not one of them, is rejected. A method
	// based on a shared symmetric secret is not permitted. Defaults to DefaultTokenEndpointAuthMethods.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-5
	TokenEndpointAuthMethods []string

	// MaxConcurrentFetches bounds the document fetches in progress at once. Defaults to 16. A party which controls
	// enough registrable domains can occupy every fetch, which Policy or an allowed domain suffix prevents.
	MaxConcurrentFetches int

	// MaxConcurrentFetchesPerDomain bounds the document fetches in progress at once from one registrable domain and
	// its subdomains, so that one domain can not occupy every fetch. An IPv4 address is its own domain, and an IPv6
	// address belongs to the domain of its /48 prefix. Defaults to 4 and is never more than MaxConcurrentFetches.
	MaxConcurrentFetchesPerDomain int

	// FetchRatePerDomain and FetchBurstPerDomain bound how often a document fetch is started from one registrable
	// domain, as defined for MaxConcurrentFetchesPerDomain: up to FetchBurstPerDomain at once, then FetchRatePerDomain
	// per second. A resolution which would start a fetch beyond the rate fails without one. A failed fetch is never
	// cached. They default to DefaultFetchRatePerDomain and DefaultFetchBurstPerDomain.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.2
	FetchRatePerDomain  float64
	FetchBurstPerDomain int

	// MaxDocumentsPerDomain bounds the documents stored for one registrable domain, as defined for
	// MaxConcurrentFetchesPerDomain, counting every stored record until it is pruned. A Client Identifier URL without a
	// stored document is refused, before it is fetched, while its domain has this many. A Client Identifier URL with a
	// stored document is unaffected. Defaults to DefaultMaxDocumentsPerDomain, and a negative value disables it.
	MaxDocumentsPerDomain int

	// FetchTimeout bounds the request for a document, and separately the validation and storage of the document it
	// returns. Defaults to DefaultFetchTimeout.
	FetchTimeout time.Duration

	// MaxBodyBytes is the number of bytes read from a response. A longer response is an error. Defaults to
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// MaxLifespan bounds the cache lifetime of a document whatever its response headers indicate, and DefaultLifespan is
	// the cache lifetime of a document whose response has no explicit expiration time. They default to
	// DefaultMaxLifespan and DefaultLifespan.
	//
	// The resolver is a shared cache and otherwise respects the response headers. A response with an unqualified
	// 'no-store' or 'private' directive is used for the request which fetched it but is never stored, and the record it
	// would have replaced is deleted. A response with an unqualified 'no-cache' directive, or a 'max-age', 's-maxage' or
	// 'Expires' which is invalid or already passed, has no cache lifetime, so the document is fetched again on its next
	// use. A response with an unqualified 'no-cache', 'must-revalidate', 'proxy-revalidate' or 's-maxage' directive is
	// never served after its cache lifetime, see StaleGracePeriod. Repeated fetches are bounded by the fetch limits
	// rather than by a minimum cache lifetime, as a minimum would reuse a response its headers forbid reusing.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.2
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-3
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-4.2.1
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2
	MaxLifespan     time.Duration
	DefaultLifespan time.Duration

	// StaleGracePeriod is how long after its cache lifetime a stored document is still served when fetching it again
	// fails transiently, such as on a network error, a timeout, a 408, 429 or 5xx status code, or a fetch limit. A
	// document whose response forbade serving it stale, as recorded in ClientIDMetadataDocumentRecord.MustRevalidate,
	// is not served, and the request fails with ErrTemporarilyUnavailable instead. A transient failure never deletes the
	// stored document. Defaults to DefaultStaleGracePeriod, and a negative value disables it.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.1
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4
	StaleGracePeriod time.Duration
}

// Resolver is the default oauth2.ClientIDMetadataDocumentResolver. It fetches, validates and caches Client ID
// Metadata Documents.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
type Resolver struct {
	config Config

	mu       sync.Mutex
	inflight map[string]*fetchCall
	fetches  chan struct{}
	domains  map[string]int
	buckets  map[string]*fetchBucket
	sweepAt  time.Time
	pruneAt  atomic.Int64
}

type fetchBucket struct {
	tokens float64
	at     time.Time
}

type fetchCall struct {
	done   chan struct{}
	record *oauth2.ClientIDMetadataDocumentRecord
	err    error
}

// NewResolver returns a new *Resolver, or an error when the config is incomplete or inconsistent.
func NewResolver(config Config) (resolver *Resolver, err error) {
	if config.Storage == nil {
		return nil, errors.New("cimd: the storage is required")
	}

	if config.HTTPClient == nil {
		return nil, errors.New("cimd: the http client is required")
	}

	if config.Validators == nil {
		if config.ValidatorConfig == nil {
			return nil, errors.New("cimd: the validator config is required when no validators are configured")
		}

		config.Validators = []oauth2.ClientRegistrationValidator{rfc7591.NewLocalValidator(config.ValidatorConfig)}
	}

	if config.Strategy == nil {
		config.Strategy = DefaultClientStrategy{}
	}

	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = DefaultMaxBodyBytes
	}

	if config.MaxLifespan <= 0 {
		config.MaxLifespan = DefaultMaxLifespan
	}

	if config.DefaultLifespan <= 0 {
		config.DefaultLifespan = DefaultLifespan
	}

	if len(config.GrantTypes) == 0 {
		config.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}
	}

	if len(config.ResponseTypes) == 0 {
		config.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
	}

	if err = applyClientDefaults(&config); err != nil {
		return nil, err
	}

	applyFetchDefaults(&config)

	return &Resolver{config: config, inflight: map[string]*fetchCall{}, fetches: make(chan struct{}, config.MaxConcurrentFetches), domains: map[string]int{}, buckets: map[string]*fetchBucket{}}, nil
}

func applyClientDefaults(config *Config) (err error) {
	if len(config.TokenEndpointAuthMethods) == 0 {
		config.TokenEndpointAuthMethods = DefaultTokenEndpointAuthMethods
	}

	for _, method := range config.TokenEndpointAuthMethods {
		if slices.ContainsFunc(secretAuthMethods, func(m string) bool { return strings.EqualFold(m, method) }) {
			return fmt.Errorf("cimd: the token endpoint authentication method '%s' requires a client secret", method)
		}
	}

	switch {
	case config.StaleGracePeriod == 0:
		config.StaleGracePeriod = DefaultStaleGracePeriod
	case config.StaleGracePeriod < 0:
		config.StaleGracePeriod = 0
	}

	switch {
	case config.MaxDocumentsPerDomain == 0:
		config.MaxDocumentsPerDomain = DefaultMaxDocumentsPerDomain
	case config.MaxDocumentsPerDomain < 0:
		config.MaxDocumentsPerDomain = 0
	}

	return nil
}

func applyFetchDefaults(config *Config) {
	if config.MaxConcurrentFetches <= 0 {
		config.MaxConcurrentFetches = DefaultMaxConcurrentFetches
	}

	if config.MaxConcurrentFetchesPerDomain <= 0 {
		config.MaxConcurrentFetchesPerDomain = DefaultMaxConcurrentFetchesPerDomain
	}

	config.MaxConcurrentFetchesPerDomain = min(config.MaxConcurrentFetchesPerDomain, config.MaxConcurrentFetches)

	if config.FetchTimeout <= 0 {
		config.FetchTimeout = DefaultFetchTimeout
	}

	if !(config.FetchRatePerDomain > 0) {
		config.FetchRatePerDomain = DefaultFetchRatePerDomain
	}

	if config.FetchBurstPerDomain <= 0 {
		config.FetchBurstPerDomain = DefaultFetchBurstPerDomain
	}
}

// ResolveClientIDMetadataDocumentClient returns the client the Client ID Metadata Document at id describes. A
// document within its cache lifetime is served from storage. Otherwise it is fetched, and a failed fetch or an
// invalid document fails the request and is not stored. A terminal failure deletes the record it would have replaced.
// A transient failure keeps that record, which is served instead until StaleGracePeriod after its cache lifetime
// unless its response forbade serving it stale, and otherwise fails the request with ErrTemporarilyUnavailable. A
// document whose response forbids storing it is not stored, and deletes the record it would have replaced. At most once per prune interval, a resolution which
// passes the Policy deletes the records whose grace period ended from storage.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.2
func (r *Resolver) ResolveClientIDMetadataDocumentClient(ctx context.Context, id string) (client oauth2.Client, err error) {
	if err = oauth2.ValidateClientIdentifierURL(id); err != nil {
		return nil, err
	}

	if r.config.Policy != nil {
		var parsed *url.URL

		if parsed, err = url.Parse(id); err != nil {
			return nil, errResolve(err, "The client identifier '%s' could not be parsed as a URL.", id)
		}

		if err = r.config.Policy(ctx, parsed); err != nil {
			return nil, errResolve(err, "The client identifier '%s' was refused by the policy: %v.", id, err)
		}
	}

	r.prune()

	var record *oauth2.ClientIDMetadataDocumentRecord

	record, err = r.config.Storage.GetClientIDMetadataDocument(ctx, id)

	switch {
	case err == nil:
		if isUsableRecord(record, id) {
			return r.newClient(ctx, record)
		}
	case !errors.Is(err, oauth2.ErrNotFound):
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Document '%s' could not be read from storage: %v.", id, err))
	}

	if record == nil {
		if err = r.checkDomainLimit(ctx, id); err != nil {
			return nil, err
		}
	}

	var fresh *oauth2.ClientIDMetadataDocumentRecord

	if fresh, err = r.refresh(ctx, id, record != nil); err != nil {
		if r.isGraceRecord(record, id) && errors.Is(err, oauth2.ErrTemporarilyUnavailable) {
			return r.newClient(ctx, record)
		}

		return nil, err
	}

	return r.newClient(ctx, fresh)
}

func (r *Resolver) checkDomainLimit(ctx context.Context, id string) (err error) {
	if r.config.MaxDocumentsPerDomain <= 0 {
		return nil
	}

	domain := fetchDomain(id)

	var count int

	if count, err = r.config.Storage.CountClientIDMetadataDocuments(ctx, domain); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Documents of the domain '%s' could not be counted: %v.", domain, err))
	}

	if count >= r.config.MaxDocumentsPerDomain {
		return errResolve(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %d documents stored for its domain is reached.", id, r.config.MaxDocumentsPerDomain)
	}

	return nil
}

func (r *Resolver) isGraceRecord(record *oauth2.ClientIDMetadataDocumentRecord, id string) (grace bool) {
	return record != nil && record.Metadata != nil && record.ID == id && !record.MustRevalidate && time.Now().Before(record.ExpiresAt.Add(r.config.StaleGracePeriod))
}

func (r *Resolver) refresh(ctx context.Context, id string, stale bool) (record *oauth2.ClientIDMetadataDocumentRecord, err error) {
	domain := fetchDomain(id)

	r.mu.Lock()

	call, ok := r.inflight[id]
	if !ok {
		if r.domains[domain] >= r.config.MaxConcurrentFetchesPerDomain && r.config.MaxConcurrentFetchesPerDomain < cap(r.fetches) {
			r.mu.Unlock()

			return nil, errTransient(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %d concurrent fetches from its domain is reached.", id, r.config.MaxConcurrentFetchesPerDomain)
		}

		bucket := r.bucket(domain, time.Now())

		if bucket.tokens < 1 {
			r.mu.Unlock()

			return nil, errTransient(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %g fetches per second from its domain is reached.", id, r.config.FetchRatePerDomain)
		}

		select {
		case r.fetches <- struct{}{}:
		default:
			r.mu.Unlock()

			return nil, errTransient(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %d concurrent fetches is reached.", id, cap(r.fetches))
		}

		bucket.tokens--

		r.domains[domain]++

		call = &fetchCall{done: make(chan struct{})}
		r.inflight[id] = call

		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					call.record = nil
					call.err = errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The Client ID Metadata Document %q could not be fetched as a panic occurred: %v.", id, recovered))
				}

				r.mu.Lock()

				delete(r.inflight, id)

				if r.domains[domain]--; r.domains[domain] <= 0 {
					delete(r.domains, domain)
				}

				r.mu.Unlock()

				<-r.fetches

				close(call.done)
			}()

			fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*r.config.FetchTimeout)
			defer cancel()

			call.record, call.err = r.fetch(fetchCtx, id)

			// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.1
			if stale && call.err != nil && errors.Is(call.err, oauth2.ErrInvalidClient) {
				r.discard(context.WithoutCancel(ctx), id)
			}
		}()
	}

	r.mu.Unlock()

	select {
	case <-call.done:
		if call.err == nil && call.record == nil {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The Client ID Metadata Document '%s' could not be fetched.", id))
		}

		return call.record, call.err
	case <-ctx.Done():
		return nil, errTransient(ctx.Err(), "The request ended before the Client ID Metadata Document '%s' was fetched.", id)
	}
}

func (r *Resolver) fetch(ctx context.Context, id string) (record *oauth2.ClientIDMetadataDocumentRecord, err error) {
	requestCtx, cancel := context.WithTimeout(ctx, r.config.FetchTimeout)
	defer cancel()

	var request *retryablehttp.Request

	if request, err = retryablehttp.NewRequestWithContext(requestCtx, http.MethodGet, id, nil); err != nil {
		return nil, errResolve(err, "The request for the Client ID Metadata Document '%s' could not be built: %v.", id, err)
	}

	request.Header.Set("Accept", "application/json")

	var response *http.Response

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
	if response, err = oauth2.HTTPClientWithoutRedirects(r.config.HTTPClient).Do(request); err != nil {
		return nil, errTransient(err, "The Client ID Metadata Document '%s' could not be fetched: %v.", id, err)
	}

	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusOK:
	case response.StatusCode == http.StatusRequestTimeout, response.StatusCode == http.StatusTooManyRequests, response.StatusCode >= http.StatusInternalServerError:
		return nil, errTransient(nil, "The Client ID Metadata Document '%s' was served with the status code %d but 200 is required.", id, response.StatusCode)
	default:
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' was served with the status code %d but 200 is required.", id, response.StatusCode)
	}

	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4
	if mediaType != "application/json" && (!strings.HasPrefix(mediaType, "application/") || !strings.HasSuffix(mediaType, "+json")) {
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' was served with the media type '%s' which is not JSON.", id, mediaType)
	}

	var body []byte

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.11
	if body, err = io.ReadAll(io.LimitReader(response.Body, r.config.MaxBodyBytes+1)); err != nil {
		return nil, errTransient(err, "The Client ID Metadata Document '%s' could not be read: %v.", id, err)
	}

	if int64(len(body)) > r.config.MaxBodyBytes {
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' is larger than the limit of %d bytes.", id, r.config.MaxBodyBytes)
	}

	var metadata *oauth2.ClientRegistrationMetadata

	if metadata, err = parseDocument(id, body); err != nil {
		return nil, r.revokeOnMismatch(ctx, id, err)
	}

	if err = r.applyCeiling(ctx, metadata); err != nil {
		return nil, err
	}

	if r.config.Filter != nil {
		if err = r.config.Filter.FilterClientRegistrationMetadata(ctx, nil, metadata); err != nil {
			return nil, errResolve(err, "The Client ID Metadata Document %q was rejected: %s.", id, oauth2.ErrorToDebugRFC6749Error(err).Error())
		}

		applyDefaults(metadata)

		if err = validateAuthMethods(metadata); err != nil {
			return nil, err
		}

		if err = validateAuthKeys(metadata); err != nil {
			return nil, err
		}
	}

	for _, validator := range r.config.Validators {
		if err = validator.ValidateClientRegistrationMetadata(ctx, nil, metadata); err != nil {
			return nil, errResolve(err, "The Client ID Metadata Document %q was rejected: %s.", id, oauth2.ErrorToDebugRFC6749Error(err).Error())
		}
	}

	now := time.Now().UTC()

	policy := newCachePolicy(response.Header, now, r.config.MaxLifespan, r.config.DefaultLifespan)

	record = &oauth2.ClientIDMetadataDocumentRecord{
		ID:             id,
		Domain:         fetchDomain(id),
		Metadata:       metadata,
		FetchedAt:      now,
		ExpiresAt:      now.Add(policy.lifespan),
		MustRevalidate: policy.revalidate,
	}

	if !policy.store {
		if err = r.config.Storage.DeleteClientIDMetadataDocument(ctx, id); err != nil {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Document '%s' could not be deleted from storage: %v.", id, err))
		}

		return record, nil
	}

	if err = r.config.Storage.SetClientIDMetadataDocument(ctx, record); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Document '%s' could not be written to storage: %v.", id, err))
	}

	return record, nil
}

// revokeOnMismatch revokes the refresh tokens issued to the client when err is a 'client_id' mismatch, and returns err
// or the error revoking them.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6.1
func (r *Resolver) revokeOnMismatch(ctx context.Context, id string, err error) error {
	if !errors.Is(err, errClientIDMismatch) {
		return err
	}

	if rerr := r.config.Storage.RevokeClientIDMetadataDocumentRefreshTokens(ctx, id); rerr != nil {
		return errResolve(rerr, "The Client ID Metadata Document '%s' has a 'client_id' which does not match the URL it was fetched from, and the refresh tokens issued to the client could not be revoked: %v.", id, rerr)
	}

	return err
}

func (r *Resolver) discard(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(ctx, r.config.FetchTimeout)
	defer cancel()

	if record, err := r.config.Storage.GetClientIDMetadataDocument(ctx, id); err != nil || isUsableRecord(record, id) {
		return
	}

	_ = r.config.Storage.DeleteClientIDMetadataDocument(ctx, id)
}

func (r *Resolver) bucket(domain string, now time.Time) (bucket *fetchBucket) {
	burst := float64(r.config.FetchBurstPerDomain)

	if !now.Before(r.sweepAt) {
		r.sweepAt = now.Add(time.Second)

		for key, b := range r.buckets {
			if b.tokens+now.Sub(b.at).Seconds()*r.config.FetchRatePerDomain >= burst {
				delete(r.buckets, key)
			}
		}
	}

	var ok bool

	if bucket, ok = r.buckets[domain]; !ok {
		bucket = &fetchBucket{tokens: burst, at: now}
		r.buckets[domain] = bucket

		return bucket
	}

	if elapsed := now.Sub(bucket.at); elapsed > 0 {
		bucket.tokens = min(burst, bucket.tokens+elapsed.Seconds()*r.config.FetchRatePerDomain)
		bucket.at = now
	}

	return bucket
}

func (r *Resolver) prune() {
	now := time.Now()

	at := r.pruneAt.Load()

	if now.UnixNano() < at || !r.pruneAt.CompareAndSwap(at, now.Add(pruneInterval).UnixNano()) {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), pruneInterval)
		defer cancel()

		_ = r.config.Storage.DeleteExpiredClientIDMetadataDocuments(ctx, now.Add(-max(pruneInterval, r.config.StaleGracePeriod)))
	}()
}

func fetchDomain(id string) (domain string) {
	parsed, err := url.Parse(id)
	if err != nil {
		return ""
	}

	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")

	if addr, err := netip.ParseAddr(host); err == nil {
		if addr = addr.Unmap().WithZone(""); addr.Is4() {
			return addr.String()
		}

		prefix, _ := addr.Prefix(48)

		return prefix.String()
	}

	if domain, err = publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return host
	}

	return domain
}

func isUsableRecord(record *oauth2.ClientIDMetadataDocumentRecord, id string) (usable bool) {
	return record != nil && record.Metadata != nil && record.ID == id && time.Now().Before(record.ExpiresAt)
}

func (r *Resolver) newClient(ctx context.Context, record *oauth2.ClientIDMetadataDocumentRecord) (client oauth2.Client, err error) {
	var (
		data   []byte
		cloned = &oauth2.ClientIDMetadataDocumentRecord{}
	)

	if data, err = json.Marshal(record); err == nil {
		err = json.Unmarshal(data, cloned)
	}

	if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Document '%s' could not be copied: %v.", record.ID, err))
	}

	// A stored document is held to the scopes and grant types permitted now, not those permitted when it was stored.
	if cloned.Metadata != nil {
		if err = r.applyBounds(ctx, cloned.Metadata); err != nil {
			return nil, err
		}
	}

	if client, err = r.config.Strategy.NewClient(ctx, cloned); err != nil {
		return nil, err
	}

	if client == nil || client.GetID() != record.ID || !jwt.IsClientIDMetadataDocumentClient(client) {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The client strategy did not return a Client ID Metadata Document client with the identifier '%s'.", record.ID))
	}

	return client, nil
}

func errResolve(cause error, debug string, args ...any) (err error) {
	rfc := oauth2.ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used.").WithDebugf(debug, args...)

	if cause != nil {
		rfc = rfc.WithWrap(cause)
	}

	return errorsx.WithStack(rfc)
}

func errTransient(cause error, debug string, args ...any) (err error) {
	rfc := oauth2.ErrTemporarilyUnavailable.WithHint("The Client ID Metadata Document could not be retrieved.").WithDebugf(debug, args...)

	if cause != nil {
		rfc = rfc.WithWrap(cause)
	}

	return errorsx.WithStack(rfc)
}

var _ oauth2.ClientIDMetadataDocumentResolver = (*Resolver)(nil)
