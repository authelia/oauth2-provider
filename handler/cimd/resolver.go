// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// DefaultMaxBodyBytes is the default number of bytes read from a Client ID Metadata Document response.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.7
	DefaultMaxBodyBytes = 5120

	// DefaultMinLifespan is the default lower bound on how long a Client ID Metadata Document is cached.
	DefaultMinLifespan = 5 * time.Minute

	// DefaultMaxLifespan is the default upper bound on how long a Client ID Metadata Document is cached.
	DefaultMaxLifespan = 24 * time.Hour

	// DefaultLifespan is the default cache lifetime of a Client ID Metadata Document served without cache headers.
	DefaultLifespan = time.Hour

	// DefaultMaxConcurrentFetches is the default number of Client ID Metadata Document fetches in progress at once.
	DefaultMaxConcurrentFetches = 16

	// DefaultMaxConcurrentFetchesPerHost is the default number of Client ID Metadata Document fetches in progress at
	// once from one host.
	DefaultMaxConcurrentFetchesPerHost = 4

	fetchTimeout = 15 * time.Second
)

// Config configures a Resolver.
type Config struct {
	// Storage persists validated documents. Required.
	Storage oauth2.ClientIDMetadataDocumentStorage

	// HTTPClient fetches documents. Required. It must refuse special-use addresses, see
	// oauth2.NewSpecialUseAddressGuardedHTTPClient.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
	HTTPClient *retryablehttp.Client

	// Policy decides whether a valid Client Identifier URL may be resolved, before storage is read or a request is
	// made. A nil Policy allows every Client Identifier URL.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.9
	Policy func(ctx context.Context, id *url.URL) (err error)

	// Filter adjusts the metadata of a fetched document before Validators run. Optional. It runs after the document
	// is reduced to Scopes and GrantTypes, and a value it adds is kept, except a scope or grant type which is not in
	// Scopes or GrantTypes.
	Filter oauth2.ClientRegistrationMetadataStrategy

	// Validators run in order against the metadata of a fetched document. When nil, a single rfc7591.LocalValidator
	// built from ValidatorConfig is used. An empty non-nil slice runs none.
	//
	// A validator which fetches a URL from the document, such as rfc7591.SectorIdentifierValidator, must be built
	// with a provider of an HTTP client which refuses special-use addresses.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
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

	// MaxConcurrentFetches bounds the document fetches in progress at once. Defaults to 16.
	MaxConcurrentFetches int

	// MaxConcurrentFetchesPerHost bounds the document fetches in progress at once from one host, so that one host
	// can not occupy every fetch. Defaults to 4 and is never more than MaxConcurrentFetches.
	MaxConcurrentFetchesPerHost int

	// MaxBodyBytes is the number of bytes read from a response. A longer response is an error. Defaults to
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// MinLifespan and MaxLifespan bound the cache lifetime taken from the response headers, and DefaultLifespan
	// applies when there are none. They default to DefaultMinLifespan, DefaultMaxLifespan and DefaultLifespan.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.2
	MinLifespan     time.Duration
	MaxLifespan     time.Duration
	DefaultLifespan time.Duration
}

// Resolver is the default oauth2.ClientIDMetadataDocumentResolver. It fetches, validates and caches Client ID
// Metadata Documents.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5
type Resolver struct {
	config Config

	mu       sync.Mutex
	inflight map[string]*fetchCall
	fetches  chan struct{}
	hosts    map[string]int
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

	if config.MinLifespan <= 0 {
		config.MinLifespan = DefaultMinLifespan
	}

	if config.MaxLifespan <= 0 {
		config.MaxLifespan = DefaultMaxLifespan
	}

	if config.DefaultLifespan <= 0 {
		config.DefaultLifespan = DefaultLifespan
	}

	if config.MinLifespan > config.MaxLifespan {
		return nil, errors.New("cimd: the minimum lifespan is greater than the maximum lifespan")
	}

	if len(config.GrantTypes) == 0 {
		config.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}
	}

	if config.MaxConcurrentFetches <= 0 {
		config.MaxConcurrentFetches = DefaultMaxConcurrentFetches
	}

	if config.MaxConcurrentFetchesPerHost <= 0 {
		config.MaxConcurrentFetchesPerHost = DefaultMaxConcurrentFetchesPerHost
	}

	config.MaxConcurrentFetchesPerHost = min(config.MaxConcurrentFetchesPerHost, config.MaxConcurrentFetches)

	return &Resolver{config: config, inflight: map[string]*fetchCall{}, fetches: make(chan struct{}, config.MaxConcurrentFetches), hosts: map[string]int{}}, nil
}

// ResolveClientIDMetadataDocumentClient returns the client the Client ID Metadata Document at id describes. A
// document within its cache lifetime is served from storage. Otherwise it is fetched, and a failed fetch or an
// invalid document fails the request, is not stored, and deletes the record it would have replaced.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.2
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

	if record, err = r.refresh(ctx, id, err == nil); err != nil {
		return nil, err
	}

	return r.newClient(ctx, record)
}

func (r *Resolver) refresh(ctx context.Context, id string, stale bool) (record *oauth2.ClientIDMetadataDocumentRecord, err error) {
	host := fetchHost(id)

	r.mu.Lock()

	call, ok := r.inflight[id]
	if !ok {
		if r.hosts[host] >= r.config.MaxConcurrentFetchesPerHost && r.config.MaxConcurrentFetchesPerHost < cap(r.fetches) {
			r.mu.Unlock()

			return nil, errResolve(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %d concurrent fetches from its host is reached.", id, r.config.MaxConcurrentFetchesPerHost)
		}

		select {
		case r.fetches <- struct{}{}:
		default:
			r.mu.Unlock()

			return nil, errResolve(nil, "The Client ID Metadata Document '%s' was not fetched as the limit of %d concurrent fetches is reached.", id, cap(r.fetches))
		}

		r.hosts[host]++

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

				if r.hosts[host]--; r.hosts[host] <= 0 {
					delete(r.hosts, host)
				}

				r.mu.Unlock()

				<-r.fetches

				close(call.done)
			}()

			fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
			defer cancel()

			call.record, call.err = r.fetch(fetchCtx, id)

			// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5.1
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
		return nil, errResolve(ctx.Err(), "The request ended before the Client ID Metadata Document '%s' was fetched.", id)
	}
}

func (r *Resolver) fetch(ctx context.Context, id string) (record *oauth2.ClientIDMetadataDocumentRecord, err error) {
	var request *retryablehttp.Request

	if request, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, id, nil); err != nil {
		return nil, errResolve(err, "The request for the Client ID Metadata Document '%s' could not be built: %v.", id, err)
	}

	request.Header.Set("Accept", "application/json")

	var response *http.Response

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-5
	if response, err = oauth2.HTTPClientWithoutRedirects(r.config.HTTPClient).Do(request); err != nil {
		return nil, errResolve(err, "The Client ID Metadata Document '%s' could not be fetched: %v.", id, err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' was served with the status code %d but 200 is required.", id, response.StatusCode)
	}

	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4
	if mediaType != "application/json" && (!strings.HasPrefix(mediaType, "application/") || !strings.HasSuffix(mediaType, "+json")) {
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' was served with the media type '%s' which is not JSON.", id, mediaType)
	}

	var body []byte

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.7
	if body, err = io.ReadAll(io.LimitReader(response.Body, r.config.MaxBodyBytes+1)); err != nil {
		return nil, errResolve(err, "The Client ID Metadata Document '%s' could not be read: %v.", id, err)
	}

	if int64(len(body)) > r.config.MaxBodyBytes {
		return nil, errResolve(nil, "The Client ID Metadata Document '%s' is larger than the limit of %d bytes.", id, r.config.MaxBodyBytes)
	}

	var metadata *oauth2.ClientRegistrationMetadata

	if metadata, err = parseDocument(id, body); err != nil {
		return nil, err
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
	}

	for _, validator := range r.config.Validators {
		if err = validator.ValidateClientRegistrationMetadata(ctx, nil, metadata); err != nil {
			return nil, errResolve(err, "The Client ID Metadata Document %q was rejected: %s.", id, oauth2.ErrorToDebugRFC6749Error(err).Error())
		}
	}

	now := time.Now().UTC()

	record = &oauth2.ClientIDMetadataDocumentRecord{
		ID:        id,
		Metadata:  metadata,
		FetchedAt: now,
		ExpiresAt: now.Add(lifespan(response.Header, now, r.config.MinLifespan, r.config.MaxLifespan, r.config.DefaultLifespan)),
	}

	if err = r.config.Storage.SetClientIDMetadataDocument(ctx, record); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("The Client ID Metadata Document '%s' could not be written to storage: %v.", id, err))
	}

	return record, nil
}

func (r *Resolver) discard(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	if record, err := r.config.Storage.GetClientIDMetadataDocument(ctx, id); err != nil || isUsableRecord(record, id) {
		return
	}

	_ = r.config.Storage.DeleteClientIDMetadataDocument(ctx, id)
}

func fetchHost(id string) (host string) {
	parsed, err := url.Parse(id)
	if err != nil {
		return ""
	}

	return strings.ToLower(parsed.Host)
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

var _ oauth2.ClientIDMetadataDocumentResolver = (*Resolver)(nil)
