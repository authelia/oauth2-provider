// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

const (
	// DefaultMetadataTTL is how long Transmitter Configuration Metadata is cached when Config.MetadataTTL is not
	// positive.
	DefaultMetadataTTL = time.Hour

	maxCachedIssuers = 256
)

// Discover returns the Transmitter Configuration Metadata of the issuer, which must come from a trusted source such as
// the configuration of the administrator and never from a SET or a request. The document is fetched from the location
// oauth2.SSFConfigurationURL derives, without following a redirect, and must be a 200 response with the
// 'application/json' content type holding a JSON object. Members that are not understood are ignored. A document
// oauth2.ValidateSSFConfigurationForIssuer refuses is not used and not cached, and one whose 'issuer' is not the
// requested issuer is an error matching ErrIssuerMismatch. A valid document is cached for Config.MetadataTTL.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.4
func (r *Receiver) Discover(ctx context.Context, issuer string) (configuration *oauth2.SSFConfiguration, err error) {
	var location string

	if location, err = oauth2.SSFConfigurationURL(issuer); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the issuer of the transmitter is not valid: %w", err)
	}

	if configuration = r.metadata.get(issuer); configuration != nil {
		return configuration, nil
	}

	if configuration, err = r.fetchMetadata(ctx, issuer, location); err != nil {
		return nil, err
	}

	ttl := r.Config.MetadataTTL

	if ttl <= 0 {
		ttl = DefaultMetadataTTL
	}

	r.metadata.set(issuer, configuration, ttl)

	return cloneConfiguration(configuration), nil
}

func (r *Receiver) fetchMetadata(ctx context.Context, issuer, location string) (configuration *oauth2.SSFConfiguration, err error) {
	var client *retryablehttp.Client

	if client, err = r.httpClient(ctx); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata could not be fetched: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, oauth2.FetchTimeout)
	defer cancel()

	var req *retryablehttp.Request

	if req, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, location, nil); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata could not be fetched: %w", err)
	}

	req.Header.Set(consts.HeaderAccept, consts.MediaTypeApplicationJSON)

	var response *http.Response

	if response, err = client.Do(req); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata could not be fetched: %w", err)
	}

	defer response.Body.Close()

	// SSF Section 7.2: a successful response is a 200 with the 'application/json' content type.
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata could not be fetched: the status code is %d", response.StatusCode)
	}

	if !isJSONContentType(response.Header) {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata is not valid: the content type is not '%s'", consts.MediaTypeApplicationJSON)
	}

	limit := r.maxResponseBytes()

	var (
		data  []byte
		large bool
	)

	if data, large, err = readLimited(response.Body, limit); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata could not be read: %w", err)
	}

	if large {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata is not valid: the body is larger than %d bytes", limit)
	}

	if _, err = ssfjson.ParseObject(data); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata is not valid: the body is not a JSON object: %w", err)
	}

	configuration = &oauth2.SSFConfiguration{}

	// SSF Section 7.1: members that are not understood are ignored.
	if err = json.Unmarshal(data, configuration); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata is not valid: a member has the wrong type: %w", err)
	}

	// SSF Section 7.2.4: the 'issuer' must be identical to the issuer the location was derived from.
	if configuration.Issuer != issuer {
		return nil, wrapError("ssfreceiver: the transmitter configuration metadata is not valid", ErrIssuerMismatch)
	}

	if err = oauth2.ValidateSSFConfigurationForIssuer(configuration, issuer, r.Config.EnforceCAEPInteroperabilityProfile); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter configuration metadata is not valid: %w", err)
	}

	return configuration, nil
}

// httpClient returns the client for a request to a Transmitter, which refuses a special-use address unless
// Config.SpecialUseAddressGuard permits it and never follows a redirect.
func (r *Receiver) httpClient(ctx context.Context) (client *retryablehttp.Client, err error) {
	if client, err = oauth2.SpecialUseAddressGuardHTTPClient(ctx, r.Config.SpecialUseAddressGuard, r.baseHTTPClient()); err != nil {
		return nil, err
	}

	return oauth2.HTTPClientWithoutRedirects(client), nil
}

func (r *Receiver) baseHTTPClient() (client *retryablehttp.Client) {
	if r.Config.HTTPClient != nil {
		return r.Config.HTTPClient
	}

	r.clientOnce.Do(func() {
		r.client = retryablehttp.NewClient()

		// The default logger writes each request URL to the standard error.
		r.client.Logger = nil
	})

	return r.client
}

func (r *Receiver) maxResponseBytes() (limit int64) {
	if r.Config.MaxResponseBytes > 0 {
		return r.Config.MaxResponseBytes
	}

	return oauth2.MaxFetchedBodyBytes
}

type metadataEntry struct {
	configuration *oauth2.SSFConfiguration
	expires       time.Time
}

// metadataCache holds the valid Transmitter Configuration Metadata of at most maxCachedIssuers issuers. The zero value
// is ready for use.
type metadataCache struct {
	mu      sync.Mutex
	entries map[string]metadataEntry

	now func() time.Time
}

func (c *metadataCache) time() time.Time {
	if c.now != nil {
		return c.now()
	}

	return time.Now()
}

func (c *metadataCache) get(issuer string) (configuration *oauth2.SSFConfiguration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[issuer]
	if !ok {
		return nil
	}

	if !c.time().Before(entry.expires) {
		delete(c.entries, issuer)

		return nil
	}

	return cloneConfiguration(entry.configuration)
}

func (c *metadataCache) set(issuer string, configuration *oauth2.SSFConfiguration, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.time()

	if c.entries == nil {
		c.entries = map[string]metadataEntry{}
	}

	if _, ok := c.entries[issuer]; !ok && len(c.entries) >= maxCachedIssuers {
		c.evict(now)
	}

	c.entries[issuer] = metadataEntry{configuration: cloneConfiguration(configuration), expires: now.Add(ttl)}
}

// evict removes every expired entry, and the entry nearest its expiry when none has expired.
func (c *metadataCache) evict(now time.Time) {
	var (
		nearest string
		expires time.Time
	)

	for issuer, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, issuer)

			continue
		}

		if nearest == "" || entry.expires.Before(expires) {
			nearest, expires = issuer, entry.expires
		}
	}

	if len(c.entries) >= maxCachedIssuers {
		delete(c.entries, nearest)
	}
}

func cloneConfiguration(configuration *oauth2.SSFConfiguration) (clone *oauth2.SSFConfiguration) {
	c := *configuration

	c.DeliveryMethodsSupported = slices.Clone(configuration.DeliveryMethodsSupported)
	c.CriticalSubjectMembers = slices.Clone(configuration.CriticalSubjectMembers)
	c.AuthorizationSchemes = slices.Clone(configuration.AuthorizationSchemes)

	return &c
}
