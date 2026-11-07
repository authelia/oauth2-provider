// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const (
	discoveredJWKSURILifespan        = time.Hour
	discoveredJWKSURIFailureLifespan = time.Minute
	discoveryTimeout                 = 10 * time.Second
)

// jwksURIDiscovery caches the outcome of each issuer's discovery, a failure briefly and a success for longer, and merges
// concurrent lookups of the same issuer into one fetch.
type jwksURIDiscovery struct {
	mu      sync.Mutex
	entries map[string]*discoveredJWKSURI
}

type discoveredJWKSURI struct {
	done    chan struct{}
	uri     string
	err     error
	expires time.Time
}

func (e *discoveredJWKSURI) settled() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (d *jwksURIDiscovery) resolve(ctx context.Context, config oauth2.HTTPClientProvider, trusted oauth2.RFC7591TrustedIssuer) (uri string, err error) {
	if trusted.JSONWebKeysURI != "" {
		return trusted.JSONWebKeysURI, nil
	}

	d.mu.Lock()

	entry, ok := d.entries[trusted.Issuer]

	if !ok || (entry.settled() && !time.Now().Before(entry.expires)) {
		if d.entries == nil {
			d.entries = map[string]*discoveredJWKSURI{}
		}

		entry = &discoveredJWKSURI{done: make(chan struct{})}
		d.entries[trusted.Issuer] = entry

		d.mu.Unlock()

		// The fetch is shared by every waiting request, so it is bounded by its own timeout rather than the
		// cancellation of the request which happened to start it.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)

		entry.uri, entry.err = discoverJWKSURI(fetchCtx, config, trusted.Issuer)

		cancel()

		if entry.err == nil {
			entry.expires = time.Now().Add(discoveredJWKSURILifespan)
		} else {
			entry.expires = time.Now().Add(discoveredJWKSURIFailureLifespan)
		}

		close(entry.done)

		return entry.uri, entry.err
	}

	d.mu.Unlock()

	select {
	case <-entry.done:
		return entry.uri, entry.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// discoverJWKSURI returns the 'jwks_uri' of the issuer from the first discovery location, the RFC 8414 form then the
// OpenID Connect Discovery 1.0 form, whose document names the issuer and a 'jwks_uri'. A location which fails, answers
// with another status or names another issuer does not stop the next one being tried.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-5
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
func discoverJWKSURI(ctx context.Context, config oauth2.HTTPClientProvider, issuer string) (uri string, err error) {
	var locations [2]string

	if locations[0], err = oauth2.WellKnownURLInsert(issuer, consts.WellKnownOpenIDConfigurationSuffix); err != nil {
		return "", fmt.Errorf("unable to determine the discovery location of the issuer '%s': %w", issuer, err)
	}

	if locations[1], err = oauth2.WellKnownURLAppend(issuer, consts.WellKnownOpenIDConfigurationSuffix); err != nil {
		return "", fmt.Errorf("unable to determine the discovery location of the issuer '%s': %w", issuer, err)
	}

	count := 2
	if locations[0] == locations[1] {
		count = 1
	}

	errs := make([]error, 0, count)

	for i := 0; i < count; i++ {
		if uri, err = discoverJWKSURIAt(ctx, config, issuer, locations[i]); err == nil {
			return uri, nil
		}

		errs = append(errs, err)
	}

	return "", errors.Join(errs...)
}

func discoverJWKSURIAt(ctx context.Context, config oauth2.HTTPClientProvider, issuer, location string) (uri string, err error) {
	var (
		req      *retryablehttp.Request
		response *http.Response
	)

	if req, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, location, nil); err != nil {
		return "", fmt.Errorf("unable to create the discovery request for the issuer '%s' at '%s': %w", issuer, location, err)
	}

	req.Header.Set(consts.HeaderAccept, consts.MediaTypeApplicationJSON)

	if response, err = oauth2.HTTPClientWithoutRedirects(config.GetHTTPClient(ctx)).Do(req); err != nil {
		return "", fmt.Errorf("unable to fetch the discovery metadata of the issuer '%s' from '%s': %w", issuer, location, err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' at '%s' returned the status code %d", issuer, location, response.StatusCode)
	}

	var metadata struct {
		Issuer         string `json:"issuer"`
		JSONWebKeysURI string `json:"jwks_uri"`
	}

	if err = json.NewDecoder(io.LimitReader(response.Body, oauth2.MaxFetchedBodyBytes)).Decode(&metadata); err != nil {
		return "", fmt.Errorf("unable to decode the discovery metadata of the issuer '%s' at '%s': %w", issuer, location, err)
	}

	if metadata.Issuer != issuer {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' at '%s' names the issuer '%s'", issuer, location, metadata.Issuer)
	}

	if metadata.JSONWebKeysURI == "" {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' at '%s' has no 'jwks_uri'", issuer, location)
	}

	return metadata.JSONWebKeysURI, nil
}
