// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

func discoverJWKSURI(ctx context.Context, config oauth2.HTTPClientProvider, issuer string) (uri string, err error) {
	location := strings.TrimSuffix(issuer, "/") + consts.WellKnownOpenIDConfiguration

	var req *retryablehttp.Request

	if req, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, location, nil); err != nil {
		return "", fmt.Errorf("unable to create the discovery request for the issuer '%s': %w", issuer, err)
	}

	req.Header.Set(consts.HeaderAccept, consts.MediaTypeApplicationJSON)

	var response *http.Response

	if response, err = oauth2.HTTPClientWithoutRedirects(config.GetHTTPClient(ctx)).Do(req); err != nil {
		return "", fmt.Errorf("unable to fetch the discovery metadata of the issuer '%s': %w", issuer, err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' returned the status code %d", issuer, response.StatusCode)
	}

	var metadata struct {
		Issuer         string `json:"issuer"`
		JSONWebKeysURI string `json:"jwks_uri"`
	}

	if err = json.NewDecoder(io.LimitReader(response.Body, oauth2.MaxFetchedBodyBytes)).Decode(&metadata); err != nil {
		return "", fmt.Errorf("unable to decode the discovery metadata of the issuer '%s': %w", issuer, err)
	}

	if metadata.Issuer != issuer {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' names the issuer '%s'", issuer, metadata.Issuer)
	}

	if metadata.JSONWebKeysURI == "" {
		return "", fmt.Errorf("the discovery metadata of the issuer '%s' has no 'jwks_uri'", issuer)
	}

	return metadata.JSONWebKeysURI, nil
}
