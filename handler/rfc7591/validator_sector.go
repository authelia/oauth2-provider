// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// sectorIdentifierMaxBodyBytes bounds the number of bytes read from a 'sector_identifier_uri' response body. The
// URI is client-supplied, so the fetch must not be allowed to consume unbounded memory.
const sectorIdentifierMaxBodyBytes = 1 << 20 // 1 MiB

// SectorIdentifierValidator is an oauth2.ClientRegistrationValidator implementing OpenID Connect Dynamic Client
// Registration 1.0 Section 5: when the client registers a 'sector_identifier_uri', the authorization server must
// dereference it and verify every registered 'redirect_uris' entry is present in the JSON array it returns. Unlike
// LocalValidator, this validator performs outbound HTTP.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation
type SectorIdentifierValidator struct {
	config oauth2.HTTPClientProvider
}

// NewSectorIdentifierValidator returns a new *SectorIdentifierValidator.
func NewSectorIdentifierValidator(config oauth2.HTTPClientProvider) (validator *SectorIdentifierValidator) {
	return &SectorIdentifierValidator{config: config}
}

// ValidateClientRegistrationMetadata validates the 'sector_identifier_uri' metadata, if present. client is nil on a
// client registration request, and the existing client on a client configuration request; neither is consulted by
// this check, which validates the incoming metadata in isolation.
func (v *SectorIdentifierValidator) ValidateClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata.SectorIdentifierURI == "" {
		return nil
	}

	var parsed *url.URL

	if parsed, err = url.Parse(metadata.SectorIdentifierURI); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' could not be parsed as a URI.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	// The specification requires 'https'. The loopback carve-out for plain 'http' exists only so the value is
	// testable (e.g. against an httptest.Server, which serves plain HTTP on a loopback host) and so local
	// development works; it is not sanctioned by the specification for general use.
	if parsed.Scheme != consts.SchemeHTTPS && !(parsed.Scheme == consts.SchemeHTTP && isLoopbackHost(parsed.Hostname())) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must use the 'https' scheme.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI))
	}

	var req *retryablehttp.Request

	if req, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, metadata.SectorIdentifierURI, nil); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' could not be used to construct an HTTP request.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	httpClient := v.config.GetHTTPClient(ctx)
	if httpClient == nil {
		// oauth2.Config.GetHTTPClient always falls back to retryablehttp.NewClient() when unconfigured, but the
		// oauth2.HTTPClientProvider interface itself does not guarantee a non-nil result, so guard against a
		// nil client from another implementation rather than panicking.
		httpClient = retryablehttp.NewClient()
	}

	var response *http.Response

	// withoutRedirects prevents the fetch from following any redirect the sector_identifier_uri server returns.
	// Without this, a registrant-controlled server behind a validly-scoped 'https' URI could 302 the fetch to an
	// internal, link-local, or loopback address, using this validator's redirect-URI containment check as a read
	// oracle against that address (SSRF). A redirect response is instead surfaced as-is and rejected below by the
	// non-200 status check, exactly like any other unexpected status code.
	if response, err = withoutRedirects(httpClient).Do(req); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' could not be fetched.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' returned HTTP status code %d instead of the expected 200.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI, response.StatusCode))
	}

	var redirectURIs []string

	if err = json.NewDecoder(io.LimitReader(response.Body, sectorIdentifierMaxBodyBytes)).Decode(&redirectURIs); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' did not return a JSON array of redirect URI strings.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	for _, redirectURI := range metadata.RedirectURIs {
		if !slices.Contains(redirectURIs, redirectURI) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' document does not contain the '%s' value '%s'.", consts.ClientMetadataSectorIdentifierURI, consts.ClientMetadataRedirectURIs, redirectURI))
		}
	}

	return nil
}

// withoutRedirects returns a *retryablehttp.Client that performs a 'sector_identifier_uri' fetch identically to
// client, except that it refuses to follow HTTP redirects: the first redirect response is returned as-is instead
// of being dereferenced. This is a fresh *retryablehttp.Client value built from client's exported configuration
// fields, not a mutation of client itself — client is typically the shared instance returned by
// oauth2.HTTPClientProvider.GetHTTPClient, and every other consumer of that shared instance must keep following
// redirects normally.
//
// client's unexported sync.Once guards are deliberately not copied (copying a sync.Once by value is unsafe once it
// may have fired); the returned Client starts with its own, unfired guards, which is safe because every field they
// guard (the resolved logger and the lazily-defaulted HTTPClient) is set explicitly below.
func withoutRedirects(client *retryablehttp.Client) (scoped *retryablehttp.Client) {
	refuseRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	inner := &http.Client{CheckRedirect: refuseRedirect}

	if client.HTTPClient != nil {
		innerCopy := *client.HTTPClient
		innerCopy.CheckRedirect = refuseRedirect
		inner = &innerCopy
	}

	return &retryablehttp.Client{
		HTTPClient:      inner,
		Logger:          client.Logger,
		RetryWaitMin:    client.RetryWaitMin,
		RetryWaitMax:    client.RetryWaitMax,
		RetryMax:        client.RetryMax,
		RequestLogHook:  client.RequestLogHook,
		ResponseLogHook: client.ResponseLogHook,
		CheckRetry:      client.CheckRetry,
		Backoff:         client.Backoff,
		ErrorHandler:    client.ErrorHandler,
		PrepareRetry:    client.PrepareRetry,
	}
}

var _ oauth2.ClientRegistrationValidator = (*SectorIdentifierValidator)(nil)
