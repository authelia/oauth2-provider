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

	// OpenID Connect Dynamic Client Registration 1.0 Section 5 requires 'https'. There is no loopback exception, as
	// the registrant chooses the URI.
	if parsed.Scheme != consts.SchemeHTTPS {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must use the 'https' scheme.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI))
	}

	var req *retryablehttp.Request

	if req, err = retryablehttp.NewRequestWithContext(ctx, http.MethodGet, metadata.SectorIdentifierURI, nil); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' could not be used to construct an HTTP request.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	httpClient := v.config.GetHTTPClient(ctx)
	if httpClient == nil {
		httpClient = retryablehttp.NewClient()
	}

	var response *http.Response

	// Redirects are not followed, so a registrant-controlled server cannot steer the fetch to an internal address
	// (SSRF). A redirect response is rejected below by the non-200 status check.
	if response, err = oauth2.HTTPClientWithoutRedirects(httpClient).Do(req); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' could not be fetched.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' returned HTTP status code %d instead of the expected 200.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI, response.StatusCode))
	}

	var redirectURIs []string

	if err = json.NewDecoder(io.LimitReader(response.Body, SectorIdentifierMaxBodyBytes)).Decode(&redirectURIs); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' did not return a JSON array of redirect URI strings.", consts.ClientMetadataSectorIdentifierURI, metadata.SectorIdentifierURI).WithWrap(err).WithDebugError(err))
	}

	for _, redirectURI := range metadata.RedirectURIs {
		if !slices.Contains(redirectURIs, redirectURI) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' document does not contain the '%s' value '%s'.", consts.ClientMetadataSectorIdentifierURI, consts.ClientMetadataRedirectURIs, redirectURI))
		}
	}

	return nil
}

var (
	_ oauth2.ClientRegistrationValidator = (*SectorIdentifierValidator)(nil)
)
