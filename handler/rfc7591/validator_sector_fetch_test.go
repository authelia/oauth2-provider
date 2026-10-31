// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestSectorIdentifierValidatorBoundsTheFetch(t *testing.T) {
	metadata := &oauth2.ClientRegistrationMetadata{
		SectorIdentifierURI: "https://registrant.example.com/sector",
		RedirectURIs:        []string{"https://example.com/cb"},
	}

	newValidator := func(transport http.RoundTripper) *SectorIdentifierValidator {
		client := retryablehttp.NewClient()
		client.Logger = nil
		client.RetryMax = 1
		client.RetryWaitMin = time.Millisecond
		client.RetryWaitMax = 10 * time.Millisecond
		client.HTTPClient = &http.Client{Transport: transport}

		return NewSectorIdentifierValidator(&oauth2.Config{HTTPClient: client})
	}

	t.Run("ShouldApplyTheFetchTimeout", func(t *testing.T) {
		var deadline time.Time

		transport := sectorRoundTripper(func(r *http.Request) (*http.Response, error) {
			deadline, _ = r.Context().Deadline()

			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`["https://example.com/cb"]`)), Request: r}, nil
		})

		require.NoError(t, newValidator(transport).ValidateClientRegistrationMetadata(context.Background(), nil, metadata))

		require.False(t, deadline.IsZero())
		assert.LessOrEqual(t, time.Until(deadline), oauth2.FetchTimeout)
	})

	t.Run("ShouldNotWaitForAnUnboundedRetryAfter", func(t *testing.T) {
		attempts := 0

		transport := sectorRoundTripper(func(r *http.Request) (*http.Response, error) {
			attempts++

			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Retry-After": {"86400"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		start := time.Now()

		_ = newValidator(transport).ValidateClientRegistrationMetadata(ctx, nil, metadata)

		assert.Less(t, time.Since(start), 2*time.Second)
		assert.Equal(t, 2, attempts)
	})
}

type sectorRoundTripper func(r *http.Request) (*http.Response, error)

func (f sectorRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
