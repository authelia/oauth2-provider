// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetRefreshTokenGracePeriod(t *testing.T) {
	grace := func(d time.Duration) *time.Duration { return &d }

	testCases := []struct {
		name     string
		config   RefreshTokenGracePeriodProvider
		client   Client
		expected time.Duration
	}{
		{"ShouldHaveNoneByDefault", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, 0},
		{"ShouldHaveNoneWithoutConfig", nil, &DefaultClient{}, 0},
		{"ShouldUseTheProviderValue", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultClient{}, time.Minute},
		{"ShouldInheritTheProviderValueWhenTheClientIsUnset", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, time.Minute},
		{"ShouldUseTheClientValueWhenTheProviderHasNone", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(time.Second)}, time.Second},
		{"ShouldUseTheClientValueWithoutConfig", nil, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(time.Second)}, time.Second},
		{"ShouldUseTheClientValueOverTheProviderValue", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(time.Second)}, time.Second},
		{"ShouldHaveNoneWhenTheClientDisables", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(0)}, 0},
		{"ShouldHaveNoneWhenTheClientValueIsNegative", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(-time.Second)}, 0},
		{"ShouldHaveNoneWhenTheProviderValueIsNegative", &Config{RefreshTokenGracePeriod: -time.Minute}, &DefaultClient{}, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetRefreshTokenGracePeriod(t.Context(), tc.config, tc.client))
		})
	}
}

func TestGetRefreshTokenGraceDeadlineForRequest(t *testing.T) {
	now := time.Now().UTC()
	grace := func(d time.Duration) *time.Duration { return &d }

	confidential := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "confidential"}}
	public := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "public", Public: true}}

	testCases := []struct {
		name     string
		config   RefreshTokenGracePeriodConfigProvider
		client   Client
		session  *DefaultSession
		expected time.Time
	}{
		{"ShouldHaveNoneByDefault", &Config{}, confidential, &DefaultSession{}, time.Time{}},
		{"ShouldHaveNoneWithoutConfig", nil, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(time.Minute)}, &DefaultSession{}, time.Time{}},
		{"ShouldApplyToAConfidentialClient", &Config{RefreshTokenGracePeriod: time.Minute}, confidential, &DefaultSession{}, now.Add(time.Minute)},
		{"ShouldApplyTheClientValue", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(time.Second)}, &DefaultSession{}, now.Add(time.Second)},
		{"ShouldHaveNoneWhenTheClientDisables", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RefreshTokenGracePeriod: grace(0)}, &DefaultSession{}, time.Time{}},
		{"ShouldHaveNoneForAPublicClientWithAnUnboundToken", &Config{RefreshTokenGracePeriod: time.Minute}, public, &DefaultSession{}, time.Time{}},
		{"ShouldHaveNoneForAPublicClientWhenDPoPIsDisabled", &Config{RefreshTokenGracePeriod: time.Minute}, public, &DefaultSession{JWKThumbprint: "jkt"}, time.Time{}},
		{"ShouldHaveNoneForAPublicClientWhenMTLSIsDisabled", &Config{RefreshTokenGracePeriod: time.Minute}, public, &DefaultSession{ClientCertificateThumbprint: "x5t"}, time.Time{}},
		{"ShouldApplyToAPublicClientWithADPoPBoundToken", &Config{RefreshTokenGracePeriod: time.Minute, DPoPEnabled: true}, public, &DefaultSession{JWKThumbprint: "jkt"}, now.Add(time.Minute)},
		{"ShouldApplyToAPublicClientWithACertificateBoundToken", &Config{RefreshTokenGracePeriod: time.Minute, MTLSEnabled: true}, public, &DefaultSession{ClientCertificateThumbprint: "x5t"}, now.Add(time.Minute)},
		{"ShouldHaveNoneWhenTheProviderDisablesRotation", &Config{RefreshTokenGracePeriod: time.Minute, DisableRefreshTokenRotation: true}, confidential, &DefaultSession{}, time.Time{}},
		{"ShouldHaveNoneWhenTheClientDisablesRotation", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, DisableRefreshTokenRotation: true}, &DefaultSession{}, time.Time{}},
		{"ShouldHaveNoneForAFAPI2SecurityProfileClient", &Config{RefreshTokenGracePeriod: time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, FAPI2SecurityProfile: true}, &DefaultSession{}, time.Time{}},
		{"ShouldEndWhenTheRefreshTokenExpires", &Config{RefreshTokenGracePeriod: time.Minute}, confidential, &DefaultSession{ExpiresAt: map[TokenType]time.Time{RefreshToken: now.Add(time.Second)}}, now.Add(time.Second)},
		{"ShouldNotBeLimitedByALaterExpiry", &Config{RefreshTokenGracePeriod: time.Minute}, confidential, &DefaultSession{ExpiresAt: map[TokenType]time.Time{RefreshToken: now.Add(time.Hour)}}, now.Add(time.Minute)},
		{"ShouldHaveNoneWhenTheRefreshTokenHasExpired", &Config{RefreshTokenGracePeriod: time.Minute}, confidential, &DefaultSession{ExpiresAt: map[TokenType]time.Time{RefreshToken: now}}, time.Time{}},
		{"ShouldHaveNoneWhenTheProviderValueIsNegative", &Config{RefreshTokenGracePeriod: -time.Minute}, confidential, &DefaultSession{}, time.Time{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &Request{Client: tc.client, Session: tc.session}

			assert.Equal(t, tc.expected, GetRefreshTokenGraceDeadlineForRequest(t.Context(), tc.config, request, now))
		})
	}
}

func TestGetRefreshTokenGraceDeadlineForRequestKeepsTheFirstDecision(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name     string
		session  *DefaultSession
		mutate   func(session *DefaultSession)
		later    time.Time
		expected time.Time
		computed time.Time
	}{
		{
			"ShouldIgnoreABindingRecordedForTheRequest",
			&DefaultSession{},
			func(session *DefaultSession) { session.SetDPoPJWKThumbprint("jkt") },
			now,
			time.Time{},
			now.Add(time.Minute),
		},
		{
			"ShouldIgnoreTheExpiryOfTheRotatedRefreshToken",
			&DefaultSession{JWKThumbprint: "jkt", ExpiresAt: map[TokenType]time.Time{RefreshToken: now.Add(time.Second)}},
			func(session *DefaultSession) { session.SetExpiresAt(RefreshToken, now.Add(time.Hour)) },
			now,
			now.Add(time.Second),
			now.Add(time.Minute),
		},
		{
			"ShouldIgnoreALaterTime",
			&DefaultSession{JWKThumbprint: "jkt"},
			func(session *DefaultSession) {},
			now.Add(time.Hour),
			now.Add(time.Minute),
			now.Add(time.Hour + time.Minute),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: true, RefreshTokenGracePeriod: time.Minute}

			request := NewAccessRequest(tc.session)
			request.Client = &DefaultClient{ID: "public", Public: true}

			assert.Equal(t, tc.expected, GetRefreshTokenGraceDeadlineForRequest(t.Context(), config, request, now))

			tc.mutate(tc.session)

			assert.Equal(t, tc.expected, GetRefreshTokenGraceDeadlineForRequest(t.Context(), config, request, tc.later))
			assert.Equal(t, tc.computed, GetRefreshTokenGraceDeadlineForRequest(t.Context(), config, &request.Request, tc.later))
		})
	}
}
