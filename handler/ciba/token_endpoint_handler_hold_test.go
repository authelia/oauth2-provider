// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

// FAPI 2.0 Security Profile Section 5.3.2.1.
func TestLongPollingTimeoutDPoPClockSkew(t *testing.T) {
	testCases := []struct {
		name  string
		fapi2 bool
		min   time.Duration
		max   time.Duration
	}{
		{name: "ShouldHoldForTheConfiguredSkew", min: 30 * time.Second, max: 30 * time.Second},
		{name: "ShouldHoldForTheSkewOfAFAPI2Client", fapi2: true, min: 8 * time.Second, max: 11 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &TokenHandler{Config: &oauth2.Config{
				CIBALongPollingTimeout: 30 * time.Second,
				DPoPEnabled:            true,
				DPoPProofLifespan:      time.Minute,
				DPoPClockSkew:          5 * time.Minute,
			}}

			now := time.Now()
			payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"iat":%d}`, now.Add(-110*time.Second).Unix()))

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil)
			r.Header.Set(consts.HeaderDPoP, "e30."+payload+".c2ln")

			ctx := context.WithValue(t.Context(), oauth2.RequestContextKey, r)

			var client oauth2.Client = &oauth2.DefaultClient{ID: "client"}

			if tc.fapi2 {
				client = &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client"}, FAPI2SecurityProfile: true}
			}

			timeout := handler.longPollingTimeout(ctx, client, now)

			assert.GreaterOrEqual(t, timeout, tc.min)
			assert.LessOrEqual(t, timeout, tc.max)
		})
	}
}
