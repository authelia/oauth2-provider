// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientRegistrationResponseToMap(t *testing.T) {
	response := NewClientRegistrationResponse()

	response.SetMetadata(&ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
		ClientName:   "Example",
		Extra:        map[string]any{"vendor": "x"},
	})

	response.SetClientID("abc")
	response.SetClientSecret("the-secret")
	response.SetClientIDIssuedAt(time.Unix(1000, 0).UTC())
	response.SetClientSecretExpiresAt(time.Unix(2000, 0).UTC())
	response.SetRegistrationAccessToken("the-registration-access-token")
	response.SetRegistrationClientURI("https://auth.example.com/register/abc")

	values := response.ToMap()

	assert.Equal(t, "abc", values["client_id"])
	assert.Equal(t, "the-secret", values["client_secret"])
	assert.Equal(t, int64(1000), values["client_id_issued_at"])
	assert.Equal(t, int64(2000), values["client_secret_expires_at"])
	assert.Equal(t, "the-registration-access-token", values["registration_access_token"])
	assert.Equal(t, "https://auth.example.com/register/abc", values["registration_client_uri"])
	assert.Equal(t, "Example", values["client_name"])
	assert.Equal(t, "x", values["vendor"])

	// A never-expiring secret is reported as 0 per RFC 7591 Section 3.2.1.
	response.SetClientSecretExpiresAt(time.Time{})
	assert.Equal(t, int64(0), response.ToMap()["client_secret_expires_at"])

	response.SetClientSecret("")
	assert.NotContains(t, response.ToMap(), "client_secret")
	assert.NotContains(t, response.ToMap(), "client_secret_expires_at")

	assert.Equal(t, http.StatusOK, response.GetStatusCode())
	response.SetStatusCode(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, response.GetStatusCode())

	response.AddHeader("X-Test", "1")
	assert.Equal(t, "1", response.GetHeader().Get("X-Test"))
}

func TestClientRegistrationResponseToMapOmitsUnsetClientIDIssuedAt(t *testing.T) {
	response := NewClientRegistrationResponse()
	response.SetClientID("abc")

	assert.NotContains(t, response.ToMap(), "client_id_issued_at")

	response.SetClientIDIssuedAt(time.Unix(1000, 0).UTC())
	assert.Equal(t, int64(1000), response.ToMap()["client_id_issued_at"])

	response.SetClientIDIssuedAt(time.Time{})
	assert.NotContains(t, response.ToMap(), "client_id_issued_at")
}

func TestClientRegistrationResponseToMapDoesNotLeakExtraServerControlledKeys(t *testing.T) {
	response := NewClientRegistrationResponse()

	response.SetMetadata(&ClientRegistrationMetadata{
		ClientName: "Example",
		Extra: map[string]any{
			"client_secret":            "attacker-chosen-secret",
			"client_secret_expires_at": 999,
			"client_id_issued_at":      999,
		},
	})

	response.SetClientID("abc")
	values := response.ToMap()

	assert.NotContains(t, values, "client_secret")
	assert.NotContains(t, values, "client_secret_expires_at")
	assert.NotContains(t, values, "client_id_issued_at")
	assert.Equal(t, "Example", values["client_name"])
}

func TestClientRegistrationResponseToMapPreservesLargeNumbers(t *testing.T) {
	metadata := &ClientRegistrationMetadata{}

	require.NoError(t, json.Unmarshal([]byte(`{"vendor_serial":9007199254740993}`), metadata))

	response := NewClientRegistrationResponse()
	response.SetMetadata(metadata)
	response.SetClientID("abc")

	data, err := json.Marshal(response.ToMap())
	require.NoError(t, err)

	assert.Contains(t, string(data), `"vendor_serial":9007199254740993`)
}
