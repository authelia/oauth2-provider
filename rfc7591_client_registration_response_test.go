// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

	// The secret is omitted entirely when there is none.
	response.SetClientSecret("")
	assert.NotContains(t, response.ToMap(), "client_secret")
	assert.NotContains(t, response.ToMap(), "client_secret_expires_at")

	assert.Equal(t, http.StatusOK, response.GetStatusCode())
	response.SetStatusCode(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, response.GetStatusCode())

	response.AddHeader("X-Test", "1")
	assert.Equal(t, "1", response.GetHeader().Get("X-Test"))
}

// TestClientRegistrationResponseToMapOmitsUnsetClientIDIssuedAt confirms that an unset ClientIDIssuedAt is omitted
// entirely from ToMap rather than emitted as 0. Unlike ClientSecretExpiresAt, 'client_id_issued_at' has no zero
// sentinel defined by RFC 7591, so emitting 0 would falsely assert the client was registered at the Unix epoch.
func TestClientRegistrationResponseToMapOmitsUnsetClientIDIssuedAt(t *testing.T) {
	response := NewClientRegistrationResponse()
	response.SetClientID("abc")

	assert.NotContains(t, response.ToMap(), "client_id_issued_at")

	response.SetClientIDIssuedAt(time.Unix(1000, 0).UTC())
	assert.Equal(t, int64(1000), response.ToMap()["client_id_issued_at"])

	response.SetClientIDIssuedAt(time.Time{})
	assert.NotContains(t, response.ToMap(), "client_id_issued_at")
}

// TestClientRegistrationResponseToMapDoesNotLeakExtraServerControlledKeys confirms that a client cannot inject
// values for server-controlled response keys by submitting them as unrecognized ('Extra') client metadata
// parameters. None of 'client_secret', 'client_secret_expires_at', or 'client_id_issued_at' are registered
// ClientRegistrationMetadata fields, so a client-submitted value for any of them is preserved in Extra and merged
// into the map by ClientRegistrationMetadata.MarshalJSON before the registration values are overlaid. When the
// server did not itself set a value for one of these keys, ToMap must delete it rather than leave the
// client-submitted value in place.
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
	// No client secret is issued and no client_id_issued_at is set: the public-client, no-timestamp case.

	values := response.ToMap()

	assert.NotContains(t, values, "client_secret")
	assert.NotContains(t, values, "client_secret_expires_at")
	assert.NotContains(t, values, "client_id_issued_at")
	assert.Equal(t, "Example", values["client_name"])
}
