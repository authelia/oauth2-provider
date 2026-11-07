// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestDiscoveryMetadataUniqueJSONNames(t *testing.T) {
	seen := map[string]string{}

	var walk func(rt reflect.Type, path string)

	walk = func(rt reflect.Type, path string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)

			if f.Anonymous {
				ft := f.Type
				if ft.Kind() == reflect.Ptr {
					ft = ft.Elem()
				}

				if ft.Kind() == reflect.Struct {
					walk(ft, path+"."+f.Name)

					continue
				}
			}

			if !f.IsExported() {
				continue
			}

			tag, ok := f.Tag.Lookup("json")
			if !assert.True(t, ok, "field %s.%s has no json tag", path, f.Name) {
				continue
			}

			name := strings.Split(tag, ",")[0]
			if prev, dup := seen[name]; dup {
				t.Errorf("json name %q is defined by both %s and %s.%s", name, prev, path, f.Name)
			}

			seen[name] = path + "." + f.Name
		}
	}

	walk(reflect.TypeOf(oauth2.OpenIDConnectProviderMetadata{}), "OpenIDConnectProviderMetadata")

	assert.Greater(t, len(seen), 100)
}

func TestDiscoveryMetadataNilExtensionsOmitted(t *testing.T) {
	data, err := json.Marshal(oauth2.OpenIDConnectProviderMetadata{OAuth2AuthorizationServerMetadata: oauth2.OAuth2AuthorizationServerMetadata{Issuer: "https://op"}})
	require.NoError(t, err)
	assert.Equal(t, `{"issuer":"https://op"}`, string(data))

	data, err = json.Marshal(oauth2.OAuth2AuthorizationServerMetadata{Issuer: "https://op"})
	require.NoError(t, err)
	assert.Equal(t, `{"issuer":"https://op"}`, string(data))
}

func TestDiscoveryMetadataRoundTrip(t *testing.T) {
	var metadata oauth2.OpenIDConnectProviderMetadata

	require.NoError(t, json.Unmarshal([]byte(`{"issuer":"https://op","dpop_signing_alg_values_supported":["ES256"],"end_session_endpoint":"https://op/logout","mtls_endpoint_aliases":{"token_endpoint":"https://mtls/token"}}`), &metadata))

	require.NotNil(t, metadata.RFC9449DPoPMetadata)
	assert.Equal(t, []string{"ES256"}, metadata.DPoPSigningAlgValuesSupported)
	require.NotNil(t, metadata.OpenIDConnectRPInitiatedLogoutMetadata)
	assert.Equal(t, "https://op/logout", metadata.EndSessionEndpoint)
	assert.Nil(t, metadata.RFC8628DeviceAuthorizationMetadata)
	assert.Nil(t, metadata.OpenIDFederationMetadata)

	require.NotNil(t, metadata.RFC8705MutualTLSMetadata)
	require.NotNil(t, metadata.MutualTLSEndpointAliases)
	assert.Equal(t, "https://mtls/token", metadata.MutualTLSEndpointAliases.Token)
}

func TestDiscoveryMetadataTrueDefaultBools(t *testing.T) {
	f := false

	data, err := json.Marshal(oauth2.OpenIDConnectProviderMetadata{RequestURIParameterSupported: &f})
	require.NoError(t, err)
	assert.Equal(t, `{"request_uri_parameter_supported":false}`, string(data))
}
