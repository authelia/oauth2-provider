// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestConfigAlgorithmDefaults(t *testing.T) {
	c := &Config{}
	ctx := context.Background()

	sigs := algorithmStrings(jwt.SignatureAlgorithms)
	sigsNone := algorithmStrings(jwt.SignatureAlgorithmsNone)
	algs := algorithmStrings(jwt.EncryptionKeyAlgorithms)
	encs := algorithmStrings(jwt.ContentEncryptionAlgorithms)

	assert.Equal(t, sigs, c.GetClientAssertionSigningAlgValues(ctx))
	assert.Equal(t, algs, c.GetClientAssertionEncryptionAlgValues(ctx))
	assert.Equal(t, encs, c.GetClientAssertionEncryptionEncValues(ctx))

	assert.Equal(t, sigsNone, c.GetRequestObjectSigningAlgValues(ctx))
	assert.Equal(t, algs, c.GetRequestObjectEncryptionAlgValues(ctx))
	assert.Equal(t, encs, c.GetRequestObjectEncryptionEncValues(ctx))

	assert.Contains(t, c.GetRFC7523AssertionSigningAlgValues(ctx), "HS256")
	assert.Contains(t, c.GetRFC7523AssertionSigningAlgValues(ctx), "EdDSA")
	assert.Contains(t, c.GetRFC7523AssertionSigningAlgValues(ctx), "Ed25519")
	assert.Contains(t, c.GetIDJAGRedeemSigningAlgValues(ctx), "EdDSA")
	assert.Contains(t, c.GetIDJAGRedeemSigningAlgValues(ctx), "Ed25519")
	assert.NotContains(t, c.GetIDJAGRedeemSigningAlgValues(ctx), "HS256")
	assert.NotContains(t, c.GetRFC7591TrustedIssuerSigningAlgValues(ctx), "HS256")
	assert.Contains(t, c.GetRFC7591TrustedIssuerSigningAlgValues(ctx), "Ed25519")

	for _, target := range []ResponseEncryptionTarget{
		ResponseEncryptionTargetIDToken,
		ResponseEncryptionTargetUserInfo,
		ResponseEncryptionTargetAuthorization,
		ResponseEncryptionTargetIntrospection,
		ResponseEncryptionTargetAccessToken,
	} {
		assert.Equal(t, algs, c.GetResponseEncryptionAlgValues(ctx, target), string(target))
		assert.Equal(t, encs, c.GetResponseEncryptionEncValues(ctx, target), string(target))
	}
}

func TestConfigAlgorithmOverrides(t *testing.T) {
	ctx := context.Background()

	c := &Config{
		ClientAssertionSigningAlgValues:      []string{"ES256"},
		ClientAssertionEncryptionAlgValues:   []string{"RSA-OAEP"},
		ClientAssertionEncryptionEncValues:   []string{"A128GCM"},
		RequestObjectSigningAlgValues:        []string{"none"},
		RequestObjectEncryptionAlgValues:     []string{"A128KW"},
		RequestObjectEncryptionEncValues:     []string{"A256GCM"},
		RFC7523AssertionSigningAlgValues:     []string{"RS256"},
		IDJAGRedeemSigningAlgValues:          []string{"PS256"},
		RFC7591TrustedIssuerSigningAlgValues: []string{"ES384"},
		ResponseEncryptionAlgValues:          map[ResponseEncryptionTarget][]string{ResponseEncryptionTargetUserInfo: {"RSA-OAEP-256"}},
		ResponseEncryptionEncValues:          map[ResponseEncryptionTarget][]string{ResponseEncryptionTargetUserInfo: {"A192GCM"}},
	}

	assert.Equal(t, []string{"ES256"}, c.GetClientAssertionSigningAlgValues(ctx))
	assert.Equal(t, []string{"RSA-OAEP"}, c.GetClientAssertionEncryptionAlgValues(ctx))
	assert.Equal(t, []string{"A128GCM"}, c.GetClientAssertionEncryptionEncValues(ctx))
	assert.Equal(t, []string{"none"}, c.GetRequestObjectSigningAlgValues(ctx))
	assert.Equal(t, []string{"A128KW"}, c.GetRequestObjectEncryptionAlgValues(ctx))
	assert.Equal(t, []string{"A256GCM"}, c.GetRequestObjectEncryptionEncValues(ctx))
	assert.Equal(t, []string{"RS256"}, c.GetRFC7523AssertionSigningAlgValues(ctx))
	assert.Equal(t, []string{"PS256"}, c.GetIDJAGRedeemSigningAlgValues(ctx))
	assert.Equal(t, []string{"ES384"}, c.GetRFC7591TrustedIssuerSigningAlgValues(ctx))

	assert.Equal(t, []string{"RSA-OAEP-256"}, c.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetUserInfo))
	assert.Equal(t, []string{"A192GCM"}, c.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetUserInfo))

	assert.Equal(t, algorithmStrings(jwt.EncryptionKeyAlgorithms), c.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetIDToken))
	assert.Equal(t, algorithmStrings(jwt.ContentEncryptionAlgorithms), c.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetIDToken))
}
