// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/gen"
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
	assert.Equal(t, symmetricKeyAlgorithms(), c.GetRequestObjectEncryptionAlgValues(ctx))
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

func TestConfigRequestObjectEncryptionAlgDefaultsFromDecryptionKeys(t *testing.T) {
	c := &Config{}
	c.JWTStrategy = &jwt.DefaultStrategy{Config: c, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: gen.MustRSAKey(), KeyID: "a", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		{Key: gen.MustRSAKey(), KeyID: "b", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		{Key: gen.MustES256Key(), KeyID: "c", Algorithm: string(jose.ECDH_ES_A128KW), Use: jwt.JSONWebTokenUseEncryption},
	}})}

	actual := c.GetRequestObjectEncryptionAlgValues(context.Background())

	assert.ElementsMatch(t, append(symmetricKeyAlgorithms(), string(jose.RSA_OAEP_256), string(jose.ECDH_ES_A128KW)), actual)
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

func TestConfigRSA15KeyManagement(t *testing.T) {
	targets := []ResponseEncryptionTarget{
		ResponseEncryptionTargetIDToken,
		ResponseEncryptionTargetUserInfo,
		ResponseEncryptionTargetAuthorization,
		ResponseEncryptionTargetIntrospection,
		ResponseEncryptionTargetAccessToken,
	}

	rsa15 := string(jose.RSA1_5)

	newConfig := func(enabled bool) *Config {
		c := &Config{EnableRSA15KeyManagement: enabled}
		c.JWTStrategy = &jwt.DefaultStrategy{Config: c, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustRSAKey(), KeyID: "a", Algorithm: rsa15, Use: jwt.JSONWebTokenUseEncryption},
			{Key: gen.MustRSAKey(), KeyID: "b", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		}})}

		return c
	}

	configured := func(c *Config) *Config {
		c.ClientAssertionEncryptionAlgValues = []string{rsa15, string(jose.RSA_OAEP)}
		c.RequestObjectEncryptionAlgValues = []string{rsa15, string(jose.RSA_OAEP)}
		c.ResponseEncryptionAlgValues = map[ResponseEncryptionTarget][]string{}

		for _, target := range targets {
			c.ResponseEncryptionAlgValues[target] = []string{rsa15, string(jose.RSA_OAEP)}
		}

		return c
	}

	t.Run("ShouldExcludeRSA15ByDefault", func(t *testing.T) {
		ctx := context.Background()
		c := newConfig(false)

		assert.False(t, c.GetEnableRSA15KeyManagement(ctx))
		assert.NotContains(t, c.GetClientAssertionEncryptionAlgValues(ctx), rsa15)
		assert.NotContains(t, c.GetRequestObjectEncryptionAlgValues(ctx), rsa15)
		assert.Contains(t, c.GetRequestObjectEncryptionAlgValues(ctx), string(jose.RSA_OAEP_256))

		for _, target := range targets {
			assert.NotContains(t, c.GetResponseEncryptionAlgValues(ctx, target), rsa15, string(target))
		}
	})

	t.Run("ShouldRemoveConfiguredRSA15ByDefault", func(t *testing.T) {
		ctx := context.Background()
		c := configured(newConfig(false))

		assert.Equal(t, []string{string(jose.RSA_OAEP)}, c.GetClientAssertionEncryptionAlgValues(ctx))
		assert.Equal(t, []string{string(jose.RSA_OAEP)}, c.GetRequestObjectEncryptionAlgValues(ctx))

		for _, target := range targets {
			assert.Equal(t, []string{string(jose.RSA_OAEP)}, c.GetResponseEncryptionAlgValues(ctx, target), string(target))
		}
	})

	t.Run("ShouldIncludeRSA15WhenEnabled", func(t *testing.T) {
		ctx := context.Background()
		c := newConfig(true)

		assert.True(t, c.GetEnableRSA15KeyManagement(ctx))
		assert.Equal(t, append([]string{rsa15}, algorithmStrings(jwt.EncryptionKeyAlgorithms)...), c.GetClientAssertionEncryptionAlgValues(ctx))
		assert.Contains(t, c.GetRequestObjectEncryptionAlgValues(ctx), rsa15)

		for _, target := range targets {
			assert.Equal(t, append([]string{rsa15}, algorithmStrings(jwt.EncryptionKeyAlgorithms)...), c.GetResponseEncryptionAlgValues(ctx, target), string(target))
		}
	})

	t.Run("ShouldKeepConfiguredRSA15WhenEnabled", func(t *testing.T) {
		ctx := context.Background()
		c := configured(newConfig(true))

		assert.Equal(t, []string{rsa15, string(jose.RSA_OAEP)}, c.GetClientAssertionEncryptionAlgValues(ctx))
		assert.Equal(t, []string{rsa15, string(jose.RSA_OAEP)}, c.GetRequestObjectEncryptionAlgValues(ctx))

		for _, target := range targets {
			assert.Equal(t, []string{rsa15, string(jose.RSA_OAEP)}, c.GetResponseEncryptionAlgValues(ctx, target), string(target))
		}
	})
}

func symmetricKeyAlgorithms() (algs []string) {
	for _, alg := range jwt.EncryptionKeyAlgorithms {
		if jwt.IsEncryptedJWTClientSecretAlg(alg) {
			algs = append(algs, string(alg))
		}
	}

	return algs
}
