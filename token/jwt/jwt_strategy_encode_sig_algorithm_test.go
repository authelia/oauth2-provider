// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestDefaultStrategyEncodeWithSigAlgorithm(t *testing.T) {
	f := getAlgorithmFixtures(t)

	permitted := []jose.SignatureAlgorithm{jose.PS256, jose.ES256, jose.EdDSA}

	testCases := []struct {
		name string
		opts []StrategyOpt
		algs []jose.SignatureAlgorithm
		err  string
	}{
		{
			name: "ShouldSignWithAnyAlgorithmWithoutTheOption",
			opts: []StrategyOpt{WithClient(f.client(jose.RS256, "", "", ""))},
		},
		{
			name: "ShouldSignWithAPermittedClientAlgorithm",
			opts: []StrategyOpt{WithClient(f.client(jose.PS256, "", "", ""))},
			algs: permitted,
		},
		{
			name: "ShouldSignAndEncryptWithAPermittedClientAlgorithm",
			opts: []StrategyOpt{WithClient(f.client(jose.ES256, jose.RSA_OAEP_256, encKID(jose.RSA_OAEP_256, ""), jose.A128GCM))},
			algs: permitted,
		},
		{
			name: "ShouldSignWithAPermittedIssuerAlgorithm",
			opts: []StrategyOpt{WithIssuerSigningAlg(string(jose.ES256))},
			algs: permitted,
		},
		{
			name: "ShouldRefuseAClientAlgorithmNotPermitted",
			opts: []StrategyOpt{WithClient(f.client(jose.RS256, "", "", ""))},
			algs: permitted,
			err:  "the signing algorithm 'RS256' is not permitted",
		},
		{
			name: "ShouldRefuseAClientSecretAlgorithmNotPermitted",
			opts: []StrategyOpt{WithClient(&testClient{id: "client", secret: f.secret, alg: string(jose.HS256), csigned: true})},
			algs: permitted,
			err:  "the signing algorithm 'HS256' is not permitted",
		},
		{
			name: "ShouldRefuseAnIssuerAlgorithmNotPermitted",
			opts: []StrategyOpt{WithIssuerSigningAlg(string(jose.RS256))},
			algs: permitted,
			err:  "the signing algorithm 'RS256' is not permitted",
		},
		{
			name: "ShouldRefuseTheDefaultIssuerAlgorithm",
			algs: permitted,
			err:  "the signing algorithm 'RS256' is not permitted",
		},
		{
			name: "ShouldRefuseAnEncryptedUnsignedToken",
			opts: []StrategyOpt{WithClient(&testClient{id: "client", alg: JSONWebTokenAlgNone, encKID: encKID(jose.RSA_OAEP_256, ""), encAlg: string(jose.RSA_OAEP_256), enc: string(jose.A128GCM), jwks: f.clientKeys}), WithAllowUnsignedEncrypted()},
			algs: permitted,
			err:  "an unsigned JWT is not permitted",
		},
		{
			name: "ShouldEncryptAnAllowedUnsignedTokenWithoutTheOption",
			opts: []StrategyOpt{WithClient(&testClient{id: "client", alg: JSONWebTokenAlgNone, encKID: encKID(jose.RSA_OAEP_256, ""), encAlg: string(jose.RSA_OAEP_256), enc: string(jose.A128GCM), jwks: f.clientKeys}), WithAllowUnsignedEncrypted()},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts

			if tc.algs != nil {
				opts = append(opts, WithSigAlgorithm(tc.algs...))
			}

			tokenString, _, err := f.strategy.Encode(t.Context(), MapClaims{ClaimSubject: "subject"}, opts...)

			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				assert.Empty(t, tokenString)

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, tokenString)
		})
	}
}
