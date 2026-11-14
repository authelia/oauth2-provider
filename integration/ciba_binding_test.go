// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestPollDPoPJKTEnforcedAtTokenEndpoint(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	thumbprint := func(t *testing.T, key *jose.JSONWebKey) string {
		t.Helper()

		pub := key.Public()

		jkt, err := jwt.ThumbprintJWK(&pub)
		require.NoError(t, err)

		return jkt
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			flow := newCIBAFlow(t, st.new)

			t.Run("ShouldRejectAProofForAnotherKeyThanTheDPoPJKT", func(t *testing.T) {
				bound, other := newDPoPProofKey(t), newDPoPProofKey(t)

				id := flow.authenticate(t, cibaClientID, &cibaRequestOptions{form: url.Values{consts.FormParameterDPoPJKT: {thumbprint(t, bound)}}})

				flow.approve(t)

				status, body := flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, other, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_dpop_proof", body["error"])

				status, body = flow.poll(t, cibaClientID, id, nil)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_dpop_proof", body["error"])

				status, body = flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, bound, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				assert.Equal(t, oauth2.DPoPAccessToken, body["token_type"])
			})

			t.Run("ShouldBindToTheProofPresentedAtTheBackChannelEndpoint", func(t *testing.T) {
				bound, other := newDPoPProofKey(t), newDPoPProofKey(t)

				id := flow.authenticate(t, cibaClientID, &cibaRequestOptions{dpop: signDPoPProof(t, bound, http.MethodPost, flow.ts.URL+"/bc-authorize", nil)})

				flow.approve(t)

				status, body := flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, other, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_dpop_proof", body["error"])

				status, body = flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, bound, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				assert.Equal(t, oauth2.DPoPAccessToken, body["token_type"])

				_, requester, err := flow.provider.IntrospectToken(context.Background(), body["access_token"].(string), oauth2.AccessToken, openid.NewDefaultSession())
				require.NoError(t, err)

				session, ok := requester.GetSession().(oauth2.DPoPBoundSession)
				require.True(t, ok)
				assert.Equal(t, thumbprint(t, bound), session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectAProofForTheTokenEndpointAtTheBackChannelEndpoint", func(t *testing.T) {
				status, body := flow.backchannel(t, cibaClientID, &cibaRequestOptions{dpop: signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_dpop_proof", body["error"])
			})

			t.Run("ShouldRejectADPoPJKTThatDisagreesWithTheProof", func(t *testing.T) {
				status, body := flow.backchannel(t, cibaClientID, &cibaRequestOptions{
					dpop: signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, flow.ts.URL+"/bc-authorize", nil),
					form: url.Values{consts.FormParameterDPoPJKT: {thumbprint(t, newDPoPProofKey(t))}},
				})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_dpop_proof", body["error"])
			})

			t.Run("ShouldBindAPollClientToTheCertificateAtTheTokenEndpoint", func(t *testing.T) {
				presented := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: cibaMTLSClientID}, SerialNumber: 101})
				rotated := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: cibaMTLSClientID}, SerialNumber: 102})

				id := flow.authenticate(t, cibaMTLSClientID, &cibaRequestOptions{certificate: presented})

				flow.approve(t)

				status, body := flow.poll(t, cibaMTLSClientID, id, &cibaRequestOptions{certificate: rotated})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)

				_, requester, err := flow.provider.IntrospectToken(context.Background(), body["access_token"].(string), oauth2.AccessToken, openid.NewDefaultSession())
				require.NoError(t, err)

				session, ok := requester.GetSession().(oauth2.MTLSBoundSession)
				require.True(t, ok)
				assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(rotated), session.GetClientCertificateSHA256Thumbprint())
			})
		})
	}
}

func TestPollKeyBoundIDToken(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			flow := newCIBAFlow(t, st.new, func(config *oauth2.Config) {
				config.OIDCKeyBindingEnabled = true
			})

			poll := func(t *testing.T, scope string, withheld ...string) (key *jose.JSONWebKey, body map[string]any) {
				t.Helper()

				key = newDPoPProofKey(t)

				id := flow.authenticate(t, cibaKeyBindingClientID, &cibaRequestOptions{
					dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+"/bc-authorize", nil),
					form: url.Values{consts.FormParameterScope: {scope}},
				})

				flow.approveScopes(t, withheld)

				status, body := flow.poll(t, cibaKeyBindingClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				require.NotEmpty(t, body["id_token"])

				return key, body
			}

			t.Run("ShouldBindTheIDTokenToTheProofKey", func(t *testing.T) {
				key, body := poll(t, cibaScope+" "+consts.ScopeBoundKey)

				header := cibaDecodeHeader(t, body["id_token"].(string))
				assert.Equal(t, consts.JSONWebTokenTypeDPoPIDToken, header[consts.JSONWebTokenHeaderType])

				claims := cibaDecodeClaims(t, body["id_token"].(string))

				cnf, ok := claims[consts.ClaimConfirmation].(map[string]any)
				require.True(t, ok, "cnf: %+v", claims[consts.ClaimConfirmation])

				raw, err := json.Marshal(cnf[consts.ClaimConfirmationJWK])
				require.NoError(t, err)

				var jwk jose.JSONWebKey

				require.NoError(t, jwk.UnmarshalJSON(raw))

				pub := key.Public()

				expected, err := jwt.ThumbprintJWK(&pub)
				require.NoError(t, err)

				actual, err := jwt.ThumbprintJWK(&jwk)
				require.NoError(t, err)

				assert.Equal(t, expected, actual)
			})

			t.Run("ShouldNotBindTheIDTokenWithoutBoundKey", func(t *testing.T) {
				_, body := poll(t, cibaScope)

				claims := cibaDecodeClaims(t, body["id_token"].(string))
				assert.NotContains(t, claims, consts.ClaimConfirmation)

				header := cibaDecodeHeader(t, body["id_token"].(string))
				assert.NotEqual(t, consts.JSONWebTokenTypeDPoPIDToken, header[consts.JSONWebTokenHeaderType])
			})

			t.Run("ShouldNotBindTheIDTokenWhenApprovalNarrowsBoundKeyAway", func(t *testing.T) {
				_, body := poll(t, cibaScope+" "+consts.ScopeBoundKey, consts.ScopeBoundKey)

				assert.Equal(t, oauth2.DPoPAccessToken, body["token_type"])
				assert.NotContains(t, strings.Fields(body["scope"].(string)), consts.ScopeBoundKey)

				claims := cibaDecodeClaims(t, body["id_token"].(string))
				assert.NotContains(t, claims, consts.ClaimConfirmation)

				header := cibaDecodeHeader(t, body["id_token"].(string))
				assert.NotEqual(t, consts.JSONWebTokenTypeDPoPIDToken, header[consts.JSONWebTokenHeaderType])
			})

			t.Run("ShouldRejectBoundKeyWithoutAProof", func(t *testing.T) {
				pub := newDPoPProofKey(t).Public()

				jkt, err := jwt.ThumbprintJWK(&pub)
				require.NoError(t, err)

				status, body := flow.backchannel(t, cibaKeyBindingClientID, &cibaRequestOptions{form: url.Values{
					consts.FormParameterScope:   {cibaScope + " " + consts.ScopeBoundKey},
					consts.FormParameterDPoPJKT: {jkt},
				}})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_request", body["error"])
			})
		})
	}
}

func cibaDecodeHeader(t *testing.T, token string) (header map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(raw, &header))

	return header
}

func TestPollLongPollingWithDPoP(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldEndTheHoldWhileTheProofIsFresh", func(t *testing.T) {
				flow := newCIBAFlow(t, st.new, func(config *oauth2.Config) {
					config.CIBALongPollingTimeout = 6 * time.Second
					config.DPoPProofLifespan = time.Second
					config.DPoPClockSkew = time.Second
				})

				key := newDPoPProofKey(t)

				id := flow.authenticate(t, cibaClientID, nil)

				start := time.Now()

				status, body := flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "authorization_pending", body["error"])
				assert.Less(t, time.Since(start), 3*time.Second)

				flow.approve(t)

				time.Sleep(time.Second)

				status, body = flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				require.Equal(t, http.StatusOK, status, "token error: %+v", body)
				assert.Equal(t, oauth2.DPoPAccessToken, body["token_type"])
			})

			t.Run("ShouldNotHoldAProofWithoutTheRequiredNonce", func(t *testing.T) {
				flow := newCIBAFlow(t, st.new, func(config *oauth2.Config) {
					config.CIBALongPollingTimeout = 6 * time.Second
					config.DPoPNonceRequired = true
				})

				id := flow.authenticate(t, cibaClientID, nil)

				start := time.Now()

				status, body := flow.poll(t, cibaClientID, id, &cibaRequestOptions{dpop: signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, flow.ts.URL+tokenRelativePath, nil)})
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Contains(t, []any{"authorization_pending", "use_dpop_nonce"}, body["error"])
				assert.Less(t, time.Since(start), time.Second)
			})
		})
	}
}
