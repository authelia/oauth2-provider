// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaPushClientID          = "ciba-push-client"
	cibaPushMTLSClientID      = "ciba-push-mtls-client"
	cibaPushNotificationToken = "push-notification-token"
	cibaPushEndpoint          = "https://client.example.com/cb"
)

type cibaPushNotifier struct {
	mu            sync.Mutex
	notifications []*oauth2.BackChannelNotification
}

func (n *cibaPushNotifier) NotifyBackChannelClient(_ context.Context, notification *oauth2.BackChannelNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifications = append(n.notifications, notification)

	return nil
}

// last returns the body of the latest notification.
func (n *cibaPushNotifier) last(t *testing.T) (body map[string]any) {
	t.Helper()

	n.mu.Lock()
	defer n.mu.Unlock()

	require.NotEmpty(t, n.notifications)

	body = map[string]any{}
	require.NoError(t, json.Unmarshal(n.notifications[len(n.notifications)-1].Body, &body))

	return body
}

// cibaPushMTLSClient is a push mode CIBA client which authenticates with 'tls_client_auth'.
type cibaPushMTLSClient struct {
	*oauth2.DefaultMTLSClient
}

func (c *cibaPushMTLSClient) GetBackChannelTokenDeliveryMode() string { return consts.CIBAModePush }

func (c *cibaPushMTLSClient) GetBackChannelClientNotificationEndpoint() string {
	return cibaPushEndpoint
}

func (c *cibaPushMTLSClient) GetBackChannelAuthenticationRequestSigningAlg() string { return "" }

func (c *cibaPushMTLSClient) GetBackChannelUserCodeParameter() bool { return false }

var cibaPushStores = []struct {
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

// newCIBAPushFlow returns a CIBA flow with push clients, recording the push notifications.
func newCIBAPushFlow(t *testing.T, newStore func() (any, map[string]oauth2.Client)) (*cibaFlow, *cibaPushNotifier) {
	t.Helper()

	notifier := &cibaPushNotifier{}

	flow := newCIBAFlow(t, func() (any, map[string]oauth2.Client) {
		store, clients := newStore()

		clients[cibaPushClientID] = &oauth2.DefaultCIBAClient{
			BackChannelTokenDeliveryMode:          consts.CIBAModePush,
			BackChannelClientNotificationEndpoint: cibaPushEndpoint,
			DefaultClient: &oauth2.DefaultClient{
				ID:           cibaPushClientID,
				ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
				GrantTypes:   []string{consts.GrantTypeRefreshToken},
				Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline},
			},
		}

		clients[cibaPushMTLSClientID] = &cibaPushMTLSClient{
			DefaultMTLSClient: &oauth2.DefaultMTLSClient{
				TLSClientAuthSubjectDN: "CN=" + cibaPushMTLSClientID,
				DefaultJARClient: &oauth2.DefaultJARClient{
					TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
					DefaultClient: &oauth2.DefaultClient{
						ID:                                    cibaPushMTLSClientID,
						GrantTypes:                            []string{consts.GrantTypeRefreshToken},
						Scopes:                                []string{consts.ScopeOpenID, consts.ScopeOffline},
						TLSClientCertificateBoundAccessTokens: true,
					},
				},
			},
		}

		return store, clients
	}, func(config *oauth2.Config) {
		config.BackChannelNotifier = notifier
	})

	return flow, notifier
}

func cibaPushOptions(opts *cibaRequestOptions) *cibaRequestOptions {
	if opts == nil {
		opts = &cibaRequestOptions{}
	}

	if opts.form == nil {
		opts.form = url.Values{}
	}

	opts.form.Set(consts.FormParameterClientNotificationToken, cibaPushNotificationToken)

	return opts
}

func TestPushDPoPBinding(t *testing.T) {
	for _, st := range cibaPushStores {
		t.Run(st.name, func(t *testing.T) {
			flow, notifier := newCIBAPushFlow(t, st.new)

			key := newDPoPProofKey(t)

			pub := key.Public()

			jkt, err := jwt.ThumbprintJWK(&pub)
			require.NoError(t, err)

			id := flow.authenticate(t, cibaPushClientID, cibaPushOptions(&cibaRequestOptions{dpop: signDPoPProof(t, key, http.MethodPost, flow.ts.URL+"/bc-authorize", nil)}))

			flow.approve(t)

			body := notifier.last(t)
			assert.Equal(t, id, body[consts.FormParameterAuthReqID])
			assert.Equal(t, oauth2.DPoPAccessToken, body[consts.AccessResponseTokenType])

			_, requester, err := flow.provider.IntrospectToken(context.Background(), body[consts.AccessResponseAccessToken].(string), oauth2.AccessToken, openid.NewDefaultSession())
			require.NoError(t, err)

			session, ok := requester.GetSession().(oauth2.DPoPBoundSession)
			require.True(t, ok)
			assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
		})
	}
}

func TestPushMTLSBinding(t *testing.T) {
	for _, st := range cibaPushStores {
		t.Run(st.name, func(t *testing.T) {
			flow, notifier := newCIBAPushFlow(t, st.new)

			certificate := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: cibaPushMTLSClientID}})

			id := flow.authenticate(t, cibaPushMTLSClientID, cibaPushOptions(&cibaRequestOptions{certificate: certificate}))

			flow.approve(t)

			body := notifier.last(t)
			assert.Equal(t, id, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "bearer", strings.ToLower(body[consts.AccessResponseTokenType].(string)))

			_, requester, err := flow.provider.IntrospectToken(context.Background(), body[consts.AccessResponseAccessToken].(string), oauth2.AccessToken, openid.NewDefaultSession())
			require.NoError(t, err)

			session, ok := requester.GetSession().(oauth2.MTLSBoundSession)
			require.True(t, ok)
			assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(certificate), session.GetClientCertificateSHA256Thumbprint())
		})
	}
}

func TestPushEquivalentToPoll(t *testing.T) {
	for _, st := range cibaPushStores {
		t.Run(st.name, func(t *testing.T) {
			flow, notifier := newCIBAPushFlow(t, st.new)

			id := flow.authenticate(t, cibaClientID, nil)

			flow.approve(t)

			status, poll := flow.poll(t, cibaClientID, id, nil)
			require.Equal(t, http.StatusOK, status, "token error: %+v", poll)

			flow.authenticate(t, cibaPushClientID, cibaPushOptions(nil))

			flow.approve(t)

			push := notifier.last(t)

			for _, body := range []map[string]any{poll, push} {
				assert.NotEmpty(t, body[consts.AccessResponseAccessToken])
				assert.NotEmpty(t, body[consts.AccessResponseIDToken])
			}

			assert.Equal(t, poll[consts.AccessResponseScope], push[consts.AccessResponseScope])
			assert.InDelta(t, poll[consts.AccessResponseExpiresIn], push[consts.AccessResponseExpiresIn], 1)
			assert.Equal(t, poll[consts.AccessResponseTokenType], push[consts.AccessResponseTokenType])
			assert.Equal(t, poll[consts.AccessResponseRefreshToken] != nil, push[consts.AccessResponseRefreshToken] != nil)
			assert.NotNil(t, push[consts.AccessResponseRefreshToken])

			pollClaims := cibaDecodeClaims(t, poll[consts.AccessResponseIDToken].(string))
			pushClaims := cibaDecodeClaims(t, push[consts.AccessResponseIDToken].(string))

			assert.Equal(t, pollClaims[consts.ClaimSubject], pushClaims[consts.ClaimSubject])
			assert.NotContains(t, pollClaims, consts.ClaimCIBAAuthReqID)
			assert.Contains(t, pushClaims, consts.ClaimCIBAAuthReqID)
		})
	}
}

func TestCIBAPushFlow(t *testing.T) {
	for _, st := range cibaPushStores {
		t.Run(st.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				payloads []map[string]any
				headers  []http.Header
			)

			notification := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)

				payload := map[string]any{}
				_ = json.Unmarshal(data, &payload)

				mu.Lock()
				payloads = append(payloads, payload)
				headers = append(headers, r.Header.Clone())
				mu.Unlock()

				rw.WriteHeader(http.StatusNoContent)
			}))

			t.Cleanup(notification.Close)

			flow := newCIBAFlow(t, func() (any, map[string]oauth2.Client) {
				store, clients := st.new()

				clients[cibaPushClientID] = &oauth2.DefaultCIBAClient{
					BackChannelTokenDeliveryMode:          consts.CIBAModePush,
					BackChannelClientNotificationEndpoint: notification.URL,
					DefaultClient: &oauth2.DefaultClient{
						ID:           cibaPushClientID,
						ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
						GrantTypes:   []string{consts.GrantTypeRefreshToken},
						Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline},
					},
				}

				return store, clients
			}, func(config *oauth2.Config) {
				config.BackChannelNotifier = oauth2.NewHTTPBackChannelNotifier(notification.Client())
			})

			id := flow.authenticate(t, cibaPushClientID, cibaPushOptions(nil))

			mu.Lock()
			require.Empty(t, payloads)
			mu.Unlock()

			flow.mu.Lock()
			requestID := flow.pending
			flow.mu.Unlock()

			loaded, err := flow.provider.NewBackChannelAuthenticationDecisionRequest(context.Background(), requestID, openid.NewDefaultSession())
			require.NoError(t, err)

			flow.approve(t)

			mu.Lock()
			require.Len(t, payloads, 1)

			payload := payloads[0]

			assert.Equal(t, "Bearer "+cibaPushNotificationToken, headers[0].Get(consts.HeaderAuthorization))
			mu.Unlock()

			assert.Equal(t, id, payload[consts.FormParameterAuthReqID])
			assert.NotEmpty(t, payload[consts.AccessResponseAccessToken])
			assert.NotEmpty(t, payload[consts.AccessResponseRefreshToken])

			raw, _ := payload[consts.AccessResponseIDToken].(string)
			require.NotEmpty(t, raw)

			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &flow.key.PublicKey, Algorithm: string(jose.RS256)}}}

			parsed, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)

			claims := map[string]any{}
			require.NoError(t, parsed.Claims(jwks.Keys[0].Public(), &claims))

			assert.Equal(t, testSubject, claims[consts.ClaimSubject])
			assert.Equal(t, id, claims[consts.ClaimCIBAAuthReqID])

			require.Len(t, parsed.Headers, 1)
			assert.Equal(t, string(jose.RS256), parsed.Headers[0].Algorithm)
			assert.Equal(t, cibaPushTestRS256Hash(payload[consts.AccessResponseAccessToken].(string)), claims[consts.ClaimAccessTokenHash])
			assert.Equal(t, cibaPushTestRS256Hash(payload[consts.AccessResponseRefreshToken].(string)), claims[consts.ClaimRefreshTokenHash])

			status, body := flow.poll(t, cibaPushClientID, id, nil)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "unauthorized_client", body["error"])

			status, refreshed := flow.token(t, cibaPushClientID, url.Values{
				consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: {payload[consts.AccessResponseRefreshToken].(string)},
			}, nil)
			require.Equal(t, http.StatusOK, status, "refresh error: %+v", refreshed)
			assert.NotEmpty(t, refreshed["access_token"])

			_, err = flow.provider.NewBackChannelAuthenticationDecisionRequest(context.Background(), requestID, openid.NewDefaultSession())
			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")

			for _, scope := range loaded.GetRequestedScopes() {
				loaded.GrantScope(scope)
			}

			again := openid.NewDefaultSession()
			again.Subject = testSubject
			again.Claims.Subject = testSubject

			_, err = flow.provider.ApproveBackChannelAuthentication(context.Background(), loaded, again)
			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")

			mu.Lock()
			assert.Len(t, payloads, 1)
			mu.Unlock()
		})
	}
}

// cibaPushTestRS256Hash returns the base64url encoding of the left-most half of the SHA-256 hash of the value, as the
// 'at_hash' and 'urn:openid:params:jwt:claim:rt_hash' claims of an RS256 ID Token are computed.
func cibaPushTestRS256Hash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
