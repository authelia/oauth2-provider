// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	oauth2jwt "authelia.com/provider/oauth2/token/jwt"
)

func TestHandlerTrustedIssuer(t *testing.T) {
	const (
		testClientID = "my-client"
		testJWKSURI  = "https://as.a.example/jwks"
	)

	client := func() *oauth2.DefaultClient {
		return &oauth2.DefaultClient{ID: testClientID, GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}
	}

	testCases := []struct {
		name    string
		setup   func(f *jwtBearerFixture) (assertion string)
		err     error
		hint    string
		subject string
		check   func(t *testing.T, f *jwtBearerFixture)
	}{
		{
			name: "ShouldSetTheResolvedSubject",
			setup: func(f *jwtBearerFixture) string {
				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldRejectAnUnknownIssuer",
			setup: func(f *jwtBearerFixture) string {
				cl := f.createStandardClaim()
				cl.Issuer = "unknown"

				return f.createTestAssertion(cl, keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldRejectAGrantSignedByAnotherKey",
			setup: func(f *jwtBearerFixture) string {
				jwk := f.createRandomTestJWK()
				jwk.KeyID = keyID

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.JSONWebKeys = f.createJWS(jwk) })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldRejectAnAlgorithmTheIssuerDoesNotPermit",
			setup: func(f *jwtBearerFixture) string {
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.SigningAlgs = []string{string(jose.ES256)} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldRejectAnHMACGrantEvenWhenListed",
			setup: func(f *jwtBearerFixture) string {
				secret := []byte("a-shared-secret-that-is-long-enough-for-hs256")

				f.handler.Config.(*oauth2.Config).RFC7523AssertionSigningAlgValues = []string{string(jose.HS256), string(jose.RS256)}

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.SigningAlgs = []string{string(jose.HS256)}
					trusted.JSONWebKeys = f.createJWS(jose.JSONWebKey{Key: secret, KeyID: keyID, Algorithm: string(jose.HS256), Use: consts.JSONWebTokenUseSignature})
				})

				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jose.JSONWebKey{Key: secret, KeyID: keyID}}, (&jose.SignerOptions{}).WithType("JWT"))
				require.NoError(f.t, err)

				assertion, err := jwt.Signed(signer).Claims(f.createStandardClaim()).Serialize()
				require.NoError(f.t, err)

				return assertion
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldVerifyWithAFetchedKeySet",
			setup: func(f *jwtBearerFixture) string {
				fetcher := &stubJWKSFetcher{jwks: f.createJWS(f.createJWK(f.privateKey.Public(), keyID))}

				f.handler.Config.(*oauth2.Config).JWKSFetcherStrategy = fetcher

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.JSONWebKeys = nil
					trusted.JSONWebKeysURI = testJWKSURI
				})

				f.t.Cleanup(func() {
					assert.Equal(f.t, []string{testJWKSURI}, fetcher.locations)
					assert.Equal(f.t, []bool{false}, fetcher.calls)
				})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldRefetchTheKeySetOnceForAGrantWithoutAKeyID",
			setup: func(f *jwtBearerFixture) string {
				fetcher := &stubJWKSFetcher{jwks: f.createJWS(f.createRandomTestJWK())}

				f.handler.Config.(*oauth2.Config).JWKSFetcherStrategy = fetcher

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.JSONWebKeys = nil
					trusted.JSONWebKeysURI = testJWKSURI
				})

				f.t.Cleanup(func() {
					assert.Equal(f.t, []bool{false, true}, fetcher.calls)
				})

				return f.createTestAssertion(f.createStandardClaim(), "")
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldNotRefetchTheKeySetWhenTheNamedKeyDoesNotVerify",
			setup: func(f *jwtBearerFixture) string {
				jwk := f.createRandomTestJWK()
				jwk.KeyID = keyID

				fetcher := &stubJWKSFetcher{jwks: f.createJWS(jwk)}

				f.handler.Config.(*oauth2.Config).JWKSFetcherStrategy = fetcher

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.JSONWebKeys = nil
					trusted.JSONWebKeysURI = testJWKSURI
				})

				f.t.Cleanup(func() {
					assert.Equal(f.t, []bool{false}, fetcher.calls)
				})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldAcceptASubjectTheIssuerLists",
			setup: func(f *jwtBearerFixture) string {
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Subjects = []string{"some_ro"} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldRejectASubjectTheIssuerDoesNotList",
			setup: func(f *jwtBearerFixture) string {
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Subjects = []string{"other"} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldRejectAnUnmappedSubject",
			setup: func(f *jwtBearerFixture) string {
				delete(f.memory.RFC7523Subjects, storage.RFC7523SubjectKey{Issuer: testTrustedIssuer, Subject: "some_ro"})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldAcceptAClientTheIssuerLists",
			setup: func(f *jwtBearerFixture) string {
				f.requester.Client = client()

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Clients = []string{testClientID} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldRejectAClientTheIssuerDoesNotList",
			setup: func(f *jwtBearerFixture) string {
				f.requester.Client = client()

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Clients = []string{"other-client"} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrAccessDenied,
		},
		{
			name: "ShouldRejectAPublicClientTheIssuerLists",
			setup: func(f *jwtBearerFixture) string {
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true

				c := client()
				c.Public = true

				f.requester.Client = c

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Clients = []string{testClientID} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrAccessDenied,
		},
		{
			name: "ShouldNotRevealAnIssuerRestrictedToClientsToAnotherClientWithoutAValidGrant",
			setup: func(f *jwtBearerFixture) string {
				f.requester.Client = client()

				jwk := f.createRandomTestJWK()
				jwk.KeyID = keyID

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.Clients = []string{"other-client"}
					trusted.JSONWebKeys = f.createJWS(jwk)
				})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldNotRevealAnIssuerRestrictedToClientsToAnAnonymousRequestWithoutAValidGrant",
			setup: func(f *jwtBearerFixture) string {
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Client = &oauth2.DefaultClient{}

				jwk := f.createRandomTestJWK()
				jwk.KeyID = keyID

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.Clients = []string{testClientID}
					trusted.JSONWebKeys = f.createJWS(jwk)
				})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldAcceptAnAnonymousRequestWhenPermitted",
			setup: func(f *jwtBearerFixture) string {
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Client = &oauth2.DefaultClient{}

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldRejectAnAnonymousRequestForAnIssuerRestrictedToClients",
			setup: func(f *jwtBearerFixture) string {
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Client = &oauth2.DefaultClient{}

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Clients = []string{testClientID} })

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrAccessDenied,
		},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
					f.requester.Form.Add(consts.FormParameterAssertion, tc.setup(f))

					err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

					assert.Equal(t, tc.subject, f.requester.GetSession().GetSubject())

					if tc.err == nil {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

						return
					}

					assert.ErrorIs(t, err, tc.err)

					if tc.hint != "" {
						assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
					}
				})
			}

			t.Run("ShouldRejectAReplayedGrant", func(t *testing.T) {
				shared := store.new()

				f := newJWTBearerFixture(t, shared)
				assertion := f.createTestAssertion(f.createStandardClaim(), keyID)

				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, assertion)
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder)))

				replay := newJWTBearerFixture(t, shared)

				replay.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				replay.requester.Form.Add(consts.FormParameterAssertion, assertion)

				err := replay.handler.HandleTokenEndpointRequest(replay.ctx, replay.requester)

				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				assert.Equal(t, hintRedeemed, oauth2.ErrorToRFC6749Error(err).HintField)
				assert.Empty(t, replay.requester.GetSession().GetSubject())
			})

			t.Run("ShouldNotConsumeAGrantThatIsRefused", func(t *testing.T) {
				shared := store.new()

				f := newJWTBearerFixture(t, shared)
				assertion := f.createTestAssertion(f.createStandardClaim(), keyID)

				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, assertion)
				f.requester.RequestedScope = []string{"wider_scope"}

				assert.ErrorIs(t, f.handler.HandleTokenEndpointRequest(f.ctx, f.requester), oauth2.ErrInvalidScope)

				again := newJWTBearerFixture(t, shared)

				again.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				again.requester.Form.Add(consts.FormParameterAssertion, assertion)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(again.handler.HandleTokenEndpointRequest(again.ctx, again.requester)))
				assert.Equal(t, "local_ro", again.requester.GetSession().GetSubject())
			})
		})
	}
}

func TestHandlerStorageResults(t *testing.T) {
	const testClientID = "my-client"

	boom := errors.New("boom")

	var (
		notFound       error = oauth2.ErrNotFound
		accessDenied   error = oauth2.ErrAccessDenied.WithHint("No license.")
		invalidRequest error = oauth2.ErrInvalidRequest
	)

	testCases := []struct {
		name    string
		setup   func(f *jwtBearerFixture) (assertion string)
		err     error
		not     error
		debug   string
		subject string
	}{
		{
			name: "ShouldAnswerServerErrorWhenTheIssuerLookupFails",
			setup: func(f *jwtBearerFixture) string {
				f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(nil, boom)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrServerError,
		},
		{
			name: "ShouldAnswerServerErrorForANilTrustedIssuer",
			setup: func(f *jwtBearerFixture) string {
				f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(nil, nil)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrServerError,
		},
		{
			name: "ShouldAnswerServerErrorWhenTheStoreReturnsAnotherIssuer",
			setup: func(f *jwtBearerFixture) string {
				trusted := f.createTrustedIssuer()
				trusted.Issuer = "https://other.example"

				f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(&trusted, nil)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err:   oauth2.ErrServerError,
			debug: "The storage returned a trusted issuer whose issuer is not the one requested.",
		},
		{
			name: "ShouldAnswerInvalidGrantForAWrappedNotFoundIssuer",
			setup: func(f *jwtBearerFixture) string {
				f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(nil, fmt.Errorf("lookup: %w", notFound))

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldAnswerInvalidGrantWhenTheSubjectIsNotFound",
			setup: func(f *jwtBearerFixture) string {
				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).Return("", fmt.Errorf("resolve: %w", notFound))

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldAnswerInvalidGrantForAnEmptySubject",
			setup: func(f *jwtBearerFixture) string {
				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).Return("", nil)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldPassThroughAccessDenied",
			setup: func(f *jwtBearerFixture) string {
				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).Return("", accessDenied)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrAccessDenied,
		},
		{
			name: "ShouldAnswerServerErrorForAnotherRFC6749Error",
			setup: func(f *jwtBearerFixture) string {
				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).Return("", invalidRequest)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrServerError,
			not: oauth2.ErrInvalidRequest,
		},
		{
			name: "ShouldAnswerServerErrorForAnyOtherResolverError",
			setup: func(f *jwtBearerFixture) string {
				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).Return("", boom)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrServerError,
			not: oauth2.ErrInvalidRequest,
		},
		{
			name: "ShouldPassTheVerifyingKeyIDAndANilClientToTheResolver",
			setup: func(f *jwtBearerFixture) string {
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Client = &oauth2.DefaultClient{}

				other := f.createRandomTestJWK()
				other.KeyID = "a"

				trusted := f.createTrustedIssuer()
				trusted.JSONWebKeys = f.createJWS(other, f.createJWK(f.privateKey.Public(), "b"))

				f.expectVerified(trusted)
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, client oauth2.Client, issuer *oauth2.RFC7523TrustedIssuer, kid string, claims map[string]any) (string, error) {
						assert.True(f.t, client == nil) //nolint:testifylint // A typed nil must fail.
						assert.Equal(f.t, "b", kid)
						assert.Equal(f.t, "some_ro", claims[consts.ClaimSubject])
						assert.Equal(f.t, &trusted, issuer)

						return "local_ro", nil
					})

				return f.createTestAssertion(f.createStandardClaim(), "")
			},
			subject: "local_ro",
		},
		{
			name: "ShouldPassTheAuthenticatedClientToTheResolver",
			setup: func(f *jwtBearerFixture) string {
				f.requester.Client = &oauth2.DefaultClient{ID: testClientID, GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}

				f.expectVerified(f.createTrustedIssuer())
				f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, client oauth2.Client, _ *oauth2.RFC7523TrustedIssuer, kid string, _ map[string]any) (string, error) {
						require.NotNil(f.t, client)
						assert.Equal(f.t, testClientID, client.GetID())
						assert.Equal(f.t, keyID, kid)

						return "local_ro", nil
					})

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			subject: "local_ro",
		},
		{
			name: "ShouldNotResolveASubjectTheIssuerDoesNotList",
			setup: func(f *jwtBearerFixture) string {
				trusted := f.createTrustedIssuer()
				trusted.Subjects = []string{"other"}

				f.expectVerified(trusted)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldRejectWhenTheUsedCheckFails",
			setup: func(f *jwtBearerFixture) string {
				trusted := f.createTrustedIssuer()

				f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(&trusted, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, testTrustedIssuer, "my_token").Return(false, boom)

				return f.createTestAssertion(f.createStandardClaim(), keyID)
			},
			err: oauth2.ErrServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWTBearerMockFixture(t)

			f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
			f.requester.Form.Add(consts.FormParameterAssertion, tc.setup(f))

			err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

			assert.Equal(t, tc.subject, f.requester.GetSession().GetSubject())

			if tc.err == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, tc.err)

			if tc.not != nil {
				assert.NotErrorIs(t, err, tc.not)
			}

			if tc.debug != "" {
				assert.Equal(t, tc.debug, oauth2.ErrorToRFC6749Error(err).DebugField)
			}
		})
	}
}

func TestHandlerRefusesItsOwnGrants(t *testing.T) {
	redeem := func(f *jwtBearerFixture, issuer string) error {
		f.handler.Config.(*oauth2.Config).RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693JWT: grantIssuerTokenType{issuer: issuer},
		}

		f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
		f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(f.createStandardClaim(), keyID))

		return f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)
	}

	t.Run("ShouldRejectAGrantFromAGrantIssuerOfThisServer", func(t *testing.T) {
		f := newJWTBearerMockFixture(t)

		err := redeem(f, testTrustedIssuer)

		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, hintAssertionUnverified, oauth2.ErrorToRFC6749Error(err).HintField)
		assert.Empty(t, f.requester.GetSession().GetSubject())
	})

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			t.Run("ShouldRejectAGrantFromAGrantIssuerOfThisServerItAlsoTrusts", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				assert.ErrorIs(t, redeem(f, testTrustedIssuer), oauth2.ErrInvalidGrant)
				assert.Empty(t, f.requester.GetSession().GetSubject())
			})

			t.Run("ShouldAcceptAGrantWhenNoTypeIssuesGrants", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(redeem(f, "")))
				assert.Equal(t, "local_ro", f.requester.GetSession().GetSubject())
			})

			t.Run("ShouldAcceptAGrantFromAnotherIssuer", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(redeem(f, "https://as.a.example/auth")))
				assert.Equal(t, "local_ro", f.requester.GetSession().GetSubject())
			})
		})
	}
}

func (f *jwtBearerFixture) expectVerified(trusted oauth2.RFC7523TrustedIssuer) {
	f.mockStore.EXPECT().GetRFC7523TrustedIssuer(f.ctx, testTrustedIssuer).Return(&trusted, nil)
	f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, testTrustedIssuer, "my_token").Return(false, nil)
}

type stubJWKSFetcher struct {
	jwks      *jose.JSONWebKeySet
	locations []string
	calls     []bool
}

func (s *stubJWKSFetcher) Resolve(_ context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	s.locations = append(s.locations, location)
	s.calls = append(s.calls, ignoreCache)

	return s.jwks, nil
}

var _ oauth2jwt.JWKSFetcherStrategy = (*stubJWKSFetcher)(nil)

type grantIssuerTokenType struct {
	issuer string
}

func (c grantIssuerTokenType) GetName(_ context.Context) (name string) {
	return consts.TokenTypeRFC8693JWT
}

func (c grantIssuerTokenType) GetType(_ context.Context) (tokenType string) {
	return consts.TokenTypeRFC8693JWT
}

func (c grantIssuerTokenType) GetAuthorizationGrantIssuer(_ context.Context) (issuer string) {
	return c.issuer
}

var _ oauth2.AuthorizationGrantIssuerProvider = grantIssuerTokenType{}
