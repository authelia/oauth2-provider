// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestRedeemHandlerValidation(t *testing.T) {
	testCases := []struct {
		name    string
		mutate  func(claims map[string]any)
		typ     string
		alg     jose.SignatureAlgorithm
		kid     string
		forge   func(t *testing.T, f *redeemFixture, assertion string, claims map[string]any) string
		client  string
		grant   string
		scope   oauth2.Arguments
		dpop    bool
		setup   func(store *storage.MemoryStore)
		err     error
		subject string
		scopes  []string
	}{
		{name: "ShouldRedeem", subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldRedeemWithUpperCaseType", typ: "OAUTH-ID-JAG+JWT", subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldResolveSubject", setup: func(store *storage.MemoryStore) {
			store.IDJAGSubjects[storage.IDJAGSubjectKey{Issuer: redeemIssuer, Subject: redeemSubject}] = redeemAlice
		}, subject: redeemAlice, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldRejectUnresolvedSubject", setup: func(store *storage.MemoryStore) {
			clear(store.IDJAGSubjects)
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldNarrowToRequestedScope", scope: oauth2.Arguments{redeemRead}, subject: redeemSubject, scopes: []string{redeemRead}},
		{name: "ShouldAcceptSingleElementAudienceArray", mutate: func(c map[string]any) { c["aud"] = []string{redeemAudience} }, subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldRejectRequestedScopeOutsideGrant", scope: oauth2.Arguments{redeemAdmin}, err: oauth2.ErrInvalidScope},
		{name: "ShouldRejectUntrustedIssuer", mutate: func(c map[string]any) { c["iss"] = redeemEvil }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectClientNotPermittedForIssuer", setup: func(store *storage.MemoryStore) {
			trusted := store.IDJAGTrustedIssuers[redeemIssuer]
			trusted.Clients = []string{"someone-else"}
			store.IDJAGTrustedIssuers[redeemIssuer] = trusted
		}, err: oauth2.ErrInvalidGrant},
		// Section 9.3: the server MUST NOT redeem an ID-JAG it issued itself.
		{name: "ShouldRejectSelfIssued", setup: func(store *storage.MemoryStore) {
			trusted := store.IDJAGTrustedIssuers[redeemIssuer]
			trusted.Issuer = redeemAudience
			store.IDJAGTrustedIssuers[redeemAudience] = trusted
		}, mutate: func(c map[string]any) { c["iss"] = redeemAudience }, err: oauth2.ErrInvalidGrant},
		// Section 4.4.1: an array 'aud' MUST contain exactly one element.
		{name: "ShouldRejectMultiValuedAudience", mutate: func(c map[string]any) { c["aud"] = []string{redeemAudience, redeemOther} }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectWrongAudience", mutate: func(c map[string]any) { c["aud"] = redeemOther }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectClientIDMismatch", mutate: func(c map[string]any) { c["client_id"] = "other" }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMissingClientID", mutate: func(c map[string]any) { delete(c, "client_id") }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMissingJTI", mutate: func(c map[string]any) { delete(c, "jti") }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMissingIAT", mutate: func(c map[string]any) { delete(c, "iat") }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMissingSub", mutate: func(c map[string]any) { delete(c, "sub") }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectExpired", mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectFutureIAT", mutate: func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectAuthorizationDetailsClaim", mutate: func(c map[string]any) { c[consts.ClaimAuthorizationDetails] = []any{} }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectUnlistedAlgorithm", alg: jose.PS256, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectSymmetricAlgorithm", alg: jose.HS256, err: oauth2.ErrInvalidGrant},
		{name: "ShouldAcceptKeyWithoutUseOrAlg", setup: func(store *storage.MemoryStore) {
			trusted := store.IDJAGTrustedIssuers[redeemIssuer]
			key := trusted.JSONWebKeys.Keys[0]
			key.Use, key.Algorithm = "", ""
			trusted.JSONWebKeys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}
			store.IDJAGTrustedIssuers[redeemIssuer] = trusted
		}, subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldRejectKeyWithMismatchedAlg", setup: func(store *storage.MemoryStore) {
			trusted := store.IDJAGTrustedIssuers[redeemIssuer]
			key := trusted.JSONWebKeys.Keys[0]
			key.Algorithm = string(jose.ES256)
			trusted.JSONWebKeys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}
			store.IDJAGTrustedIssuers[redeemIssuer] = trusted
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectKeyForEncryptionUse", setup: func(store *storage.MemoryStore) {
			trusted := store.IDJAGTrustedIssuers[redeemIssuer]
			key := trusted.JSONWebKeys.Keys[0]
			key.Use = "enc"
			trusted.JSONWebKeys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}
			store.IDJAGTrustedIssuers[redeemIssuer] = trusted
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectSignatureFromAnotherKey", forge: func(t *testing.T, f *redeemFixture, _ string, claims map[string]any) string {
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			return (&redeemFixture{private: other}).sign(t, claims, "", "", "")
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectTamperedPayload", forge: func(t *testing.T, _ *redeemFixture, assertion string, claims map[string]any) string {
			claims[consts.ClaimSubject] = "attacker"

			payload, err := json.Marshal(claims)
			require.NoError(t, err)

			parts := strings.Split(assertion, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString(payload)

			return strings.Join(parts, ".")
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectUnknownKeyID", kid: "rotated-away", err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectClientWithoutGrantType", client: redeemNoGrant, err: oauth2.ErrUnauthorizedClient},
		// Section 9.1: the grant is for confidential clients.
		{name: "ShouldRejectPublicClient", client: redeemPublic, mutate: func(c map[string]any) { c["client_id"] = redeemPublic }, err: oauth2.ErrUnauthorizedClient},
		// Section 9.8.1.2: the binding is enforced in the binding phase, not recorded by the grant.
		{name: "ShouldAcceptConfirmation", dpop: true, mutate: func(c map[string]any) { c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT} }, subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldFailClosedWhenDPoPDisabled", mutate: func(c map[string]any) { c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT} }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectUnsupportedConfirmation", dpop: true, mutate: func(c map[string]any) { c["cnf"] = map[string]any{"x5t#S256": "abc"} }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMalformedThumbprint", dpop: true, mutate: func(c map[string]any) { c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: "short"} }, err: oauth2.ErrInvalidGrant},
		// Section 9.8.1.2.1: a DPoP-bound grant presented with the 'jwt-dpop' grant type.
		{name: "ShouldRedeemBoundGrantWithJWTDPoP", grant: consts.GrantTypeOAuthJWTDPoP, client: redeemDPoP, dpop: true, mutate: func(c map[string]any) {
			c["client_id"] = redeemDPoP
			c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT}
		}, subject: redeemSubject, scopes: []string{redeemRead, redeemHistory}},
		{name: "ShouldRejectUnboundGrantWithJWTDPoP", grant: consts.GrantTypeOAuthJWTDPoP, client: redeemDPoP, dpop: true, mutate: func(c map[string]any) { c["client_id"] = redeemDPoP }, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectBoundGrantWithJWTDPoPWhenDPoPDisabled", grant: consts.GrantTypeOAuthJWTDPoP, client: redeemDPoP, mutate: func(c map[string]any) {
			c["client_id"] = redeemDPoP
			c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT}
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectClientWithoutJWTDPoPGrantType", grant: consts.GrantTypeOAuthJWTDPoP, dpop: true, mutate: func(c map[string]any) { c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT} }, err: oauth2.ErrUnauthorizedClient},
		{name: "ShouldRejectClientWithoutJWTBearerGrantType", client: redeemDPoP, mutate: func(c map[string]any) { c["client_id"] = redeemDPoP }, err: oauth2.ErrUnauthorizedClient},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, tc.dpop)

			if tc.setup != nil {
				tc.setup(fixture.store)
			}

			claims := fixture.claims()
			if tc.mutate != nil {
				tc.mutate(claims)
			}

			assertion := fixture.sign(t, claims, tc.typ, tc.alg, tc.kid)

			if tc.forge != nil {
				assertion = tc.forge(t, fixture, assertion, claims)
			}

			client := tc.client
			if client == "" {
				client = redeemClient
			}

			request := newRedeemRequest(fixture.store.Clients[client], assertion, tc.scope)
			setGrantType(request, tc.grant)

			err := fixture.handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.subject, request.GetSession().GetSubject())
			assert.ElementsMatch(t, tc.scopes, request.GetGrantedScopes())
			assert.ElementsMatch(t, oauth2.Arguments{redeemResource}, request.GetGrantedResource())

			if tc.dpop {
				assert.Empty(t, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPJWKThumbprint())
			}
		})
	}
}

func TestRedeemHandlerReplay(t *testing.T) {
	type step struct {
		request  int
		populate bool
		err      error
	}

	testCases := []struct {
		name      string
		singleUse bool
		steps     []step
	}{
		// Section 4.4.3: the client MAY present the same grant again until it expires.
		{name: "ShouldPermitReuseByDefault", steps: []step{{request: 0, populate: true}, {request: 1, populate: true}}},
		// RFC 7521 Section 4.1.1: a replayed assertion is an invalid grant.
		{name: "ShouldRejectReuseWhenSingleUse", singleUse: true, steps: []step{{request: 0, populate: true}, {request: 1, err: oauth2.ErrInvalidGrant}}},
		{name: "ShouldNotConsumeAnUnissuedGrant", singleUse: true, steps: []step{{request: 0}, {request: 1, populate: true}}},
		{name: "ShouldRejectAConcurrentSecondUse", singleUse: true, steps: []step{{request: 0}, {request: 1}, {request: 0, populate: true}, {request: 1, populate: true, err: oauth2.ErrInvalidGrant}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, false)
			fixture.config.IDJAGSingleUse = tc.singleUse

			assertion := fixture.sign(t, fixture.claims(), "", "", "")
			client := fixture.store.Clients[redeemClient]

			requests := []*oauth2.AccessRequest{newRedeemRequest(client, assertion, nil), newRedeemRequest(client, assertion, nil)}
			handled := make([]bool, len(requests))

			for _, st := range tc.steps {
				request := requests[st.request]

				var err error

				if !handled[st.request] {
					handled[st.request] = true
					err = fixture.handler.HandleTokenEndpointRequest(t.Context(), request)
				}

				if err == nil && st.populate {
					err = fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())
				}

				if st.err != nil {
					require.ErrorIs(t, err, st.err)

					continue
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			}
		})
	}
}

func TestRedeemHandlerDispatch(t *testing.T) {
	testCases := []struct {
		name   string
		grants oauth2.Arguments
		typ    string
		can    bool
		err    error
	}{
		{name: "ShouldLeaveAnotherJWTBearerAssertion", grants: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer}, typ: consts.JSONWebTokenTypeJWT, err: oauth2.ErrUnknownRequest},
		{name: "ShouldLeaveAnotherJWTDPoPAssertion", grants: oauth2.Arguments{consts.GrantTypeOAuthJWTDPoP}, typ: consts.JSONWebTokenTypeJWT, err: oauth2.ErrUnknownRequest},
		{name: "ShouldHandleJWTBearer", grants: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer}, can: true},
		// Section 9.8.1.2.1: the 'jwt-dpop' grant type.
		{name: "ShouldHandleJWTDPoP", grants: oauth2.Arguments{consts.GrantTypeOAuthJWTDPoP}, can: true},
		{name: "ShouldNotHandleOtherGrantTypes", grants: oauth2.Arguments{consts.GrantTypeClientCredentials}, err: oauth2.ErrUnknownRequest},
		{name: "ShouldNotHandleSeveralGrantTypes", grants: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer, consts.GrantTypeOAuthJWTDPoP}, err: oauth2.ErrUnknownRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, true)
			client := fixture.store.Clients[redeemClient].(*oauth2.DefaultClient)
			client.GrantTypes = oauth2.Arguments{consts.GrantTypeOAuthJWTBearer, consts.GrantTypeOAuthJWTDPoP}

			claims := fixture.claims()
			claims[consts.ClaimConfirmation] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT}

			request := newRedeemRequest(client, fixture.sign(t, claims, tc.typ, "", ""), nil)
			request.GrantTypes = tc.grants

			assert.Equal(t, tc.can, fixture.handler.CanHandleTokenEndpointRequest(t.Context(), request))
			assert.False(t, fixture.handler.CanSkipClientAuth(t.Context(), request))

			err := fixture.handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.ErrorIs(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			require.NoError(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()))
		})
	}
}

func TestRedeemHandlerPopulate(t *testing.T) {
	fixture := newRedeemFixture(t, false)
	client := fixture.store.Clients[redeemClient]

	fixture.claimsScope = "chat.read offline_access"

	request := newRedeemRequest(client, fixture.sign(t, fixture.claims(), "", "", ""), oauth2.Arguments{redeemOffline, redeemRead})

	require.NoError(t, fixture.handler.HandleTokenEndpointRequest(t.Context(), request))

	response := oauth2.NewAccessResponse()
	require.NoError(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, response))

	assert.NotEmpty(t, response.GetAccessToken())
	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
	// Section 4.4.3: no refresh token, even when 'offline_access' is granted.
	assert.Empty(t, response.GetExtra(consts.AccessResponseRefreshToken))
	assert.Equal(t, []string{redeemOffline, redeemRead}, []string(request.GetGrantedScopes()))
	assert.Equal(t, redeemSubject, request.GetSession().(*redeemSession).claims[consts.ClaimSubject])
}

func TestRedeemHandlerResource(t *testing.T) {
	testCases := []struct {
		name      string
		claim     any
		permitted []string
		requested []string
		err       error
		granted   []string
		response  any
	}{
		{name: "ShouldOmitResourceWhenNoneIsGranted", claim: nil},
		// Section 4.4.1: the granted resource is included in the access token response.
		{name: "ShouldRespondWithASingleResource", claim: redeemResource, granted: []string{redeemResource}, response: redeemResource},
		{name: "ShouldRespondWithSeveralResources", claim: []string{redeemResource, redeemOther}, permitted: []string{redeemResource, redeemOther}, granted: []string{redeemResource, redeemOther}, response: []string{redeemResource, redeemOther}},
		{name: "ShouldRespondWithOnlyTheGrantedResource", claim: []string{redeemResource, redeemOther}, granted: []string{redeemResource}, response: redeemResource},
		// RFC 8707 Section 2: the access token stays audience restricted to the resources of the grant.
		{name: "ShouldRejectAGrantWhoseResourcesAreNotPermitted", claim: redeemOther, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARequestedResourceTheClientIsNotPermitted", claim: []string{redeemResource, redeemOther}, requested: []string{redeemOther}, err: oauth2.ErrInvalidTarget},
		// RFC 8707 Section 2.2: a requested resource narrows the grant.
		{name: "ShouldNarrowToTheRequestedResource", claim: []string{redeemResource, redeemOther}, permitted: []string{redeemResource, redeemOther}, requested: []string{redeemOther}, granted: []string{redeemOther}, response: redeemOther},
		{name: "ShouldNarrowToTheRequestedResourceTheClientIsPermitted", claim: []string{redeemResource, redeemOther}, requested: []string{redeemResource, redeemOther}, granted: []string{redeemResource}, response: redeemResource},
		{name: "ShouldRejectARequestedResourceOutsideTheGrant", claim: redeemResource, requested: []string{redeemEvil}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARequestedResourceWhenTheGrantHasNone", requested: []string{redeemResource}, err: oauth2.ErrInvalidTarget},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, false)

			client := fixture.store.Clients[redeemClient].(*oauth2.DefaultClient)
			if tc.permitted != nil {
				client.Resource = tc.permitted
			}

			claims := fixture.claims()
			if tc.claim == nil {
				delete(claims, consts.ClaimResource)
			} else {
				claims[consts.ClaimResource] = tc.claim
			}

			request := newRedeemRequest(client, fixture.sign(t, claims, "", "", ""), nil)
			request.SetRequestedResource(tc.requested)

			err := fixture.handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			response := oauth2.NewAccessResponse()
			require.NoError(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, response))

			assert.ElementsMatch(t, tc.granted, request.GetGrantedResource())
			assert.Equal(t, tc.response, response.GetExtra(consts.FormParameterResource))
		})
	}
}

func TestRedeemHandlerLifespan(t *testing.T) {
	testCases := []struct {
		name     string
		lifespan time.Duration
		expiry   time.Duration
		expected time.Duration
	}{
		// RFC 7521 Section 4.1: the access token does not outlive the assertion.
		{name: "ShouldCapTheLifespanAtTheGrantExpiry", lifespan: time.Hour, expiry: 2 * time.Minute, expected: 2 * time.Minute},
		{name: "ShouldKeepAShorterLifespan", lifespan: time.Minute, expiry: 5 * time.Minute, expected: time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, false)
			fixture.config.AccessTokenLifespan = tc.lifespan

			claims := fixture.claims()
			claims[consts.ClaimExpirationTime] = time.Now().Add(tc.expiry).Unix()

			request := newRedeemRequest(fixture.store.Clients[redeemClient], fixture.sign(t, claims, "", "", ""), nil)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(fixture.handler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()
			require.NoError(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, response))

			assert.WithinDuration(t, time.Now().Add(tc.expected), request.GetSession().GetExpiresAt(oauth2.AccessToken), 2*time.Second)
			assert.InDelta(t, tc.expected.Seconds(), response.GetExtra(consts.AccessResponseExpiresIn), 2)
		})
	}
}

func TestRedeemHandlerRefetchesRotatedKeys(t *testing.T) {
	fixture := newRedeemFixture(t, false)

	fetcher := &countingFetcher{sets: []*jose.JSONWebKeySet{{}, {Keys: []jose.JSONWebKey{fixture.public}}}}
	fixture.config.JWKSFetcherStrategy = fetcher

	trusted := fixture.store.IDJAGTrustedIssuers[redeemIssuer]
	trusted.JSONWebKeys = nil
	trusted.JSONWebKeysURI = redeemJWKSURI
	fixture.store.IDJAGTrustedIssuers[redeemIssuer] = trusted

	request := newRedeemRequest(fixture.store.Clients[redeemClient], fixture.sign(t, fixture.claims(), "", "", ""), nil)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(fixture.handler.HandleTokenEndpointRequest(t.Context(), request)))
	assert.Equal(t, []bool{false, true}, fetcher.forced)
}

func TestRedeemHandlerKeyResolution(t *testing.T) {
	testCases := []struct {
		name   string
		sets   func(f *redeemFixture) []*jose.JSONWebKeySet
		fetch  error
		uri    string
		forge  bool
		err    error
		forced []bool
	}{
		{name: "ShouldNotRefetchWhenAMatchingKeyRejectsTheSignature", sets: func(f *redeemFixture) []*jose.JSONWebKeySet {
			return []*jose.JSONWebKeySet{{Keys: []jose.JSONWebKey{f.public}}, {Keys: []jose.JSONWebKey{f.public}}}
		}, uri: redeemJWKSURI, forge: true, err: oauth2.ErrInvalidGrant, forced: []bool{false}},
		{name: "ShouldRefetchOnceWhenNoKeyMatches", sets: func(_ *redeemFixture) []*jose.JSONWebKeySet {
			return []*jose.JSONWebKeySet{{}, {}}
		}, uri: redeemJWKSURI, err: oauth2.ErrInvalidGrant, forced: []bool{false, true}},
		{name: "ShouldReturnServerErrorWhenTheFetchFails", fetch: errors.New("connection refused"), uri: redeemJWKSURI, err: oauth2.ErrServerError, forced: []bool{false}},
		{name: "ShouldReturnServerErrorWhenTheIssuerHasNoKeys", err: oauth2.ErrServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, false)

			fetcher := &countingFetcher{err: tc.fetch}
			if tc.sets != nil {
				fetcher.sets = tc.sets(fixture)
			}

			fixture.config.JWKSFetcherStrategy = fetcher

			trusted := fixture.store.IDJAGTrustedIssuers[redeemIssuer]
			trusted.JSONWebKeys = nil
			trusted.JSONWebKeysURI = tc.uri
			fixture.store.IDJAGTrustedIssuers[redeemIssuer] = trusted

			signer := fixture

			if tc.forge {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				signer = &redeemFixture{private: other}
			}

			request := newRedeemRequest(fixture.store.Clients[redeemClient], signer.sign(t, fixture.claims(), "", "", ""), nil)

			require.ErrorIs(t, fixture.handler.HandleTokenEndpointRequest(t.Context(), request), tc.err)
			assert.Equal(t, tc.forced, fetcher.forced)
		})
	}
}

func TestRedeemHandlerLimitsForcedKeyRefetches(t *testing.T) {
	fixture := newRedeemFixture(t, false)

	var fetches atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)

		require.NoError(t, json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{fixture.public}}))
	}))
	t.Cleanup(ts.Close)

	fetcher := oauth2.NewDefaultJWKSFetcherStrategy().(*oauth2.DefaultJWKSFetcherStrategy)
	fixture.config.JWKSFetcherStrategy = fetcher

	trusted := fixture.store.IDJAGTrustedIssuers[redeemIssuer]
	trusted.JSONWebKeys = nil
	trusted.JSONWebKeysURI = ts.URL
	fixture.store.IDJAGTrustedIssuers[redeemIssuer] = trusted

	client := fixture.store.Clients[redeemClient]

	for i := range 10 {
		request := newRedeemRequest(client, fixture.sign(t, fixture.claims(), "", "", fmt.Sprintf("unknown-%d", i)), nil)

		require.ErrorIs(t, fixture.handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrInvalidGrant)
		fetcher.WaitForCache()
	}

	request := newRedeemRequest(client, fixture.sign(t, fixture.claims(), "", "", ""), nil)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(fixture.handler.HandleTokenEndpointRequest(t.Context(), request)))
	assert.Equal(t, int64(2), fetches.Load())
}

func TestRedeemHandlerBindAccessRequest(t *testing.T) {
	cnf := func(c map[string]any) {
		c["cnf"] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT}
	}

	testCases := []struct {
		name      string
		grantType string
		typ       string
		mutate    func(map[string]any)
		proof     *oauth2.DPoPProof
		err       error
	}{
		{name: "ShouldIgnoreOtherGrantTypes", grantType: consts.GrantTypeClientCredentials, mutate: cnf},
		{name: "ShouldIgnoreOtherAssertionTypes", typ: "JWT", mutate: cnf},
		// Section 9.8.1.2.3 and Section 9.8.1.2.4: a grant without 'cnf' is left to RFC 9449.
		{name: "ShouldAcceptUnboundGrantWithoutProof"},
		{name: "ShouldAcceptUnboundGrantWithProof", proof: &oauth2.DPoPProof{Thumbprint: redeemJKT}},
		// Section 9.8.1.2.2.
		{name: "ShouldRejectMissingProof", mutate: cnf, err: oauth2.ErrInvalidGrant},
		// Section 9.8.1.2.1 step 4.
		{name: "ShouldRejectMismatchedProof", mutate: cnf, proof: &oauth2.DPoPProof{Thumbprint: redeemOtherJKT}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldAcceptMatchingProof", mutate: cnf, proof: &oauth2.DPoPProof{Thumbprint: redeemJKT}},
		{name: "ShouldRejectMissingProofWithJWTDPoP", grantType: consts.GrantTypeOAuthJWTDPoP, mutate: cnf, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMismatchedProofWithJWTDPoP", grantType: consts.GrantTypeOAuthJWTDPoP, mutate: cnf, proof: &oauth2.DPoPProof{Thumbprint: redeemOtherJKT}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectUnboundGrantBoundByJWTDPoP", grantType: consts.GrantTypeOAuthJWTDPoP, proof: &oauth2.DPoPProof{Thumbprint: redeemJKT}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldAcceptMatchingProofWithJWTDPoP", grantType: consts.GrantTypeOAuthJWTDPoP, mutate: cnf, proof: &oauth2.DPoPProof{Thumbprint: redeemJKT}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, true)

			claims := fixture.claims()
			if tc.mutate != nil {
				tc.mutate(claims)
			}

			request := newRedeemRequest(fixture.store.Clients[redeemClient], fixture.sign(t, claims, tc.typ, "", ""), nil)

			setGrantType(request, tc.grantType)

			ctx := context.WithValue(t.Context(), oauth2.DPoPProofContextKey, &oauth2.DPoPProofHolder{Proof: tc.proof})

			err := fixture.handler.BindAccessRequest(ctx, request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestRedeemHandlerProofRequired(t *testing.T) {
	testCases := []struct {
		name    string
		dpop    bool
		enforce bool
		client  bool
		bound   bool
		header  bool
		empty   bool
		noHTTP  bool
		grant   string
		err     error
	}{
		// Section 9.8.1.2.2.
		{name: "ShouldRejectBoundGrantWithoutProof", dpop: true, bound: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectBoundGrantWithoutProofWhenEnforced", dpop: true, enforce: true, bound: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldLeaveTheProofToTheBindingPhase", dpop: true, enforce: true, bound: true, header: true},
		{name: "ShouldRejectBoundGrantWithAnEmptyProof", dpop: true, bound: true, empty: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectJWTDPoPWithoutProof", dpop: true, bound: true, grant: consts.GrantTypeOAuthJWTDPoP, err: oauth2.ErrInvalidGrant},
		{name: "ShouldLeaveTheJWTDPoPProofToTheBindingPhase", dpop: true, bound: true, header: true, grant: consts.GrantTypeOAuthJWTDPoP},
		{name: "ShouldLeaveTheBindingPhaseToEnforceWithoutTheHTTPRequest", dpop: true, bound: true, noHTTP: true},
		// Section 9.8.1.2.4 item 2.
		{name: "ShouldRejectUnboundGrantWithoutProofWhenEnforced", dpop: true, enforce: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectUnboundGrantWithoutProofWhenTheClientRequiresDPoP", dpop: true, client: true, err: oauth2.ErrInvalidGrant},
		// Section 9.8.1.2.4 item 1.
		{name: "ShouldAcceptUnboundGrantWithoutProofByDefault", dpop: true},
		{name: "ShouldAcceptUnboundGrantWhenDPoPIsDisabled", client: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, tc.dpop)
			fixture.config.DPoPEnforce = tc.enforce

			claims := fixture.claims()
			if tc.bound {
				claims[consts.ClaimConfirmation] = map[string]any{consts.ClaimConfirmationJWKThumbprint: redeemJKT}
			}

			client := fixture.store.Clients[redeemClient]

			switch {
			case tc.client:
				client = &dpopClient{DefaultClient: fixture.store.Clients[redeemClient].(*oauth2.DefaultClient)}
			case tc.grant != "":
				client = fixture.store.Clients[redeemDPoP]
				claims[consts.ClaimClientIdentifier] = redeemDPoP
			}

			request := newRedeemRequest(client, fixture.sign(t, claims, "", "", ""), nil)
			setGrantType(request, tc.grant)

			ctx := t.Context()

			if !tc.noHTTP {
				r := httptest.NewRequest(http.MethodPost, redeemEndpoint, nil)
				switch {
				case tc.header:
					r.Header.Set(consts.HeaderDPoP, "proof")
				case tc.empty:
					r.Header.Set(consts.HeaderDPoP, "")
				}

				ctx = context.WithValue(ctx, oauth2.RequestContextKey, r)
			}

			err := fixture.handler.HandleTokenEndpointRequest(ctx, request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestRedeemHandlerPopulateBoundTokenEndpointResponse(t *testing.T) {
	fixture := newRedeemFixture(t, true)

	response := oauth2.NewAccessResponse()
	response.SetTokenType(oauth2.BearerAccessToken)

	require.NoError(t, fixture.handler.PopulateBoundTokenEndpointResponse(t.Context(), newRedeemRequest(fixture.store.Clients[redeemClient], "", nil), response))
	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
}

func TestRedeemHandlerAuthorizationDetailsTypeHandlerFailure(t *testing.T) {
	fixture := newRedeemFixture(t, false)

	fixture.config.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{failingTypeHandler{}}

	claims := fixture.claims()
	claims[consts.ClaimAuthorizationDetails] = []any{map[string]any{redeemMemberType: internal.AuthorizationDetailsTypePaymentInitiation, redeemMemberActions: []any{redeemActionInitiate}}}

	request := newRedeemRequest(fixture.store.Clients[redeemClient], fixture.sign(t, claims, "", "", ""), nil)

	require.ErrorIs(t, fixture.handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrServerError)
	assert.Empty(t, request.GetGrantedAuthorizationDetails())
}

func TestRedeemHandlerAuthorizationDetails(t *testing.T) {
	payment := map[string]any{redeemMemberType: internal.AuthorizationDetailsTypePaymentInitiation, redeemMemberActions: []any{redeemActionInitiate}}
	invalid := map[string]any{redeemMemberType: internal.AuthorizationDetailsTypePaymentInitiation, redeemMemberActions: []any{"unknown"}}
	unsupported := map[string]any{redeemMemberType: "unsupported", redeemMemberActions: []any{redeemActionRead}}

	granted := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{redeemActionInitiate}}}

	testCases := []struct {
		name     string
		enabled  bool
		claim    any
		null     bool
		maximum  int
		client   oauth2.Client
		expected oauth2.AuthorizationDetails
		err      error
	}{
		{name: "ShouldGrantValidDetails", enabled: true, claim: []any{payment}, expected: granted},
		// Section 4.4.1: the Resource AS MAY filter authorization details based on policy.
		{name: "ShouldDropInvalidDetails", enabled: true, claim: []any{payment, invalid}, expected: granted},
		{name: "ShouldDropUnsupportedTypes", enabled: true, claim: []any{payment, unsupported}, expected: granted},
		{name: "ShouldDropTypesTheClientMayNotRequest", enabled: true, claim: []any{payment}, client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{ID: redeemClient, GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer}, Scopes: oauth2.Arguments{redeemRead, redeemHistory, redeemOffline}, Resource: oauth2.Arguments{redeemResource}}, AuthorizationDetailsTypes: []string{"other"}}},
		{name: "ShouldGrantNothingWhenEveryDetailIsDropped", enabled: true, claim: []any{invalid}},
		{name: "ShouldGrantNothingWithoutClaim", enabled: true},
		{name: "ShouldRejectNullClaim", enabled: true, null: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMalformedClaim", enabled: true, claim: redeemMalformed, err: oauth2.ErrInvalidGrant},
		{name: "ShouldGrantDetailsAtTheObjectLimit", enabled: true, claim: []any{payment}, maximum: 1, expected: granted},
		{name: "ShouldRejectDetailsOverTheObjectLimit", enabled: true, claim: []any{payment, invalid}, maximum: 1, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectEmptyClaim", enabled: true, claim: []any{}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectClaimWhenDisabled", claim: []any{payment}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectMalformedClaimWhenDisabled", claim: redeemMalformed, err: oauth2.ErrInvalidGrant},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRedeemFixture(t, false)

			if tc.enabled {
				fixture.config.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}
			}

			fixture.config.AuthorizationDetailsMaxObjects = tc.maximum

			claims := fixture.claims()
			if tc.claim != nil {
				claims[consts.ClaimAuthorizationDetails] = tc.claim
			}

			if tc.null {
				claims[consts.ClaimAuthorizationDetails] = nil
			}

			client := tc.client
			if client == nil {
				client = fixture.store.Clients[redeemClient]
			}

			request := newRedeemRequest(client, fixture.sign(t, claims, "", "", ""), nil)

			err := fixture.handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expected, request.GetGrantedAuthorizationDetails())

			response := oauth2.NewAccessResponse()

			require.NoError(t, fixture.handler.PopulateTokenEndpointResponse(t.Context(), request, response))

			if tc.expected == nil {
				assert.Nil(t, response.GetExtra(consts.AccessResponseAuthorizationDetails))
			} else {
				assert.Equal(t, tc.expected, response.GetExtra(consts.AccessResponseAuthorizationDetails))
			}
		})
	}
}

type redeemSession struct {
	*oauth2.DefaultSession

	claims map[string]any
}

func (s *redeemSession) SetIDJAGClaims(claims map[string]any) {
	s.claims = claims
}

type dpopClient struct {
	*oauth2.DefaultClient
}

func (c *dpopClient) GetEnableDPoPBoundAccessTokens() bool {
	return true
}

type failingTypeHandler struct {
	internal.PaymentInitiationTypeHandler
}

func (failingTypeHandler) Validate(_ context.Context, _ oauth2.Client, _ oauth2.AuthorizationDetail) error {
	return oauth2.ErrServerError.WithDebug("The backend is unavailable.")
}

type countingFetcher struct {
	sets   []*jose.JSONWebKeySet
	err    error
	forced []bool
}

func (f *countingFetcher) Resolve(_ context.Context, _ string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	f.forced = append(f.forced, ignoreCache)

	if f.err != nil {
		return nil, f.err
	}

	return f.sets[min(len(f.forced)-1, len(f.sets)-1)], nil
}

type redeemFixture struct {
	handler     *idjag.RedeemHandler
	config      *oauth2.Config
	store       *storage.MemoryStore
	private     *rsa.PrivateKey
	public      jose.JSONWebKey
	claimsScope string
}

func newRedeemFixture(t *testing.T, dpop bool) *redeemFixture {
	t.Helper()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	public := jose.JSONWebKey{Key: &private.PublicKey, KeyID: redeemKeyID, Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}

	config := &oauth2.Config{
		AuthorizationServerIdentificationIssuer: redeemAudience,
		AccessTokenLifespan:                     time.Hour,
		GrantTypeJWTBearerMaxDuration:           time.Hour,
		ScopeStrategy:                           oauth2.ExactScopeStrategy,
		DPoPEnabled:                             dpop,
		GlobalSecret:                            []byte("some-secret-thats-random-some-secret-thats-random-"),
	}

	store := storage.NewMemoryStore()
	store.Clients[redeemClient] = &oauth2.DefaultClient{
		ID:         redeemClient,
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer},
		Scopes:     oauth2.Arguments{redeemRead, redeemHistory, redeemOffline},
		Resource:   oauth2.Arguments{redeemResource},
	}
	store.Clients[redeemDPoP] = &oauth2.DefaultClient{
		ID:         redeemDPoP,
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTDPoP},
		Scopes:     oauth2.Arguments{redeemRead, redeemHistory, redeemOffline},
		Resource:   oauth2.Arguments{redeemResource},
	}
	store.Clients[redeemNoGrant] = &oauth2.DefaultClient{ID: redeemNoGrant, GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials}}
	store.Clients[redeemPublic] = &oauth2.DefaultClient{
		ID:         redeemPublic,
		Public:     true,
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer},
		Scopes:     oauth2.Arguments{redeemRead, redeemHistory},
		Resource:   oauth2.Arguments{redeemResource},
	}
	store.IDJAGTrustedIssuers[redeemIssuer] = oauth2.IDJAGTrustedIssuer{
		Issuer:      redeemIssuer,
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}},
		SigningAlgs: []string{string(jose.RS256)},
	}
	store.IDJAGSubjects[storage.IDJAGSubjectKey{Issuer: redeemIssuer, Subject: redeemSubject}] = redeemSubject

	strategy := compose.NewOAuth2HMACStrategy(config)

	return &redeemFixture{
		handler: &idjag.RedeemHandler{
			Config:  config,
			Storage: store,
			HandleHelper: &hoauth2.HandleHelper{
				AccessTokenStrategy: strategy,
				AccessTokenStorage:  store,
				Config:              config,
			},
		},
		config:      config,
		store:       store,
		private:     private,
		public:      public,
		claimsScope: "chat.read chat.history",
	}
}

func (f *redeemFixture) claims() map[string]any {
	return map[string]any{
		"iss":       redeemIssuer,
		"sub":       redeemSubject,
		"aud":       redeemAudience,
		"client_id": redeemClient,
		"jti":       uuid.New().String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
		"scope":     f.claimsScope,
		"resource":  redeemResource,
	}
}

func (f *redeemFixture) sign(t *testing.T, claims map[string]any, typ string, alg jose.SignatureAlgorithm, kid string) string {
	t.Helper()

	if typ == "" {
		typ = consts.JSONWebTokenTypeIDJAG
	}

	if alg == "" {
		alg = jose.RS256
	}

	if kid == "" {
		kid = redeemKeyID
	}

	var key any = jose.JSONWebKey{Key: f.private, KeyID: kid}

	if alg == jose.HS256 {
		key = jose.JSONWebKey{Key: f.private.N.Bytes(), KeyID: kid}
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func newRedeemRequest(client oauth2.Client, assertion string, scope oauth2.Arguments) *oauth2.AccessRequest {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer},
		Request: oauth2.Request{
			ID:             uuid.New().String(),
			Client:         client,
			RequestedScope: scope,
			Form: url.Values{
				consts.FormParameterGrantType: {consts.GrantTypeOAuthJWTBearer},
				consts.FormParameterAssertion: {assertion},
			},
			Session: &redeemSession{DefaultSession: &oauth2.DefaultSession{}},
		},
	}
}

func setGrantType(request *oauth2.AccessRequest, grantType string) {
	if grantType == "" {
		return
	}

	request.GrantTypes = oauth2.Arguments{grantType}
	request.Form.Set(consts.FormParameterGrantType, grantType)
}
