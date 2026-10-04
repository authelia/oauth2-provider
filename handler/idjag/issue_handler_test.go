// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIssueHandlerHandle(t *testing.T) {
	testCases := []struct {
		name      string
		audience  oauth2.Arguments
		resource  oauth2.Arguments
		scope     oauth2.Arguments
		form      url.Values
		err       error
		scopes    []string
		resources []string
	}{
		{name: "ShouldGrantPermittedScopesOnly", audience: oauth2.Arguments{issueAudienceURN}, scope: oauth2.Arguments{redeemRead, redeemAdmin}, scopes: []string{redeemRead}},
		{name: "ShouldGrantPermittedResource", audience: oauth2.Arguments{redeemAudience}, resource: oauth2.Arguments{redeemResource}, resources: []string{redeemResource}},
		{name: "ShouldRejectMissingAudience", err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectMultipleAudiences", audience: oauth2.Arguments{redeemAudience, issueAudienceURN}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectUnknownAudience", audience: oauth2.Arguments{redeemOther}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectResourceOutsideRelationship", audience: oauth2.Arguments{redeemAudience}, resource: oauth2.Arguments{redeemEvil}, err: oauth2.ErrInvalidTarget},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newIssueFixture(t, false)

			request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), tc.form)
			request.RequestedAudience = tc.audience
			request.RequestedResource = tc.resource
			request.RequestedScope = tc.scope

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.ElementsMatch(t, tc.scopes, request.GetGrantedScopes())
			assert.ElementsMatch(t, tc.resources, request.GetGrantedResource())
			assert.Equal(t, oauth2.Arguments{redeemAudience}, request.GetGrantedAudience())
		})
	}
}

func TestIssueHandlerIgnoresOtherRequestedTypes(t *testing.T) {
	handler, _, _ := newIssueFixture(t, false)

	request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken}})
	response := oauth2.NewAccessResponse()

	require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))
	require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response))
	assert.Empty(t, response.GetAccessToken())
}

func TestIssueHandlerPopulate(t *testing.T) {
	testCases := []struct {
		name         string
		dpop         bool
		jkt          string
		subjectExp   time.Time
		resources    oauth2.Arguments
		expectCNF    bool
		expectExpCap bool
	}{
		{name: "ShouldIssueTheClaimSet", subjectExp: time.Now().Add(time.Hour), resources: oauth2.Arguments{redeemResource}},
		{name: "ShouldIssueResourceArray", subjectExp: time.Now().Add(time.Hour), resources: oauth2.Arguments{redeemResource, issueFiles}},
		// Section 9.8.1.1: 'cnf' only when a proof was validated on this request.
		{name: "ShouldBindWhenDPoPEnabled", dpop: true, jkt: redeemJKT, subjectExp: time.Now().Add(time.Hour), expectCNF: true},
		{name: "ShouldNotBindWhenDPoPDisabled", jkt: redeemJKT, subjectExp: time.Now().Add(time.Hour)},
		{name: "ShouldCapToSubjectTokenExpiry", subjectExp: time.Now().Add(time.Minute), expectExpCap: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, cfg, key := newIssueFixture(t, tc.dpop)

			authTime := time.Now().Add(-time.Minute).Unix()

			session := newIssueSession(tc.subjectExp)
			session.SetDPoPJWKThumbprint(tc.jkt)
			session.SubjectToken[consts.ClaimAuthenticationTime] = float64(authTime)
			session.SubjectToken[consts.ClaimAuthenticationContextClassReference] = issueACRGold
			session.SubjectToken[consts.ClaimAuthenticationMethodsReference] = []any{issueAMRMFA}

			request := newIssueRequest(t, session, nil)
			request.RequestedAudience = oauth2.Arguments{redeemAudience}
			request.RequestedScope = oauth2.Arguments{redeemRead}
			request.RequestedResource = tc.resources

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			assert.Equal(t, oauth2.RFC8693NAToken, response.GetTokenType())
			assert.Equal(t, consts.TokenTypeRFC8693IDJAG, response.GetExtra(consts.FormParameterIssuedTokenType))
			assert.Empty(t, response.GetExtra(consts.AccessResponseRefreshToken))

			header, claims := parseIssued(t, response.GetAccessToken(), key)

			assert.Equal(t, consts.JSONWebTokenTypeIDJAG, header)
			assert.Equal(t, cfg.AuthorizationServerIdentificationIssuer, claims[consts.ClaimIssuer])
			assert.Equal(t, issueMapped, claims[consts.ClaimSubject])
			assert.Equal(t, redeemAudience, claims[consts.ClaimAudience])
			assert.Equal(t, redeemClient, claims[consts.ClaimClientIdentifier])
			assert.Equal(t, redeemRead, claims[consts.ClaimScope])
			assert.Equal(t, issueACRGold, claims[consts.ClaimAuthenticationContextClassReference])
			assert.Equal(t, []any{issueAMRMFA}, claims[consts.ClaimAuthenticationMethodsReference])
			assert.Equal(t, float64(authTime), claims[consts.ClaimAuthenticationTime])
			assert.Equal(t, issueEmail, claims[consts.ClaimPreferredEmail])
			assert.NotEmpty(t, claims[consts.ClaimJWTID])
			assert.NotContains(t, claims, consts.ClaimActor)

			keys := []string{
				consts.ClaimIssuer, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimClientIdentifier, consts.ClaimJWTID,
				consts.ClaimIssuedAt, consts.ClaimExpirationTime, consts.ClaimScope, consts.ClaimPreferredEmail,
				consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference,
			}

			if len(tc.resources) != 0 {
				keys = append(keys, consts.ClaimResource)
			}

			if tc.expectCNF {
				keys = append(keys, consts.ClaimConfirmation)
			}

			assert.ElementsMatch(t, keys, slices.Collect(maps.Keys(claims)))

			switch len(tc.resources) {
			case 0:
				assert.NotContains(t, claims, consts.ClaimResource)
			case 1:
				assert.Equal(t, tc.resources[0], claims[consts.ClaimResource])
			default:
				assert.ElementsMatch(t, []any{tc.resources[0], tc.resources[1]}, claims[consts.ClaimResource])
			}

			if tc.expectCNF {
				assert.Equal(t, map[string]any{consts.ClaimConfirmationJWKThumbprint: tc.jkt}, claims[consts.ClaimConfirmation])
			} else {
				assert.NotContains(t, claims, consts.ClaimConfirmation)
			}

			exp := int64(claims[consts.ClaimExpirationTime].(float64))

			if tc.expectExpCap {
				assert.Equal(t, tc.subjectExp.Unix(), exp)
			} else {
				assert.InDelta(t, time.Now().Add(5*time.Minute).Unix(), exp, 2)
			}

			assert.InDelta(t, time.Until(time.Unix(exp, 0)).Seconds(), float64(response.GetExtra(consts.AccessResponseExpiresIn).(int64)), 2)
		})
	}
}

func TestIssueHandlerRejectsSubjectTokenExpiringTooSoon(t *testing.T) {
	testCases := []struct {
		name       string
		subjectExp time.Time
	}{
		{name: "ShouldRejectSubjectTokenExpiringThisSecond", subjectExp: time.Now()},
		{name: "ShouldRejectExpiredSubjectToken", subjectExp: time.Now().Add(-time.Minute)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newIssueFixture(t, false)

			request := newIssueRequest(t, newIssueSession(tc.subjectExp), nil)
			request.RequestedAudience = oauth2.Arguments{redeemAudience}

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()

			require.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response), oauth2.ErrInvalidRequest)
			assert.Empty(t, response.GetAccessToken())
		})
	}
}

func TestIssueHandlerRejectsMissingIssuerIdentifier(t *testing.T) {
	handler, cfg, _ := newIssueFixture(t, false)

	cfg.AuthorizationServerIdentificationIssuer = ""

	request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), nil)
	request.RequestedAudience = oauth2.Arguments{redeemAudience}

	require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

	response := oauth2.NewAccessResponse()

	require.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response), oauth2.ErrServerError)
	assert.Empty(t, response.GetAccessToken())
}

func TestIssueHandlerSubject(t *testing.T) {
	testCases := []struct {
		name    string
		storage func(store *storage.MemoryStore) idjag.IssueStorage
		err     error
	}{
		{name: "ShouldRejectASubjectWithoutAnIdentifierForTheAudience", storage: func(store *storage.MemoryStore) idjag.IssueStorage {
			clear(store.IDJAGAudienceSubjects)

			return store
		}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldReturnServerErrorForAnEmptyIdentifier", storage: func(store *storage.MemoryStore) idjag.IssueStorage {
			return &subjectStorage{MemoryStore: store}
		}, err: oauth2.ErrServerError},
		{name: "ShouldReturnServerErrorWhenTheStorageFails", storage: func(store *storage.MemoryStore) idjag.IssueStorage {
			return &subjectStorage{MemoryStore: store, err: errors.New("connection refused")}
		}, err: oauth2.ErrServerError},
		{name: "ShouldReturnTheErrorOfTheStorage", storage: func(store *storage.MemoryStore) idjag.IssueStorage {
			return &subjectStorage{MemoryStore: store, err: oauth2.ErrAccessDenied}
		}, err: oauth2.ErrAccessDenied},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newIssueFixture(t, false)

			handler.Storage = tc.storage(handler.Storage.(*storage.MemoryStore))

			request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), nil)
			request.RequestedAudience = oauth2.Arguments{redeemAudience}

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()

			require.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response), tc.err)
			assert.Empty(t, response.GetAccessToken())
		})
	}
}

func TestIssueHandlerSessionCannotOverrideRegisteredClaims(t *testing.T) {
	handler, _, key := newIssueFixture(t, false)

	session := newIssueSession(time.Now().Add(time.Hour))
	session.extra = map[string]any{consts.ClaimAudience: redeemEvil, consts.ClaimClientIdentifier: "evil", consts.ClaimConfirmation: map[string]any{"jkt": "x"}, consts.ClaimTenant: "acme"}

	request := newIssueRequest(t, session, nil)
	request.RequestedAudience = oauth2.Arguments{redeemAudience}

	require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

	response := oauth2.NewAccessResponse()
	require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response))

	_, claims := parseIssued(t, response.GetAccessToken(), key)

	assert.Equal(t, redeemAudience, claims[consts.ClaimAudience])
	assert.Equal(t, redeemClient, claims[consts.ClaimClientIdentifier])
	assert.NotContains(t, claims, consts.ClaimConfirmation)
	assert.Equal(t, "acme", claims[consts.ClaimTenant])
}

func TestIssueHandlerAuthenticationClaims(t *testing.T) {
	authTime, idTokenAuthTime := time.Now().Add(-time.Minute).Unix(), time.Now().Add(-time.Hour).Unix()

	testCases := []struct {
		name     string
		typ      string
		subject  map[string]any
		idToken  *jwt.IDTokenClaims
		extra    map[string]any
		expected map[string]any
	}{
		{
			name:     "ShouldCopyFromTheSubjectToken",
			subject:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
			expected: map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
		},
		{
			name:     "ShouldCopyFromARefreshTokenSubjectToken",
			typ:      consts.TokenTypeRFC8693RefreshToken,
			subject:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
			expected: map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
		},
		{
			name:     "ShouldNotCopyFromACustomJWTSubjectToken",
			typ:      consts.TokenTypeRFC8693JWT,
			subject:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
			expected: map[string]any{},
		},
		{
			name:     "ShouldUseTheIDTokenClaimsForACustomJWTSubjectToken",
			typ:      consts.TokenTypeRFC8693JWT,
			subject:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
			idToken:  &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(idTokenAuthTime, 0)), AuthenticationContextClassReference: issueACRSilver, AuthenticationMethodsReferences: []string{issueAMRPassword}},
			expected: map[string]any{consts.ClaimAuthenticationTime: float64(idTokenAuthTime), consts.ClaimAuthenticationContextClassReference: issueACRSilver, consts.ClaimAuthenticationMethodsReference: []any{issueAMRPassword}},
		},
		{
			name:     "ShouldPreferTheSubjectToken",
			subject:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
			idToken:  &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(idTokenAuthTime, 0)), AuthenticationContextClassReference: issueACRSilver, AuthenticationMethodsReferences: []string{issueAMRPassword}},
			expected: map[string]any{consts.ClaimAuthenticationTime: float64(authTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRMFA}},
		},
		{
			name:     "ShouldFallBackToTheIDTokenClaimsPerClaim",
			subject:  map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRGold},
			idToken:  &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(idTokenAuthTime, 0)), AuthenticationContextClassReference: issueACRSilver, AuthenticationMethodsReferences: []string{issueAMRPassword}},
			expected: map[string]any{consts.ClaimAuthenticationTime: float64(idTokenAuthTime), consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationMethodsReference: []any{issueAMRPassword}},
		},
		{
			name:     "ShouldPermitSessionClaimsWhenNeitherSourceHasThem",
			extra:    map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRBronze},
			expected: map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRBronze},
		},
		{
			name:     "ShouldNotPermitSessionClaimsToOverrideTheSubjectToken",
			subject:  map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRGold},
			extra:    map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRBronze},
			expected: map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRGold},
		},
		{
			name:     "ShouldOmitAbsentClaims",
			expected: map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, key := newIssueFixture(t, false)

			session := newIssueSession(time.Now().Add(time.Hour))
			session.extra = tc.extra

			maps.Copy(session.SubjectToken, tc.subject)

			if tc.idToken != nil {
				session.Claims = tc.idToken
			}

			var extra url.Values

			if tc.typ != "" {
				extra = url.Values{consts.FormParameterSubjectTokenType: {tc.typ}}
			}

			request := newIssueRequest(t, session, extra)
			request.RequestedAudience = oauth2.Arguments{redeemAudience}

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			_, claims := parseIssued(t, response.GetAccessToken(), key)

			actual := map[string]any{}

			for _, claim := range []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference} {
				if value, ok := claims[claim]; ok {
					actual[claim] = value
				}
			}

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIssueHandlerAuthenticationRequirements(t *testing.T) {
	recent, stale := float64(time.Now().Add(-time.Minute).Unix()), float64(time.Now().Add(-time.Hour).Unix())

	testCases := []struct {
		name     string
		acr      []string
		maxAge   time.Duration
		subject  map[string]any
		expected map[string]any
	}{
		{
			name:    "ShouldIssueWhenTheContextClassIsAccepted",
			acr:     []string{issueACRGold, issueACRSilver},
			subject: map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRSilver},
		},
		{
			name:    "ShouldIssueWhenTheAuthenticationIsRecent",
			maxAge:  5 * time.Minute,
			subject: map[string]any{consts.ClaimAuthenticationTime: recent},
		},
		{
			name:     "ShouldRejectAnotherContextClass",
			acr:      []string{issueACRGold, issueACRSilver},
			subject:  map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRBronze},
			expected: map[string]any{consts.FormParameterAuthenticationContextClassReferenceValues: issueACRGold + " " + issueACRSilver},
		},
		{
			name:     "ShouldRejectAnAbsentContextClass",
			acr:      []string{issueACRGold},
			expected: map[string]any{consts.FormParameterAuthenticationContextClassReferenceValues: issueACRGold},
		},
		{
			name:     "ShouldRejectAStaleAuthentication",
			maxAge:   5 * time.Minute,
			subject:  map[string]any{consts.ClaimAuthenticationTime: stale},
			expected: map[string]any{consts.FormParameterMaximumAge: float64(300)},
		},
		{
			name:     "ShouldRejectAnAbsentAuthenticationTime",
			maxAge:   5 * time.Minute,
			expected: map[string]any{consts.FormParameterMaximumAge: float64(300)},
		},
		{
			name:     "ShouldReportEveryRequirement",
			acr:      []string{issueACRGold},
			maxAge:   5 * time.Minute,
			subject:  map[string]any{consts.ClaimAuthenticationContextClassReference: issueACRGold, consts.ClaimAuthenticationTime: stale},
			expected: map[string]any{consts.FormParameterAuthenticationContextClassReferenceValues: issueACRGold, consts.FormParameterMaximumAge: float64(300)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newIssueFixture(t, false)

			store := handler.Storage.(*storage.MemoryStore)
			key := storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: redeemAudience}

			relationship := store.IDJAGRelationships[key]
			relationship.ACRValues, relationship.MaxAge = tc.acr, tc.maxAge
			store.IDJAGRelationships[key] = relationship

			session := newIssueSession(time.Now().Add(time.Hour))

			maps.Copy(session.SubjectToken, tc.subject)

			request := newIssueRequest(t, session, nil)
			request.RequestedAudience = oauth2.Arguments{redeemAudience}

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()

			err := handler.PopulateTokenEndpointResponse(t.Context(), request, response)

			if tc.expected == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.NotEmpty(t, response.GetAccessToken())

				return
			}

			// Section 9.2: the error response conveys the authentication requirements.
			require.ErrorIs(t, err, oauth2.ErrInsufficientUserAuthentication)
			assert.Empty(t, response.GetAccessToken())

			encoded, err := json.Marshal(oauth2.ErrorToRFC6749Error(err))
			require.NoError(t, err)

			actual := map[string]any{}

			require.NoError(t, json.Unmarshal(encoded, &actual))

			delete(actual, "error")
			delete(actual, "error_description")

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIssueHandlerAuthorizationDetails(t *testing.T) {
	payment := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{redeemActionInitiate}}
	other := oauth2.AuthorizationDetail{Type: issueOtherType, Actions: []string{redeemActionRead}}

	testCases := []struct {
		name      string
		audience  string
		requested oauth2.AuthorizationDetails
		expected  oauth2.AuthorizationDetails
		claim     bool
		response  bool
	}{
		{name: "ShouldGrantEveryTypeWhenUnrestricted", audience: redeemAudience, requested: oauth2.AuthorizationDetails{payment, other}, expected: oauth2.AuthorizationDetails{payment, other}, claim: true, response: true},
		// Section 4.3.3: the IdP MAY filter authorization details based on policy.
		{name: "ShouldDropTypesTheRelationshipDoesNotPermit", audience: issueAudienceTyped, requested: oauth2.AuthorizationDetails{payment, other}, expected: oauth2.AuthorizationDetails{payment}, claim: true, response: true},
		// Section 4.3.4: the response carries the granted details whenever they differ from those requested.
		{name: "ShouldReturnEmptyWhenNonePermitted", audience: issueAudienceNone, requested: oauth2.AuthorizationDetails{payment}, expected: oauth2.AuthorizationDetails{}, response: true},
		{name: "ShouldOmitWhenNoneRequested", audience: redeemAudience},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, key := newIssueFixture(t, false)

			request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), nil)
			request.RequestedAudience = oauth2.Arguments{tc.audience}
			request.SetRequestedAuthorizationDetails(tc.requested)

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			_, claims := parseIssued(t, response.GetAccessToken(), key)

			if tc.claim {
				raw, err := json.Marshal(claims[consts.ClaimAuthorizationDetails])
				require.NoError(t, err)

				details, err := oauth2.ParseAuthorizationDetails(string(raw))
				require.NoError(t, err)
				assert.Equal(t, tc.expected, details)
			} else {
				assert.NotContains(t, claims, consts.ClaimAuthorizationDetails)
			}

			if tc.response {
				assert.Equal(t, tc.expected, response.GetExtra(consts.AccessResponseAuthorizationDetails))
			} else {
				assert.Nil(t, response.GetExtra(consts.AccessResponseAuthorizationDetails))
			}
		})
	}
}

func TestIssueHandlerCanHandleAuthorizationDetails(t *testing.T) {
	handler, _, _ := newIssueFixture(t, false)

	testCases := []struct {
		name     string
		form     url.Values
		expected bool
	}{
		{name: "ShouldAcceptIDJAGRequest", expected: true},
		{name: "ShouldDeclineOtherRequestedTypes", form: url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, handler.CanHandleAuthorizationDetails(t.Context(), newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), tc.form)))
		})
	}
}

type issueSession struct {
	*rfc8693.DefaultSession

	extra map[string]any
}

func (s *issueSession) IDJAGClaims(_ context.Context, _ *oauth2.IDJAGRelationship) map[string]any {
	claims := map[string]any{consts.ClaimPreferredEmail: issueEmail}

	for k, v := range s.extra {
		claims[k] = v
	}

	return claims
}

func newIssueSession(subjectExp time.Time) *issueSession {
	session := rfc8693.NewDefaultSession()
	session.Subject = issueSubject
	session.Claims = &jwt.IDTokenClaims{Subject: issueSubject}
	session.SetSubjectToken(map[string]any{consts.ClaimSubject: issueSubject, consts.ClaimExpirationTime: subjectExp.Unix()})

	return &issueSession{DefaultSession: session}
}

func newIssueFixture(t *testing.T, dpop bool) (*idjag.IssueHandler, *oauth2.Config, *jose.JSONWebKey) {
	t.Helper()

	private := gen.MustRSAKey()
	key := &jose.JSONWebKey{Key: private, KeyID: "idp", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}

	issuer, err := jwt.NewDefaultIssuer(*key)
	require.NoError(t, err)

	cfg := &oauth2.Config{
		AccessTokenIssuer:                       "https://tokens.idp.example.com",
		AuthorizationServerIdentificationIssuer: redeemIssuer,
		ScopeStrategy:                           oauth2.ExactScopeStrategy,
		DPoPEnabled:                             dpop,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693IDToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
			consts.TokenTypeRFC8693IDJAG:   &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
		},
	}

	store := storage.NewExampleStore()
	relationship := oauth2.IDJAGRelationship{
		Issuer:    redeemAudience,
		ClientID:  redeemClient,
		Scopes:    []string{redeemRead, redeemHistory},
		Resources: []string{redeemResource, issueFiles},
	}

	store.IDJAGAudienceSubjects[storage.IDJAGAudienceSubjectKey{Issuer: redeemAudience, Subject: issueSubject}] = issueMapped
	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: redeemAudience}] = relationship
	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: issueAudienceURN}] = relationship

	typed := relationship
	typed.AuthorizationDetailsTypes = []string{internal.AuthorizationDetailsTypePaymentInitiation}

	none := relationship
	none.AuthorizationDetailsTypes = []string{}

	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: issueAudienceTyped}] = typed
	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: issueAudienceNone}] = none

	return &idjag.IssueHandler{
		Config:   cfg,
		Strategy: &jwt.DefaultStrategy{Config: cfg, Issuer: issuer},
		Storage:  store,
	}, cfg, key
}

func newIssueRequest(t *testing.T, session oauth2.Session, extra url.Values) *oauth2.AccessRequest {
	t.Helper()

	form := url.Values{
		consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectToken:       {"subject"},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693IDToken},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
	}

	for k, v := range extra {
		form[k] = v
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  storage.NewExampleStore().Clients[issueClient],
			Form:    form,
			Session: session,
		},
	}
}

func parseIssued(t *testing.T, token string, key *jose.JSONWebKey) (typ string, claims map[string]any) {
	t.Helper()

	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	payload, err := signed.Verify(key.Public())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, &claims))

	typ, _ = signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)

	return typ, claims
}

type subjectStorage struct {
	*storage.MemoryStore

	err error
}

func (s *subjectStorage) GetIDJAGSubject(_ context.Context, _ oauth2.AccessRequester, _ *oauth2.IDJAGRelationship) (string, error) {
	return "", s.err
}
