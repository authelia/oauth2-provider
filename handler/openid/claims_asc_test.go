// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid/asc"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateClaimsASC(t *testing.T) {
	const (
		requireEmail  = `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[{"loc":"/email","else":"abort"}]}}}`
		omitEmail     = `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[{"loc":"/email","else":"omit"}]}}}`
		requireAdult  = `{"id_token":{":adult":null},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"id_token":[{"loc":"/:adult","method":"simple","value":true,"else":"abort"}]}}}`
		requirePostal = `{"userinfo":{"address":null},"_asc":{"sao":{"userinfo":[{"loc":"/address/postal_code","else":"abort"}]}}}`
	)

	enabled := oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true, Evaluator: asc.NewEvaluator()}

	withExtra := func(extra map[string]any) *DefaultSession {
		return &DefaultSession{Subject: "peter", Claims: &jwt.IDTokenClaims{Subject: "peter", Extra: extra}}
	}

	testCases := []struct {
		name    string
		config  oauth2.ClaimsASC
		parse   *oauth2.ClaimsASC
		raw     string
		session oauth2.Session
		err     error
	}{
		{name: "ShouldPassWithoutClaims", config: enabled, session: withExtra(nil)},
		{name: "ShouldPassWhenRuleFulfilled", config: enabled, raw: requireEmail, session: withExtra(map[string]any{"email": "peter@example.com"})},
		{name: "ShouldAbortWhenRuleNotFulfilled", config: enabled, raw: requireEmail, session: withExtra(nil), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassWhenRuleOmits", config: enabled, raw: omitEmail, session: withExtra(nil)},
		{name: "ShouldPassWhenDisabled", config: oauth2.ClaimsASC{}, parse: &enabled, raw: requireEmail, session: withExtra(nil)},
		{name: "ShouldPassWithoutEvaluator", config: oauth2.ClaimsASC{SelectiveAbortOmit: true}, parse: &enabled, raw: requireEmail, session: withExtra(nil)},
		{name: "ShouldFailUnknownSessionType", config: enabled, raw: requireEmail, session: &oauth2.DefaultSession{}, err: oauth2.ErrServerError},
		{name: "ShouldAbortOnTransformedClaimWithoutSource", config: enabled, raw: requireAdult, session: withExtra(nil), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassOnTransformedClaimFromSource", config: enabled, raw: requireAdult, session: &ascTestSession{DefaultSession: withExtra(nil), sources: map[string]any{"birthdate": "2000-01-01"}}},
		{name: "ShouldAbortOnTransformedClaimFromSource", config: enabled, raw: requireAdult, session: &ascTestSession{DefaultSession: withExtra(nil), sources: map[string]any{"birthdate": "2015-01-01"}}, err: oauth2.ErrAccessDenied},
		{name: "ShouldSkipUserInfoRulesWithoutUserInfoClaims", config: enabled, raw: requirePostal, session: withExtra(nil)},
		{name: "ShouldAbortOnUserInfoRule", config: enabled, raw: requirePostal, session: &ascTestSession{DefaultSession: withExtra(nil), userinfo: map[string]any{"address": map[string]any{"country": "GB"}}}, err: oauth2.ErrAccessDenied},
		{name: "ShouldPassUserInfoRule", config: enabled, raw: requirePostal, session: &ascTestSession{DefaultSession: withExtra(nil), userinfo: map[string]any{"address": map[string]any{"postal_code": "EH1 1AA"}}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewOpenIDConnectRequestValidator(nil, &oauth2.Config{ClaimsASC: tc.config})

			request := &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request:       oauth2.Request{Form: url.Values{}, Client: &oauth2.DefaultClient{}, Session: tc.session},
			}

			if tc.raw != "" {
				parse := tc.config
				if tc.parse != nil {
					parse = *tc.parse
				}

				claims, err := oauth2.ParseRequestedClaims(t.Context(), &oauth2.Config{ClaimsASC: parse}, url.Values{consts.FormParameterClaims: {tc.raw}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				request.SetClaims(claims)
			}

			err := v.ValidateClaimsASC(t.Context(), request)

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)

				return
			}

			assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestValidateClaimsASCProtocolClaims(t *testing.T) {
	enabled := oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: asc.NewEvaluator()}

	exists := func(names ...string) string {
		rules := make([]string, len(names))

		for i, name := range names {
			rules[i] = `{"loc":"/` + name + `","else":"abort"}`
		}

		return `{"_asc":{"sao":{"id_token":[` + strings.Join(rules, ",") + `]}}}`
	}

	testCases := []struct {
		name  string
		types oauth2.Arguments
		form  url.Values
		state string
		raw   string
		err   error
	}{
		{name: "ShouldPassOnClaimsSetWhenTheTokenIsIssued", types: oauth2.Arguments{"code"}, raw: exists("iss", "sub", "aud", "exp", "iat")},
		{name: "ShouldPassOnAudienceElement", types: oauth2.Arguments{"code"}, raw: `{"_asc":{"sao":{"id_token":[{"loc":"/aud/0","method":"simple","value":"client","else":"abort"}]}}}`},
		{name: "ShouldPassOnIssuerValue", types: oauth2.Arguments{"code"}, raw: `{"_asc":{"sao":{"id_token":[{"loc":"/iss","method":"simple","value":"https://issuer.example.com","else":"abort"}]}}}`},
		{name: "ShouldPassOnRequestedNonce", types: oauth2.Arguments{"code"}, form: url.Values{"nonce": {"some-nonce-value"}}, raw: `{"_asc":{"sao":{"id_token":[{"loc":"/nonce","method":"simple","value":"some-nonce-value","else":"abort"}]}}}`},
		{name: "ShouldAbortOnNonceWhichWasNotRequested", types: oauth2.Arguments{"code"}, raw: exists("nonce"), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassOnAccessTokenHashForCodeFlow", types: oauth2.Arguments{"code"}, raw: exists("at_hash")},
		{name: "ShouldAbortOnCodeHashForCodeFlow", types: oauth2.Arguments{"code"}, raw: exists("c_hash"), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassOnCodeHashForHybridFlow", types: oauth2.Arguments{"code", "id_token"}, raw: exists("c_hash")},
		{name: "ShouldAbortOnAccessTokenHashForHybridFlowWithoutToken", types: oauth2.Arguments{"code", "id_token"}, raw: exists("at_hash"), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassOnHashesForHybridFlowWithToken", types: oauth2.Arguments{"code", "id_token", "token"}, raw: exists("c_hash", "at_hash")},
		{name: "ShouldPassOnStateHashForHybridFlowWithState", types: oauth2.Arguments{"code", "id_token"}, state: "some-state-value", raw: exists("s_hash")},
		{name: "ShouldAbortOnStateHashWithoutState", types: oauth2.Arguments{"code", "id_token"}, raw: exists("s_hash"), err: oauth2.ErrAccessDenied},
		{name: "ShouldPassOnAccessTokenHashForImplicitFlowWithToken", types: oauth2.Arguments{"id_token", "token"}, raw: exists("at_hash")},
		{name: "ShouldAbortOnAccessTokenHashForImplicitFlowWithoutToken", types: oauth2.Arguments{"id_token"}, raw: exists("at_hash"), err: oauth2.ErrAccessDenied},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{ClaimsASC: enabled, Issuer: "https://issuer.example.com"}

			v := NewOpenIDConnectRequestValidator(nil, config)

			form := tc.form
			if form == nil {
				form = url.Values{}
			}

			session := &DefaultSession{Subject: "peter", Claims: &jwt.IDTokenClaims{Subject: "peter"}}

			request := &oauth2.AuthorizeRequest{
				ResponseTypes: tc.types,
				State:         tc.state,
				Request:       oauth2.Request{Form: form, Client: &oauth2.DefaultClient{ID: "client"}, Session: session},
			}

			claims, err := oauth2.ParseRequestedClaims(t.Context(), config, url.Values{consts.FormParameterClaims: {tc.raw}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			request.SetClaims(claims)

			err = v.ValidateClaimsASC(t.Context(), request)

			assert.Empty(t, session.Claims.Audience)
			assert.Empty(t, session.Claims.Nonce)

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)

				return
			}

			assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestValidateClaimsASCAbortHint(t *testing.T) {
	v := NewOpenIDConnectRequestValidator(nil, &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: asc.NewEvaluator()}})

	request := &oauth2.AuthorizeRequest{Request: oauth2.Request{Form: url.Values{}, Client: &oauth2.DefaultClient{}, Session: NewDefaultSession()}}
	request.SetClaims(&oauth2.ClaimsRequest{ASC: &oauth2.ClaimsRequestASC{SAO: &oauth2.SelectiveAbortOmit{IDToken: []oauth2.SelectiveAbortOmitRule{
		{Loc: "/email", Method: oauth2.SelectiveAbortOmitMethodSimple, Value: "secret@example.com", Else: oauth2.SelectiveAbortOmitActionAbort},
	}}}})

	err := v.ValidateClaimsASC(t.Context(), request)
	require.Error(t, err)

	rfc := oauth2.ErrorToRFC6749Error(err)

	assert.Equal(t, "A Selective Abort/Omit rule of the 'claims' parameter was not fulfilled.", rfc.HintField)
	assert.NotContains(t, rfc.HintField, "email")
}

func TestGenerateIDTokenClaimsASC(t *testing.T) {
	const (
		adult     = `{"id_token":{":adult":null},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}}}`
		omitEmail = `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[{"loc":"/email_verified","method":"simple","value":true,"else":"omit","what":["/email","/email_verified"]}]}}}`
		omitProto = `{"_asc":{"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/sub","/exp","/iss","/aud","/iat","/s_hash","/email"]}]}}}`
		plain     = `{"id_token":{"email":null}}`

		omitOptional = `{"_asc":{"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/acr","/amr","/azp","/jti","/nbf","/auth_time"]}]}}}`
		abortEmail   = `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[{"loc":"/email","else":"abort"}]}}}`
	)

	enabled := oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true, Evaluator: asc.NewEvaluator()}

	newRequest := func(t *testing.T, raw string, session oauth2.Session, grant string) *oauth2.AccessRequest {
		t.Helper()

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{ID: "client"}
		request.GrantTypes = oauth2.Arguments{grant}

		claims, err := oauth2.ParseRequestedClaims(t.Context(), &oauth2.Config{ClaimsASC: enabled}, url.Values{consts.FormParameterClaims: {raw}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		request.SetClaims(claims)

		return request
	}

	newSession := func(extra map[string]any) *DefaultSession {
		session := NewDefaultSession()
		session.Claims.Subject = "peter"
		session.Claims.Extra = extra

		return session
	}

	decode := func(t *testing.T, token string) map[string]any {
		t.Helper()

		var payload map[string]any

		require.NoError(t, json.Unmarshal(payloadOf(t, token), &payload))

		return payload
	}

	t.Run("ShouldAddTransformedClaimFromSource", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		session := &ascTestSession{DefaultSession: newSession(nil), sources: map[string]any{"birthdate": "2000-01-01"}}

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, adult, session, consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		payload := decode(t, token)

		assert.Equal(t, true, payload[":adult"])
		assert.NotContains(t, payload, "birthdate")
		assert.Equal(t, "peter", payload["sub"])
		assert.NotContains(t, session.Claims.Extra, ":adult")
	})

	t.Run("ShouldOmitClaims", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		session := newSession(map[string]any{"email": "peter@example.com", "email_verified": false})

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, omitEmail, session, consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		payload := decode(t, token)

		assert.NotContains(t, payload, "email")
		assert.NotContains(t, payload, "email_verified")
		assert.Equal(t, "peter@example.com", session.Claims.Extra["email"])
	})

	t.Run("ShouldNotOmitProtocolClaims", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled
		config.Issuer = "https://issuer.example.com"

		session := newSession(map[string]any{"email": "peter@example.com"})
		session.Claims.StateHash = "state-hash"

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, omitProto, session, consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		payload := decode(t, token)

		assert.Equal(t, "peter", payload["sub"])
		assert.Equal(t, "https://issuer.example.com", payload["iss"])
		assert.Contains(t, payload, "aud")
		assert.Equal(t, "state-hash", payload["s_hash"])
		assert.IsType(t, float64(0), payload["exp"])
		assert.IsType(t, float64(0), payload["iat"])
		assert.NotContains(t, payload, "email")
	})

	t.Run("ShouldOmitClaimsWhichAreNotRequiredOfAnIDToken", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		session := newSession(map[string]any{"azp": "client", "nbf": 1})
		session.Claims.AuthenticationContextClassReference = "1"
		session.Claims.AuthenticationMethodsReferences = []string{"pwd"}
		session.Claims.JTI = "identifier"
		session.Claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Minute))

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, omitOptional, session, consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		payload := decode(t, token)

		for _, name := range []string{"acr", "amr", "azp", "jti", "nbf"} {
			assert.NotContains(t, payload, name)
		}

		assert.Contains(t, payload, "auth_time")
	})

	t.Run("ShouldEncodeNumbersAsNumbers", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		session := newSession(map[string]any{
			"email":      "peter@example.com",
			"updated_at": int64(9007199254740993),
			"score":      1.5,
			"nested":     map[string]any{"count": 3, "list": []any{1, 2.5}},
		})

		session.Claims.AuthTime = jwt.NewNumericDate(time.Unix(1700000000, 0))

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, abortEmail, session, consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		raw := payloadOf(t, token)

		assert.NotContains(t, string(raw), `"exp":"`)

		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()

		var payload map[string]any

		require.NoError(t, decoder.Decode(&payload))

		assert.Equal(t, json.Number("9007199254740993"), payload["updated_at"])
		assert.Equal(t, json.Number("1.5"), payload["score"])
		assert.Equal(t, map[string]any{"count": json.Number("3"), "list": []any{json.Number("1"), json.Number("2.5")}}, payload["nested"])
		assert.IsType(t, json.Number(""), payload["exp"])
		assert.IsType(t, json.Number(""), payload["iat"])
		assert.Equal(t, json.Number("1700000000"), payload["auth_time"])
	})

	t.Run("ShouldNotModifyNestedSessionClaims", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{"WithoutRules", plain},
			{"WithRules", abortEmail},
		} {
			t.Run(tc.name, func(t *testing.T) {
				strategy, config := newTestIDTokenStrategy(t)
				config.ClaimsASC = enabled

				session := newSession(map[string]any{
					"email":  "peter@example.com",
					"nested": map[string]any{"n": json.Number("7"), "l": []any{json.Number("8")}},
				})

				token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, tc.raw, session, consts.GrantTypeAuthorizationCode))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, map[string]any{"n": json.Number("7"), "l": []any{json.Number("8")}}, session.Claims.Extra["nested"])

				decoder := json.NewDecoder(bytes.NewReader(payloadOf(t, token)))
				decoder.UseNumber()

				var payload map[string]any

				require.NoError(t, decoder.Decode(&payload))

				assert.Equal(t, map[string]any{"n": json.Number("7"), "l": []any{json.Number("8")}}, payload["nested"])
			})
		}
	})

	t.Run("ShouldAbortWithInvalidGrantAtTokenEndpoint", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		_, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, abortEmail, newSession(nil), consts.GrantTypeAuthorizationCode))

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldAbortWithAccessDeniedAtAuthorizationEndpoint", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		claims, err := oauth2.ParseRequestedClaims(t.Context(), &oauth2.Config{ClaimsASC: enabled}, url.Values{consts.FormParameterClaims: {abortEmail}})
		require.NoError(t, err)

		request := oauth2.NewAuthorizeRequest()
		request.Client = &oauth2.DefaultClient{ID: "client"}
		request.Session = newSession(nil)
		request.SetClaims(claims)

		_, err = strategy.GenerateIDToken(t.Context(), time.Hour, request)

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
	})

	t.Run("ShouldEvaluateCurrentValuesOnRefresh", func(t *testing.T) {
		strategy, config := newTestIDTokenStrategy(t)
		config.ClaimsASC = enabled

		session := newSession(map[string]any{"email": "peter@example.com"})

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, abortEmail, session, consts.GrantTypeRefreshToken))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.Equal(t, "peter@example.com", decode(t, token)["email"])

		delete(session.Claims.Extra, "email")
		session.Claims.ExpirationTime = nil

		_, err = strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, abortEmail, session, consts.GrantTypeRefreshToken))

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldNotEvaluateWhenDisabled", func(t *testing.T) {
		strategy, _ := newTestIDTokenStrategy(t)

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, newRequest(t, abortEmail, newSession(nil), consts.GrantTypeAuthorizationCode))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.Equal(t, "peter", decode(t, token)["sub"])
	})
}

func TestEvaluateUserInfoClaims(t *testing.T) {
	const raw = `{"userinfo":{":adult":null,"address":null},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"userinfo":[{"loc":"/address/postal_code","else":"abort"}]}}}`

	enabled := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true, Evaluator: asc.NewEvaluator()}}

	claims, err := oauth2.ParseRequestedClaims(t.Context(), enabled, url.Values{consts.FormParameterClaims: {raw}})
	require.NoError(t, err)

	request := oauth2.NewAccessRequest(NewDefaultSession())
	request.SetClaims(claims)

	released := map[string]any{"sub": "peter", "address": map[string]any{"postal_code": "EH1 1AA"}}
	sources := map[string]any{"birthdate": "2000-01-01"}

	t.Run("ShouldEvaluate", func(t *testing.T) {
		result, err := EvaluateUserInfoClaims(t.Context(), enabled, request, released, sources)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"sub": "peter", "address": map[string]any{"postal_code": "EH1 1AA"}, ":adult": true}, result)
	})

	t.Run("ShouldReturnAbortError", func(t *testing.T) {
		_, err := EvaluateUserInfoClaims(t.Context(), enabled, request, map[string]any{"sub": "peter"}, sources)

		var aborted *asc.AbortError

		require.ErrorAs(t, err, &aborted)
		assert.Equal(t, asc.DeliveryUserInfo, aborted.Delivery)
	})

	t.Run("ShouldReturnClaimsWhenDisabled", func(t *testing.T) {
		result, err := EvaluateUserInfoClaims(t.Context(), &oauth2.Config{}, request, map[string]any{"sub": "peter"}, sources)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"sub": "peter"}, result)
	})

	t.Run("ShouldReturnClaimsWithoutClaimsRequest", func(t *testing.T) {
		result, err := EvaluateUserInfoClaims(t.Context(), enabled, oauth2.NewAccessRequest(NewDefaultSession()), map[string]any{"sub": "peter"}, sources)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"sub": "peter"}, result)
	})

	t.Run("ShouldReturnClaimsForRequesterWithoutClaims", func(t *testing.T) {
		result, err := EvaluateUserInfoClaims(t.Context(), enabled, &oauth2.Request{}, map[string]any{"sub": "peter"}, sources)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"sub": "peter"}, result)
	})
}

func TestClaimsASCComponentSwitches(t *testing.T) {
	const (
		predefined = `{"id_token":{"::age_18_or_over":null,"verified_claims":{"claims":{"::age_18_or_over":null}}},"userinfo":{"::age_18_or_over":null,"verified_claims":{"claims":{"::age_18_or_over":null}}}}`
		key        = "::age_18_or_over"
	)

	newEvaluator := func() *asc.Evaluator {
		evaluator := asc.NewEvaluator()
		evaluator.Predefined = map[string]*oauth2.TransformedClaim{
			"age_18_or_over": {Claim: "birthdate", Fn: []oauth2.TransformedClaimFunction{{Name: "years_ago"}, {Name: "gte", Args: []any{float64(18)}}}},
		}

		return evaluator
	}

	newSession := func(extra map[string]any) *ascTestSession {
		session := NewDefaultSession()
		session.Claims.Subject = "peter"
		session.Claims.Extra = extra

		return &ascTestSession{DefaultSession: session}
	}

	released := func() map[string]any {
		return map[string]any{
			"sub":             "peter",
			"email":           "peter@example.com",
			"birthdate":       "2000-01-01",
			"verified_claims": map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}},
		}
	}

	t.Run("ShouldNotTransformPredefinedClaimWithOnlySelectiveAbortOmit", func(t *testing.T) {
		config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: newEvaluator()}}

		claims, err := oauth2.ParseRequestedClaims(t.Context(), config, url.Values{consts.FormParameterClaims: {predefined}})
		require.NoError(t, err)

		before := claims.Clone()

		strategy, idConfig := newTestIDTokenStrategy(t)
		idConfig.ClaimsASC = config.ClaimsASC

		request := oauth2.NewAccessRequest(newSession(released()))
		request.Client = &oauth2.DefaultClient{ID: "client"}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.SetClaims(claims)

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, request)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		var payload map[string]any

		require.NoError(t, json.Unmarshal(payloadOf(t, token), &payload))

		assert.NotContains(t, payload, key)
		assert.NotContains(t, payload["verified_claims"].(map[string]any)["claims"], key)
		assert.Equal(t, before, request.GetClaims())

		result, err := EvaluateUserInfoClaims(t.Context(), config, request, released(), nil)
		require.NoError(t, err)

		assert.NotContains(t, result, key)
		assert.NotContains(t, result["verified_claims"].(map[string]any)["claims"], key)
		assert.Equal(t, before, request.GetClaims())
	})

	t.Run("ShouldTransformPredefinedClaimWithTransformedClaims", func(t *testing.T) {
		config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: newEvaluator()}}

		claims, err := oauth2.ParseRequestedClaims(t.Context(), config, url.Values{consts.FormParameterClaims: {predefined}})
		require.NoError(t, err)

		request := oauth2.NewAccessRequest(newSession(released()))
		request.SetClaims(claims)

		result, err := EvaluateUserInfoClaims(t.Context(), config, request, released(), nil)
		require.NoError(t, err)

		assert.Equal(t, true, result[key])
		assert.Equal(t, true, result["verified_claims"].(map[string]any)["claims"].(map[string]any)[key])
	})

	t.Run("ShouldNotTransformStoredDefinitionWithOnlySelectiveAbortOmit", func(t *testing.T) {
		config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: newEvaluator()}}

		claims := &oauth2.ClaimsRequest{
			IDToken: map[string]*oauth2.ClaimRequest{":adult": nil},
			ASC: &oauth2.ClaimsRequestASC{TransformedClaims: map[string]*oauth2.TransformedClaim{
				"adult": {Claim: "birthdate", Fn: []oauth2.TransformedClaimFunction{{Name: "years_ago"}, {Name: "gte", Args: []any{float64(18)}}}},
			}},
		}

		before := claims.Clone()

		strategy, idConfig := newTestIDTokenStrategy(t)
		idConfig.ClaimsASC = config.ClaimsASC

		request := oauth2.NewAccessRequest(newSession(released()))
		request.Client = &oauth2.DefaultClient{ID: "client"}
		request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
		request.SetClaims(claims)

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, request)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		var payload map[string]any

		require.NoError(t, json.Unmarshal(payloadOf(t, token), &payload))

		assert.NotContains(t, payload, ":adult")
		assert.Equal(t, before, request.GetClaims())
	})

	t.Run("ShouldNotApplyStoredRulesWithOnlyTransformedClaims", func(t *testing.T) {
		config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: newEvaluator()}}

		claims := &oauth2.ClaimsRequest{ASC: &oauth2.ClaimsRequestASC{SAO: &oauth2.SelectiveAbortOmit{
			IDToken: []oauth2.SelectiveAbortOmitRule{
				{Loc: "/missing", Else: oauth2.SelectiveAbortOmitActionAbort},
				{Loc: "/missing", Else: oauth2.SelectiveAbortOmitActionOmit, What: []string{"/email"}},
			},
			UserInfo: []oauth2.SelectiveAbortOmitRule{
				{Loc: "/missing", Else: oauth2.SelectiveAbortOmitActionAbort},
				{Loc: "/missing", Else: oauth2.SelectiveAbortOmitActionOmit, What: []string{"/email"}},
			},
		}}}

		before := claims.Clone()

		session := newSession(released())
		session.userinfo = released()

		request := oauth2.NewAuthorizeRequest()
		request.Client = &oauth2.DefaultClient{ID: "client"}
		request.Session = session
		request.SetClaims(claims)

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(NewOpenIDConnectRequestValidator(nil, config).ValidateClaimsASC(t.Context(), request)))
		assert.Equal(t, before, request.GetClaims())

		strategy, idConfig := newTestIDTokenStrategy(t)
		idConfig.ClaimsASC = config.ClaimsASC

		token, err := strategy.GenerateIDToken(t.Context(), time.Hour, request)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		var payload map[string]any

		require.NoError(t, json.Unmarshal(payloadOf(t, token), &payload))

		assert.Equal(t, "peter@example.com", payload["email"])
		assert.Equal(t, before, request.GetClaims())

		result, err := EvaluateUserInfoClaims(t.Context(), config, request, released(), nil)
		require.NoError(t, err)

		assert.Equal(t, released(), result)
		assert.Equal(t, before, request.GetClaims())
	})
}

func TestEvaluateUserInfoClaimsProtectsSubject(t *testing.T) {
	config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: asc.NewEvaluator()}}

	request := oauth2.NewAccessRequest(NewDefaultSession())
	request.SetClaims(&oauth2.ClaimsRequest{ASC: &oauth2.ClaimsRequestASC{SAO: &oauth2.SelectiveAbortOmit{
		UserInfo: []oauth2.SelectiveAbortOmitRule{{Loc: "/missing", Else: oauth2.SelectiveAbortOmitActionOmit, What: []string{"/sub", "/name"}}},
	}}})

	result, err := EvaluateUserInfoClaims(t.Context(), config, request, map[string]any{"sub": "peter", "name": "Peter"}, nil)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"sub": "peter"}, result)
}

type ascTestSession struct {
	*DefaultSession

	sources  map[string]any
	userinfo map[string]any
}

func (s *ascTestSession) GetASCSourceClaims(string) map[string]any {
	return s.sources
}

func (s *ascTestSession) GetASCUserInfoClaims() map[string]any {
	return s.userinfo
}
