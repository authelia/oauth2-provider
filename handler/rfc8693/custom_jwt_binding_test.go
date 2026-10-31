// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestCustomJWTInheritsItsConfirmation(t *testing.T) {
	confirmationKey, confirmationJKT := newConfirmationKey(t)

	bothRoles := func(subject, actor any) func(f *customJWTConsumeFixture, t *testing.T) url.Values {
		return func(f *customJWTConsumeFixture, t *testing.T) url.Values {
			return url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {customJWTWithConfirmation(t, f, subject)},
				consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
				consts.FormParameterActorToken:       {customJWTWithConfirmation(t, f, actor)},
			}
		}
	}

	subjectRole := func(cnf any) func(f *customJWTConsumeFixture, t *testing.T) url.Values {
		return func(f *customJWTConsumeFixture, t *testing.T) url.Values {
			return url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {customJWTWithConfirmation(t, f, cnf)},
			}
		}
	}

	actorRole := func(cnf any) func(f *customJWTConsumeFixture, t *testing.T) url.Values {
		return func(f *customJWTConsumeFixture, t *testing.T) url.Values {
			return url.Values{
				consts.FormParameterActorTokenType: {"urn:spec:jwt"},
				consts.FormParameterActorToken:     {customJWTWithConfirmation(t, f, cnf)},
			}
		}
	}

	jkt := map[string]any{jwt.ClaimConfirmationJWKThumbprint: bindingJKT}

	testCases := []struct {
		name     string
		form     func(f *customJWTConsumeFixture, t *testing.T) url.Values
		jkt      string
		x5t      string
		expected string
	}{
		{name: "ShouldRecordTheDPoPBindingOfASubjectToken", form: subjectRole(jkt), jkt: bindingJKT},
		{name: "ShouldRecordTheCertificateBindingOfASubjectToken", form: subjectRole(map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: bindingX5T}), x5t: bindingX5T},
		{name: "ShouldRecordTheKeyOfASubjectToken", form: subjectRole(map[string]any{consts.ClaimConfirmationJWK: confirmationKey}), jkt: confirmationJKT},
		{name: "ShouldRecordTheDPoPBindingOfAnActorToken", form: actorRole(jkt), jkt: bindingJKT},
		{name: "ShouldRecordNothingWithoutAConfirmation", form: subjectRole(nil)},
		{name: "ShouldAcceptMatchingBindingsOnBothTokens", form: bothRoles(jkt, jkt), jkt: bindingJKT},
		{
			name:     "ShouldRejectDifferentBindingsOnTheTwoTokens",
			form:     bothRoles(jkt, map[string]any{jwt.ClaimConfirmationJWKThumbprint: bindingJKTOther}),
			expected: "The subject token and the actor token are bound to different keys or certificates, and the issued token can only carry one binding.",
		},
		{
			name:     "ShouldRejectAnUnreadableKey",
			form:     subjectRole(map[string]any{consts.ClaimConfirmationJWK: map[string]any{"kty": "EC", "crv": "P-256", "x": "!!!"}}),
			expected: "The 'cnf' claim of the presented token carries a 'jwk' that could not be read as a JSON Web Key.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, false)
			request := f.request(tc.form(f, t))

			err := f.custom.HandleTokenEndpointRequest(t.Context(), request)

			if tc.expected != "" {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			session := request.GetSession().(*DefaultSession)

			assert.Equal(t, tc.jkt, session.GetDPoPJWKThumbprint())
			assert.Equal(t, tc.x5t, session.GetClientCertificateSHA256Thumbprint())
		})
	}
}

func customJWTWithConfirmation(t *testing.T, f *customJWTConsumeFixture, cnf any) string {
	t.Helper()

	claims := jwt.MapClaims{
		consts.ClaimIssuer:         "https://as.example.com",
		consts.ClaimSubject:        "peter",
		consts.ClaimJWTID:          uuid.New().String(),
		consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
		"subject":                  "peter",
	}

	if cnf != nil {
		claims[consts.ClaimConfirmation] = cnf
	}

	return createJWT(t.Context(), f.client, f.strategy, claims)
}
