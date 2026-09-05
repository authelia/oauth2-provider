// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestGenerateIDToken(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(t *testing.T, strategy *mock.MockOpenIDConnectTokenStrategy, requester oauth2.AccessRequester)
		expected error
	}{
		{
			name: "ShouldReturnTheStrategyError",
			setup: func(t *testing.T, strategy *mock.MockOpenIDConnectTokenStrategy, requester oauth2.AccessRequester) {
				requester.GetRequestForm().Set(consts.FormParameterNonce, "11111111111111111111111111111111111")
				strategy.EXPECT().GenerateIDToken(t.Context(), time.Duration(0), requester).Return("", fooErr)
			},
			expected: fooErr,
		},
		{
			name: "ShouldReturnTheGeneratedToken",
			setup: func(t *testing.T, strategy *mock.MockOpenIDConnectTokenStrategy, requester oauth2.AccessRequester) {
				strategy.EXPECT().GenerateIDToken(t.Context(), time.Duration(0), requester).AnyTimes().Return("asdf", nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			chgen := mock.NewMockOpenIDConnectTokenStrategy(ctrl)

			requester := oauth2.NewAccessRequest(&DefaultSession{
				Claims:  &jwt.IDTokenClaims{Subject: testSubjectPeter},
				Headers: &jwt.Headers{},
			})

			tc.setup(t, chgen, requester)

			h := &IDTokenHandleHelper{IDTokenStrategy: chgen}

			token, err := h.generateIDToken(t.Context(), time.Duration(0), requester)

			if tc.expected != nil {
				assert.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)
		})
	}
}

func TestIssueExplicitToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	resp := mock.NewMockAccessResponder(ctrl)
	defer ctrl.Finish()

	ar := oauth2.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&DefaultSession{Claims: &jwt.IDTokenClaims{
		Subject: testSubjectPeter,
	}, Headers: &jwt.Headers{}})

	resp.EXPECT().SetExtra("id_token", gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}
	err := h.IssueExplicitIDToken(t.Context(), time.Duration(0), ar, resp)
	assert.NoError(t, err)
}

func TestIssueImplicitToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	resp := mock.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	ar := oauth2.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&DefaultSession{Claims: &jwt.IDTokenClaims{
		Subject: testSubjectPeter,
	}, Headers: &jwt.Headers{}})

	resp.EXPECT().AddParameter(consts.AccessResponseIDToken, gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}
	err := h.IssueImplicitIDToken(t.Context(), time.Duration(0), ar, resp)
	assert.NoError(t, err)
}

func TestGetAccessTokenHash(t *testing.T) {
	const token = "7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8"

	const (
		sha256Hash = "Zfn_XBitThuDJiETU3OALQ"
		sha384Hash = "VNX38yiOyeqBPheW5jDsWQKa6IjJzK66"
		sha512Hash = "0vQSMeFZrxwBD6DqjBfQKEQCQ00-IPnyWBhxLoO91-4"
	)

	testCases := []struct {
		name     string
		client   oauth2.Client
		expected string
	}{
		{"ShouldUseSHA256ForRS256", newIDTokenSignedClient("RS256"), sha256Hash},
		{"ShouldUseSHA384ForRS384", newIDTokenSignedClient("RS384"), sha384Hash},
		{"ShouldUseSHA512ForRS512", newIDTokenSignedClient("RS512"), sha512Hash},
		{"ShouldUseSHA256ForES256", newIDTokenSignedClient("ES256"), sha256Hash},
		{"ShouldUseSHA512ForES512", newIDTokenSignedClient("ES512"), sha512Hash},
		{"ShouldUseSHA384ForPS384", newIDTokenSignedClient("PS384"), sha384Hash},
		{"ShouldUseSHA512ForHS512", newIDTokenSignedClient("HS512"), sha512Hash},

		// RFC8037 Section 3.1 defines EdDSA for JOSE in terms of Ed25519, which uses SHA-512 internally. Deriving
		// the digest from the digits in the algorithm name, as this once did, cannot express that.
		{"ShouldUseSHA512ForEdDSA", newIDTokenSignedClient("EdDSA"), sha512Hash},

		// An unset 'id_token_signed_response_alg' defaults to RS256 per OpenID Connect Dynamic Client Registration
		// 1.0 Section 2, and a client that does not implement the ID Token metadata at all falls back the same way.
		{"ShouldDefaultToSHA256WhenAlgUnregistered", newIDTokenSignedClient(""), sha256Hash},
		{"ShouldDefaultToSHA256WhenClientCarriesNoIDTokenMetadata", &oauth2.DefaultClient{ID: "foo"}, sha256Hash},

		// An algorithm this does not recognise falls back to SHA-256 rather than panicking in GetAccessTokenHash.
		{"ShouldDefaultToSHA256ForUnknownAlg", newIDTokenSignedClient("XX999"), sha256Hash},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			req := mock.NewMockAccessRequester(ctrl)
			resp := mock.NewMockAccessResponder(ctrl)

			req.EXPECT().GetClient().Return(tc.client)
			resp.EXPECT().GetAccessToken().Return(token)

			h := &IDTokenHandleHelper{IDTokenStrategy: strategy}

			assert.Equal(t, tc.expected, h.GetAccessTokenHash(t.Context(), req, resp))
		})
	}
}

func newIDTokenSignedClient(alg string) oauth2.Client {
	return &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "foo"}, IDTokenSignedResponseAlg: alg}
}

var strategy = &DefaultStrategy{
	Strategy: &jwt.DefaultStrategy{
		Config: &oauth2.Config{
			MinParameterEntropy: oauth2.MinParameterEntropy,
		},
		Issuer: jwt.MustGenDefaultIssuer(),
	},
	Config: &oauth2.Config{
		MinParameterEntropy: oauth2.MinParameterEntropy,
	},
}

var fooErr = errors.New("foo")
