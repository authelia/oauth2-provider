// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

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

func TestGenerateIDToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	chgen := mock.NewMockOpenIDConnectTokenStrategy(ctrl)
	defer ctrl.Finish()

	requester := oauth2.NewAccessRequest(nil)
	session := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: testSubjectPeter,
		},
		Headers: &jwt.Headers{},
	}
	h := &IDTokenHandleHelper{IDTokenStrategy: chgen}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because generator failed",
			setup: func() {
				requester.Form.Set("nonce", "11111111111111111111111111111111111")
				requester.SetSession(session)
				chgen.EXPECT().GenerateIDToken(t.Context(), time.Duration(0), requester).Return("", fooErr)
			},
			expectErr: fooErr,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().GenerateIDToken(t.Context(), time.Duration(0), requester).AnyTimes().Return("asdf", nil)
			},
		},
	} {
		c.setup()
		token, err := h.generateIDToken(t.Context(), time.Duration(0), requester)
		assert.True(t, err == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		if err == nil {
			assert.NotEmpty(t, token, "(%d) %s", k, c.description)
		}
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
	ctrl := gomock.NewController(t)
	req := mock.NewMockAccessRequester(ctrl)
	resp := mock.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	req.EXPECT().GetSession().Return(nil)
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}

	hash := h.GetAccessTokenHash(t.Context(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}

func TestGetAccessTokenHashWithDifferentKeyLength(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := mock.NewMockAccessRequester(ctrl)
	resp := mock.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]any{
			"alg": "RS384",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}

	hash := h.GetAccessTokenHash(t.Context(), req, resp)
	assert.Equal(t, "VNX38yiOyeqBPheW5jDsWQKa6IjJzK66", hash)
}

func TestGetAccessTokenHashWithBadAlg(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := mock.NewMockAccessRequester(ctrl)
	resp := mock.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]any{
			"alg": "R",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}

	hash := h.GetAccessTokenHash(t.Context(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}

func TestGetAccessTokenHashWithMissingKeyLength(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := mock.NewMockAccessRequester(ctrl)
	resp := mock.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]any{
			"alg": "RS",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strategy}

	hash := h.GetAccessTokenHash(t.Context(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}
