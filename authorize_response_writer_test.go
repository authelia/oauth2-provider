// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*mock.MockAuthorizeEndpointHandler{mock.NewMockAuthorizeEndpointHandler(ctrl)}
	ar := mock.NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	ctx := context.Background()
	provider := &Fosite{Config: &Config{AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{handlers[0]}}}
	duo := &Fosite{Config: &Config{AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{handlers[0], handlers[0]}}}
	ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession))).AnyTimes()
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
			isErr: false,
		},
		{
			mock: func() {
				provider = duo
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
			isErr: false,
		},
		{
			mock: func() {
				provider = duo
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				provider = duo
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery).Times(2)
				ar.EXPECT().GetResponseTypes().Return([]string{"token", "code"})
			},
			isErr:     true,
			expectErr: ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", ResponseModeQuery, oauth2.Arguments{"token", "code"}),
		},
	} {
		c.mock()
		responder, err := provider.NewAuthorizeResponse(ctx, ar, new(DefaultSession))
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err != nil {
			assert.Equal(t, c.expectErr, err, "%d: %s", k, err)
			assert.Nil(t, responder, "%d", k)
		} else {
			assert.NotNil(t, responder, "%d", k)
		}
		t.Logf("Passed test case %d", k)
	}
}
