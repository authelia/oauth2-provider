package oauth2_test

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestFosite_NewRFC8628UserAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*mock.MockRFC8628UserAuthorizeEndpointHandler{mock.NewMockRFC8628UserAuthorizeEndpointHandler(ctrl)}
	dar := mock.NewMockDeviceAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	ctx := context.Background()
	oauth2 := &Fosite{Config: &Config{RFC8628UserAuthorizeEndpointHandlers: RFC8628UserAuthorizeEndpointHandlers{handlers[0]}}}
	duo := &Fosite{Config: &Config{RFC8628UserAuthorizeEndpointHandlers: RFC8628UserAuthorizeEndpointHandlers{handlers[0], handlers[0]}}}
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				oauth2 = duo
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		responder, err := oauth2.NewRFC8628UserAuthorizeResponse(ctx, dar, new(DefaultSession))
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
