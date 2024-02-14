package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestFosite_NewRFC8628UserAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*internal.MockRFC8628UserAuthorizeEndpointHandler{internal.NewMockRFC8628UserAuthorizeEndpointHandler(ctrl)}
	req := &http.Request{
		Form: url.Values{
			consts.FormParameterUserCode: {"A1B2C3D4"},
		},
	}
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
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		resp, err := oauth2.NewRFC8628UserAuthorizeRequest(ctx, req)
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err != nil {
			assert.Equal(t, c.expectErr, err, "%d: %s", k, err)
			assert.Nil(t, resp, "%d", k)
		} else {
			assert.NotNil(t, resp, "%d", k)
			assert.Equal(t, req.Form, resp.GetRequestForm())
		}
		t.Logf("Passed test case %d", k)
	}
}
