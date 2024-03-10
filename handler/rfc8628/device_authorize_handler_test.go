package rfc8628_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
)

func Test_HandleDeviceEndpointRequest(t *testing.T) {
	strategy := NewRFC8628HMACSHAStrategy(&hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
		&oauth2.Config{
			AccessTokenLifespan:   time.Minute * 24,
			AuthorizeCodeLifespan: time.Minute * 24,
			RFC8628CodeLifespan:   time.Minute * 24,
		}, "authelia_%s_")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := storage.NewMemoryStore()
	handler := DeviceAuthorizeHandler{
		Storage:  store,
		Strategy: strategy,
		Config: &oauth2.Config{
			RFC8628CodeLifespan:         time.Minute * 10,
			RFC8628TokenPollingInterval: time.Second * 10,
			RFC8628UserVerificationURL:  "https://www.test.com",
			AccessTokenLifespan:         time.Hour,
			RefreshTokenLifespan:        time.Hour,
			ScopeStrategy:               oauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
			RefreshTokenScopes:          []string{consts.ScopeOffline},
		},
	}

	req := oauth2.NewDeviceAuthorizeRequest()
	req.SetSession(openid.NewDefaultSession())

	resp := &oauth2.DeviceAuthorizeResponse{Extra: map[string]any{}}

	err := handler.HandleRFC8628DeviceAuthorizeEndpointRequest(context.TODO(), req, resp)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.GetDeviceCode())
	assert.NotEmpty(t, resp.GetUserCode())
	assert.Equal(t, 8, len(resp.GetUserCode()))
	assert.Contains(t, resp.GetDeviceCode(), "authelia_dc_")
	assert.Contains(t, resp.GetDeviceCode(), ".")
	assert.Equal(t, "https://www.test.com", resp.GetVerificationURI())
	assert.Equal(t, fmt.Sprintf("https://www.test.com?user_code=%s", resp.GetUserCode()), resp.GetVerificationURIComplete())
	assert.Equal(t, 10, resp.GetInterval())
}
