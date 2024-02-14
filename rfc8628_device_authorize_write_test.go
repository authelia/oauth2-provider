package oauth2_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
)

func TestWriteDeviceAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{
		DeviceAndUserCodeLifespan:      time.Minute,
		DeviceAuthTokenPollingInterval: time.Minute,
		RFC8628UserVerificationURL:     "http://ory.sh",
	}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizeRequest{}
	resp := &DeviceAuthorizeResponse{Extra: map[string]any{}}
	resp.SetUserCode("AAAA")
	resp.SetDeviceCode("BBBB")
	resp.SetInterval(int(
		oauth2.Config.GetDeviceAuthTokenPollingInterval(context.TODO()).Round(time.Second).Seconds(),
	))
	resp.SetExpiresIn(int64(
		time.Now().Round(time.Second).Add(oauth2.Config.GetDeviceAndUserCodeLifespan(context.TODO())).Second(),
	))
	resp.SetVerificationURI(oauth2.Config.GetRFC8628UserVerificationURL(context.TODO()))
	resp.SetVerificationURIComplete(
		oauth2.Config.GetRFC8628UserVerificationURL(context.TODO()) + "?user_code=" + resp.GetUserCode(),
	)

	oauth2.WriteRFC862DeviceAuthorizeResponse(context.Background(), rw, ar, resp)

	assert.Equal(t, 200, rw.Code)

	wroteDeviceResponse := DeviceAuthorizeResponse{Extra: map[string]any{}}
	err := wroteDeviceResponse.FromJson(rw.Body)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserCode(), wroteDeviceResponse.UserCode)
	assert.Equal(t, resp.GetDeviceCode(), wroteDeviceResponse.DeviceCode)
	assert.Equal(t, resp.GetVerificationURI(), wroteDeviceResponse.VerificationURI)
	assert.Equal(t, resp.GetVerificationURIComplete(), wroteDeviceResponse.VerificationURIComplete)
	assert.Equal(t, resp.GetInterval(), wroteDeviceResponse.Interval)
	assert.Equal(t, resp.GetExpiresIn(), wroteDeviceResponse.ExpiresIn)
}
