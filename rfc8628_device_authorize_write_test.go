package oauth2_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestWriteDeviceAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{
		RFC8628CodeLifespan:         time.Minute,
		RFC8628TokenPollingInterval: time.Minute,
		RFC8628UserVerificationURL:  "https://auth.example.com",
	}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizeRequest{}
	resp := &DeviceAuthorizeResponse{Extra: map[string]any{}}
	resp.SetUserCode("AAAA")
	resp.SetDeviceCode("BBBB")
	resp.SetInterval(int(
		oauth2.Config.GetRFC8628TokenPollingInterval(context.TODO()).Truncate(jwt.TimePrecision).Seconds(),
	))
	resp.SetExpiresIn(int64(
		time.Now().Truncate(jwt.TimePrecision).Add(oauth2.Config.GetRFC8628CodeLifespan(context.TODO())).Second(),
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

	assert.Equal(t, "AAAA", wroteDeviceResponse.UserCode)
	assert.Equal(t, "BBBB", wroteDeviceResponse.DeviceCode)

	assert.Equal(t, "AAAA", resp.GetUserCode())
	assert.Equal(t, "BBBB", resp.GetDeviceCode())

	assert.Equal(t, "https://auth.example.com?user_code=AAAA", resp.GetVerificationURIComplete())
	assert.Equal(t, "https://auth.example.com?user_code=AAAA", wroteDeviceResponse.VerificationURIComplete)

	assert.Equal(t, "https://auth.example.com", resp.GetVerificationURI())
	assert.Equal(t, "https://auth.example.com", wroteDeviceResponse.VerificationURI)
}
