package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
)

func TestFosite_WriteRFC8628UserAuthorizeError(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizeRequest{}
	resp := &RFC8628UserAuthorizeResponse{Extra: map[string]any{}}

	resp.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved))

	oauth2.WriteRFC8628UserAuthorizeResponse(context.Background(), rw, ar, resp)
	wroteDeviceResponse := RFC8628UserAuthorizeResponse{Extra: map[string]any{}}
	err := wroteDeviceResponse.FromJson(rw.Body)
	require.NoError(t, err)

	assert.Equal(t, resp.GetStatus(), wroteDeviceResponse.GetStatus())
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	assert.Equal(t, "application/json; charset=utf-8", rw.Header().Get("Content-Type"))
}

func TestFosite_WriteRFC8628UserAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizeRequest{}
	theErr := ErrInvalidGrant.WithDescription("invalid grant message.")

	oauth2.WriteRFC8628UserAuthorizeError(context.Background(), rw, ar, theErr)

	result := map[string]string{}
	err := json.NewDecoder(rw.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Contains(t, result, "error")
	assert.Equal(t, theErr.ErrorField, result["error"])
	assert.Contains(t, result, "error_description")
	assert.Equal(t, theErr.DescriptionField, result["error_description"])
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	assert.Equal(t, "application/json; charset=utf-8", rw.Header().Get("Content-Type"))
}
