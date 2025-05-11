package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestFosite_WriteRFC8628UserAuthorizeError(t *testing.T) {
	rw := httptest.NewRecorder()

	oauth2 := &Fosite{Config: &Config{}}

	requester := &DeviceAuthorizeRequest{}
	responder := &RFC8628UserAuthorizeResponse{Extra: map[string]any{}}

	responder.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved))

	oauth2.WriteRFC8628UserAuthorizeResponse(context.Background(), rw, requester, responder)
	wroteDeviceResponse := RFC8628UserAuthorizeResponse{Extra: map[string]any{}}
	require.NoError(t, wroteDeviceResponse.FromJson(rw.Body))

	assert.Equal(t, responder.GetStatus(), wroteDeviceResponse.GetStatus())
	assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
	assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))
	assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
}

func TestFosite_WriteRFC8628UserAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()
	requester := &DeviceAuthorizeRequest{}

	err := ErrInvalidGrant.WithDescription("invalid grant message.")

	oauth2.WriteRFC8628UserAuthorizeError(context.Background(), rw, requester, err)

	result := map[string]string{}

	assert.NoError(t, json.NewDecoder(rw.Body).Decode(&result))
	require.Contains(t, result, "error")
	assert.Equal(t, err.ErrorField, result["error"])
	require.Contains(t, result, "error_description")
	assert.Equal(t, err.DescriptionField, result["error_description"])

	assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
	assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))
	assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
}
