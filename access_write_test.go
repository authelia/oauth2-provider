// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := &Fosite{Config: new(Config)}
	header := http.Header{}
	rw := mock.NewMockResponseWriter(ctrl)
	requester := mock.NewMockAccessRequester(ctrl)
	responder := mock.NewMockAccessResponder(ctrl)

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusOK)
	rw.EXPECT().Write(gomock.Any())
	responder.EXPECT().ToMap().Return(map[string]any{})

	provider.WriteAccessResponse(t.Context(), rw, requester, responder)
	assert.Equal(t, consts.ContentTypeApplicationJSON, header.Get(consts.HeaderContentType))
	assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
	assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
}
