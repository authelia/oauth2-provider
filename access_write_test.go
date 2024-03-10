// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAccessResponse(t *testing.T) {
	provider := &Fosite{Config: new(Config)}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := mock.NewMockResponseWriter(ctrl)
	ar := mock.NewMockAccessRequester(ctrl)
	resp := mock.NewMockAccessResponder(ctrl)
	defer ctrl.Finish()

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusOK)
	rw.EXPECT().Write(gomock.Any())
	resp.EXPECT().ToMap().Return(map[string]any{})

	provider.WriteAccessResponse(context.Background(), rw, ar, resp)
	assert.Equal(t, consts.ContentTypeApplicationJSON, header.Get(consts.HeaderContentType))
	assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
	assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
}
