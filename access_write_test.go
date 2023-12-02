// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package goauth2_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "github.com/authelia/goauth2"
	. "github.com/authelia/goauth2/internal"
)

func TestWriteAccessResponse(t *testing.T) {
	provider := &Fosite{Config: new(Config)}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	ar := NewMockAccessRequester(ctrl)
	resp := NewMockAccessResponder(ctrl)
	defer ctrl.Finish()

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusOK)
	rw.EXPECT().Write(gomock.Any())
	resp.EXPECT().ToMap().Return(map[string]interface{}{})

	provider.WriteAccessResponse(context.Background(), rw, ar, resp)
	assert.Equal(t, "application/json;charset=UTF-8", header.Get("Content-Type"))
	assert.Equal(t, "no-store", header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", header.Get("Pragma"))
}
