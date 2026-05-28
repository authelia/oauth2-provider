// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestNewCIBAResponse(t *testing.T) {
	response := NewCIBAResponse()

	assert.NotNil(t, response)
	assert.NotNil(t, response.Header)
	assert.NotNil(t, response.Extra)
}

func TestCIBAResponse_AuthRequestID(t *testing.T) {
	response := NewCIBAResponse()

	response.SetAuthRequestID("abc")
	assert.Equal(t, "abc", response.GetAuthRequestID())
}

func TestCIBAResponse_ExpiresIn(t *testing.T) {
	response := NewCIBAResponse()

	response.SetExpiresIn(600)
	assert.Equal(t, int64(600), response.GetExpiresIn())
}

func TestCIBAResponse_Interval(t *testing.T) {
	response := NewCIBAResponse()

	response.SetInterval(5)
	assert.Equal(t, 5, response.GetInterval())
}

func TestCIBAResponse_Headers(t *testing.T) {
	response := NewCIBAResponse()

	response.AddHeader("X-Test", "value")
	assert.Equal(t, "value", response.GetHeader().Get("X-Test"))
}

func TestCIBAResponse_Extra(t *testing.T) {
	response := NewCIBAResponse()

	response.SetExtra("custom", 42)
	assert.Equal(t, 42, response.GetExtra("custom"))
	assert.Nil(t, response.GetExtra("missing"))
}

func TestCIBAResponse_ToMap(t *testing.T) {
	response := NewCIBAResponse()
	response.SetAuthRequestID("abc")
	response.SetExpiresIn(600)
	response.SetInterval(5)
	response.SetExtra("custom", "value")

	m := response.ToMap()

	assert.Equal(t, "abc", m[consts.CIBAResponseAuthRequestID])
	assert.Equal(t, int64(600), m[consts.CIBAResponseExpiresIn])
	assert.Equal(t, 5, m[consts.CIBAResponseInterval])
	assert.Equal(t, "value", m["custom"])
}

func TestCIBAResponse_ToMap_OmitsZeroInterval(t *testing.T) {
	response := NewCIBAResponse()
	response.SetAuthRequestID("abc")
	response.SetExpiresIn(600)

	m := response.ToMap()

	_, ok := m[consts.CIBAResponseInterval]
	assert.False(t, ok, "interval should be omitted when zero")
}
