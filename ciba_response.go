// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2/internal/consts"
)

// BackChannelAuthenticationResponse is the successful authentication request acknowledgement.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
type BackChannelAuthenticationResponse struct {
	AuthRequestID string
	ExpiresIn     int64
	Interval      int64
}

// NewBackChannelAuthenticationResponse returns an empty BackChannelAuthenticationResponse.
func NewBackChannelAuthenticationResponse() *BackChannelAuthenticationResponse {
	return &BackChannelAuthenticationResponse{}
}

func (r *BackChannelAuthenticationResponse) GetAuthRequestID() string { return r.AuthRequestID }

func (r *BackChannelAuthenticationResponse) SetAuthRequestID(id string) { r.AuthRequestID = id }

func (r *BackChannelAuthenticationResponse) GetExpiresIn() int64 { return r.ExpiresIn }

func (r *BackChannelAuthenticationResponse) SetExpiresIn(seconds int64) { r.ExpiresIn = seconds }

func (r *BackChannelAuthenticationResponse) GetInterval() int64 { return r.Interval }

// SetInterval sets the minimum polling interval in seconds. A value of 0 omits the parameter.
func (r *BackChannelAuthenticationResponse) SetInterval(seconds int64) { r.Interval = seconds }

// ToMap returns the response members. The 'interval' member is present only when it is greater than 0.
func (r *BackChannelAuthenticationResponse) ToMap() map[string]any {
	m := map[string]any{
		consts.FormParameterAuthReqID:      r.AuthRequestID,
		consts.DeviceCodeResponseExpiresIn: r.ExpiresIn,
	}

	if r.Interval > 0 {
		m[consts.DeviceCodeResponseInterval] = r.Interval
	}

	return m
}

var (
	_ BackChannelAuthenticationResponder = (*BackChannelAuthenticationResponse)(nil)
)
