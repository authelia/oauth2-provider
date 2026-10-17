// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"
)

// DeviceAuthorizeStatus is the end user's progress through the RFC 8628 device authorization grant. The values are
// persisted by storage implementations, so new values are appended rather than inserted.
type DeviceAuthorizeStatus int

const (
	// DeviceAuthorizeStatusNew marks a request the device authorization endpoint has issued but no end user has acted
	// on. It is undecided, so the device keeps receiving 'authorization_pending'.
	DeviceAuthorizeStatusNew DeviceAuthorizeStatus = iota

	// DeviceAuthorizeStatusApproved marks a request the end user has approved. The device receives tokens on its next
	// poll of the token endpoint.
	DeviceAuthorizeStatusApproved

	// DeviceAuthorizeStatusDenied marks a request the end user has denied. The device receives 'access_denied' on its
	// next poll of the token endpoint.
	DeviceAuthorizeStatusDenied

	// DeviceAuthorizeStatusClaimed marks a request whose user code an end user has entered but not yet approved or
	// denied. Like DeviceAuthorizeStatusNew it is undecided, so the device keeps receiving 'authorization_pending'.
	DeviceAuthorizeStatusClaimed
)

// DeviceAuthorizeRequest is an implementation of DeviceAuthorizeRequester
type DeviceAuthorizeRequest struct {
	Request
	DeviceCodeSignature string
	UserCodeSignature   string
	Status              DeviceAuthorizeStatus
	LastChecked         time.Time
}

// NewDeviceAuthorizeRequest returns an empty DeviceAuthorizeRequest with its embedded Request initialized.
func NewDeviceAuthorizeRequest() *DeviceAuthorizeRequest {
	return &DeviceAuthorizeRequest{
		Request: *NewRequest(),
	}
}

// SetDeviceCodeSignature set the device code signature
func (d *DeviceAuthorizeRequest) SetDeviceCodeSignature(signature string) {
	d.DeviceCodeSignature = signature
}

// GetDeviceCodeSignature returns the device code signature
func (d *DeviceAuthorizeRequest) GetDeviceCodeSignature() string {
	return d.DeviceCodeSignature
}

// SetUserCodeSignature set the user code signature
func (d *DeviceAuthorizeRequest) SetUserCodeSignature(signature string) {
	d.UserCodeSignature = signature
}

// GetUserCodeSignature returns the user code signature
func (d *DeviceAuthorizeRequest) GetUserCodeSignature() string {
	return d.UserCodeSignature
}

// SetStatus records the user authorization status (new, claimed, approved, or denied) for the device flow.
func (d *DeviceAuthorizeRequest) SetStatus(status DeviceAuthorizeStatus) {
	d.Status = status
}

// GetStatus returns the user authorization status (new, claimed, approved, or denied) for the device flow.
func (d *DeviceAuthorizeRequest) GetStatus() DeviceAuthorizeStatus {
	return d.Status
}

// SetLastChecked records the time of the most recent token endpoint polling attempt for the request. The value is
// normalized to UTC and is used by token endpoint handlers to enforce the polling interval.
func (d *DeviceAuthorizeRequest) SetLastChecked(lastChecked time.Time) {
	d.LastChecked = lastChecked.UTC()
}

// GetLastChecked returns the time of the most recent token endpoint polling attempt for the request.
func (d *DeviceAuthorizeRequest) GetLastChecked() time.Time {
	return d.LastChecked
}

// Merge copies the requester data into this request. When requester is a *DeviceAuthorizeRequest the status, code
// signatures, and last-checked timestamp are also merged.
func (d *DeviceAuthorizeRequest) Merge(requester Requester) {
	d.Request.Merge(requester)

	if authReq, ok := requester.(*DeviceAuthorizeRequest); ok {
		d.Status = authReq.Status
		d.DeviceCodeSignature = authReq.DeviceCodeSignature
		d.UserCodeSignature = authReq.UserCodeSignature
		d.LastChecked = authReq.LastChecked
	}
}

var (
	_ DeviceAuthorizeRequester = (*DeviceAuthorizeRequest)(nil)
)
