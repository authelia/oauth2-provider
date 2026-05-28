// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"
)

type DeviceAuthorizeStatus int

const (
	DeviceAuthorizeStatusNew DeviceAuthorizeStatus = iota
	DeviceAuthorizeStatusApproved
	DeviceAuthorizeStatusDenied
)

var (
	_ DeviceAuthorizeRequester = (*DeviceAuthorizeRequest)(nil)
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

// SetStatus records the user authorization status (new, approved, or denied) for the device flow.
func (d *DeviceAuthorizeRequest) SetStatus(status DeviceAuthorizeStatus) {
	d.Status = status
}

// GetStatus returns the user authorization status (new, approved, or denied) for the device flow.
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
