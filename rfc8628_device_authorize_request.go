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

func (d *DeviceAuthorizeRequest) SetStatus(status DeviceAuthorizeStatus) {
	d.Status = status
}

func (d *DeviceAuthorizeRequest) GetStatus() DeviceAuthorizeStatus {
	return d.Status
}

func (d *DeviceAuthorizeRequest) SetLastChecked(lastChecked time.Time) {
	d.LastChecked = lastChecked
}

func (d *DeviceAuthorizeRequest) GetLastChecked() time.Time {
	return d.LastChecked
}

func (d *DeviceAuthorizeRequest) Merge(requester Requester) {
	d.Request.Merge(requester)

	if authReq, ok := requester.(*DeviceAuthorizeRequest); ok {
		d.Status = authReq.Status
		d.DeviceCodeSignature = authReq.DeviceCodeSignature
		d.UserCodeSignature = authReq.UserCodeSignature
		d.LastChecked = authReq.LastChecked
	}
}
