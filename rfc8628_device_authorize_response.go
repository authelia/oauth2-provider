package oauth2

import (
	"encoding/json"
	"io"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

type DeviceAuthorizeResponse struct {
	Header                  http.Header    `json:"-"`
	DeviceCode              string         `json:"device_code"`
	UserCode                string         `json:"user_code"`
	VerificationURI         string         `json:"verification_uri"`
	VerificationURIComplete string         `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64          `json:"expires_in"`
	Interval                int            `json:"interval,omitempty"`
	Extra                   map[string]any `json:"-"`
}

func NewDeviceAuthorizeResponse() *DeviceAuthorizeResponse {
	return &DeviceAuthorizeResponse{
		Extra: map[string]any{},
	}
}

func (d *DeviceAuthorizeResponse) GetDeviceCode() string {
	return d.DeviceCode
}

// SetDeviceCode returns the response's user code
func (d *DeviceAuthorizeResponse) SetDeviceCode(code string) {
	d.DeviceCode = code
}

func (d *DeviceAuthorizeResponse) GetUserCode() string {
	return d.UserCode
}

func (d *DeviceAuthorizeResponse) SetUserCode(code string) {
	d.UserCode = code
}

// GetVerificationURI returns the response's verification uri
func (d *DeviceAuthorizeResponse) GetVerificationURI() string {
	return d.VerificationURI
}

func (d *DeviceAuthorizeResponse) SetVerificationURI(uri string) {
	d.VerificationURI = uri
}

// GetVerificationURIComplete returns the response's complete verification uri if set
func (d *DeviceAuthorizeResponse) GetVerificationURIComplete() string {
	return d.VerificationURIComplete
}

func (d *DeviceAuthorizeResponse) SetVerificationURIComplete(uri string) {
	d.VerificationURIComplete = uri
}

// GetExpiresIn returns the response's device code and user code lifetime in seconds if set
func (d *DeviceAuthorizeResponse) GetExpiresIn() int64 {
	return d.ExpiresIn
}

func (d *DeviceAuthorizeResponse) SetExpiresIn(seconds int64) {
	d.ExpiresIn = seconds
}

// GetInterval returns the response's polling interval if set
func (d *DeviceAuthorizeResponse) GetInterval() int {
	return d.Interval
}

func (d *DeviceAuthorizeResponse) SetInterval(seconds int) {
	d.Interval = seconds
}

func (d *DeviceAuthorizeResponse) GetHeader() http.Header {
	return d.Header
}

func (d *DeviceAuthorizeResponse) AddHeader(key, value string) {
	d.Header.Add(key, value)
}

func (d *DeviceAuthorizeResponse) FromJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d)
}

// ToMap converts the response to a map.
func (d *DeviceAuthorizeResponse) ToMap() map[string]any {
	d.Extra[consts.DeviceCodeResponseDeviceCode] = d.DeviceCode
	d.Extra[consts.DeviceCodeResponseUserCode] = d.UserCode
	d.Extra[consts.DeviceCodeResponseVerificationURI] = d.VerificationURI
	d.Extra[consts.DeviceCodeResponseVerificationURIComplete] = d.VerificationURIComplete
	d.Extra[consts.DeviceCodeResponseExpiresIn] = d.ExpiresIn
	d.Extra[consts.DeviceCodeResponseInterval] = d.Interval

	return d.Extra
}

func (d *DeviceAuthorizeResponse) SetExtra(key string, value any) {
	d.Extra[key] = value
}

func (d *DeviceAuthorizeResponse) GetExtra(key string) any {
	return d.Extra[key]
}

var (
	_ DeviceAuthorizeResponder = (*DeviceAuthorizeResponse)(nil)
)
