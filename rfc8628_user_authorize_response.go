package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
)

// RFC8628UserAuthorizeResponse is an implementation of RFC8628UserAuthorizeResponder
type RFC8628UserAuthorizeResponse struct {
	Header     http.Header    `json:"-"`
	Parameters url.Values     `json:"-"`
	Status     string         `json:"status"`
	Extra      map[string]any `json:"-"`
}

func NewRFC8628UserAuthorizeResponse() *RFC8628UserAuthorizeResponse {
	return &RFC8628UserAuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
		Extra:      map[string]any{},
	}
}

func (d *RFC8628UserAuthorizeResponse) GetHeader() http.Header {
	return d.Header
}

func (d *RFC8628UserAuthorizeResponse) AddHeader(key, value string) {
	d.Header.Add(key, value)
}

func (d *RFC8628UserAuthorizeResponse) GetParameters() url.Values {
	return d.Parameters
}

func (d *RFC8628UserAuthorizeResponse) AddParameter(key, value string) {
	d.Parameters.Add(key, value)
}

func (d *RFC8628UserAuthorizeResponse) GetStatus() string {
	return d.Status
}

func (d *RFC8628UserAuthorizeResponse) SetStatus(status string) {
	d.Status = status
}

func (d *RFC8628UserAuthorizeResponse) ToJson(rw io.Writer) error {
	return json.NewEncoder(rw).Encode(&d)
}

func (d *RFC8628UserAuthorizeResponse) FromJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d)
}

func (d *RFC8628UserAuthorizeResponse) SetExtra(key string, value any) {
	d.Extra[key] = value
}

func (d *RFC8628UserAuthorizeResponse) GetExtra(key string) any {
	return d.Extra[key]
}

// ToMap converts the response to a map.
func (d *RFC8628UserAuthorizeResponse) ToMap() map[string]any {
	d.Extra[consts.DeviceCodeResponseStatus] = d.Status

	return d.Extra
}

var (
	_ RFC8628UserAuthorizeResponder = (*RFC8628UserAuthorizeResponse)(nil)
)
