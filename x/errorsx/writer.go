package errorsx

import (
	"context"
	"encoding/json"
	stderr "errors"
	"net/http"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
)

// WriteJSONError is a helper function for writing errors in various scenarios. Taken from github.com/ory/herodot.
func WriteJSONError(w http.ResponseWriter, r *http.Request, err error) {
	if c := StatusCodeCarrier(nil); stderr.As(err, &c) {
		WriteJSONErrorCode(w, r, c.StatusCode(), err)
	} else {
		WriteJSONErrorCode(w, r, http.StatusInternalServerError, err)
	}
}

// WriteJSONErrorCode is a helper function for writing errors in various scenarios. Taken from github.com/ory/herodot.
func WriteJSONErrorCode(w http.ResponseWriter, r *http.Request, code int, err error) {
	if code == 0 {
		code = http.StatusInternalServerError
	}

	if errors.Is(r.Context().Err(), context.Canceled) {
		code = 499
	}

	w.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	w.WriteHeader(code)

	_ = json.NewEncoder(w).Encode(err)
}
