package errorsx

import (
	"context"
	"encoding/json"
	stderr "errors"
	"fmt"
	"net/http"
	"strings"

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

type Fields map[string]string

func (f Fields) EncodeRFC6750() string {
	items := make([]string, 0, len(f))

	for key, value := range f {
		items = append(items, fmt.Sprintf(`%s="%s"`, key, value))
	}

	return fmt.Sprintf("Bearer %s", strings.Join(items, ", "))
}

// WriteRFC6750Error handles a RFC6750 error response.
func WriteRFC6750Error(w http.ResponseWriter, e any, extra Fields) {
	var (
		code   int
		fields = make(Fields)
		err    error
	)

	switch et := e.(type) {
	case error:
		err = et

		if rfc, ok := et.(RFCError); ok {
			if field := rfc.Error(); len(field) != 0 {
				fields[fieldError] = field
			}

			if field := rfc.GetDescription(); len(field) != 0 {
				fields[fieldErrorDescription] = field
			}

			if field := rfc.Reason(); len(field) != 0 {
				fields[fieldErrorHint] = field
			}

			code = rfc.StatusCode()
		} else {
			fields[fieldError] = et.Error()
		}
	case map[string]any:
		for field, value := range et {
			if statusCode, ok := value.(int); ok && field == fieldStatusCode {
				code = statusCode
			} else {
				fields[field] = fmt.Sprintf("%s", value)

				if err != nil {
					continue
				}

				switch field {
				case fieldError, fieldErrorDescription:
					if ev, ok := value.(error); ok {
						err = ev
					}
				}
			}
		}

		if err != nil {
			break
		}

		if value, ok := fields[fieldErrorDescription]; ok {
			err = errors.New(value)
		} else if value, ok = fields[fieldError]; ok {
			err = errors.New(value)
		}
	case nil:
		break
	default:
		code = http.StatusBadRequest
		fields[fieldError] = "invalid_request"
		fields[fieldErrorDescription] = fmt.Sprintf("%s", e)
		err = errors.New(fields[fieldErrorDescription])
	}

	var ok bool

	for k, v := range extra {
		if _, ok = fields[k]; ok {
			continue
		}

		fields[k] = v
	}

	if code < http.StatusBadRequest || code > http.StatusForbidden {
		code = http.StatusBadRequest
	}

	w.Header().Set(consts.HeaderWWWAuthenticate, fields.EncodeRFC6750())
	w.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	w.WriteHeader(code)

	if err != nil {
		_ = json.NewEncoder(w).Encode(err)
	}
}
