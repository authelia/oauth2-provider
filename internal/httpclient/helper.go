package httpclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func isCertError(err error) bool {
	var e *tls.CertificateVerificationError

	return errors.As(err, &e)
}

func getBodyReaderAndContentLength(raw any) (reader ReaderFunc, n int64, err error) {
	switch body := raw.(type) {
	// If they gave us a function already, great! Use it.
	case ReaderFunc:
		reader = body
		tmp, err := body()
		if err != nil {
			return nil, 0, err
		}
		if lr, ok := tmp.(LenReader); ok {
			n = int64(lr.Len())
		}
		if c, ok := tmp.(io.Closer); ok {
			c.Close()
		}

	case func() (io.Reader, error):
		reader = body
		tmp, err := body()
		if err != nil {
			return nil, 0, err
		}

		if lr, ok := tmp.(LenReader); ok {
			n = int64(lr.Len())
		}

		if c, ok := tmp.(io.Closer); ok {
			c.Close()
		}

	// If a regular byte slice, we can read it over and over via new
	// readers
	case []byte:
		buf := body
		reader = func() (io.Reader, error) {
			return bytes.NewReader(buf), nil
		}

		n = int64(len(buf))

	// If a bytes.Buffer we can read the underlying byte slice over and
	// over
	case *bytes.Buffer:
		buf := body
		reader = func() (io.Reader, error) {
			return bytes.NewReader(buf.Bytes()), nil
		}

		n = int64(buf.Len())
	// We prioritize *bytes.Reader here because we don't really want to
	// deal with it seeking so want it to match here instead of the
	// io.ReadSeeker case.
	case *bytes.Reader:
		snapshot := *body
		reader = func() (io.Reader, error) {
			r := snapshot
			return &r, nil
		}

		n = int64(body.Len())
	// Compat case
	case io.ReadSeeker:
		raw := body
		reader = func() (io.Reader, error) {
			_, err := raw.Seek(0, 0)
			return io.NopCloser(raw), err
		}
		if lr, ok := raw.(LenReader); ok {
			n = int64(lr.Len())
		}

	// Read all in so we can reset
	case io.Reader:
		buf, err := io.ReadAll(body)
		if err != nil {
			return nil, 0, err
		}
		if len(buf) == 0 {
			reader = func() (io.Reader, error) {
				return http.NoBody, nil
			}
			n = 0
		} else {
			reader = func() (io.Reader, error) {
				return bytes.NewReader(buf), nil
			}
			n = int64(len(buf))
		}

	// No body provided, nothing to do
	case nil:

	// Unrecognized type
	default:
		return nil, 0, fmt.Errorf("cannot handle type %T", raw)
	}
	return reader, n, nil
}
