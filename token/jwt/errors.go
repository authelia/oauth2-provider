package jwt

import "errors"

var (
	ErrNotRegistered = errors.New("error: no JWKS registered")
)
