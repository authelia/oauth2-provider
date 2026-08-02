package rfc7591

import "errors"

var (
	errTestCreateSessionFailed = errors.New("create access token session failed")
)

const (
	testEndpoint = "https://auth.example.com/register"
	testClientID = "abc"
)
