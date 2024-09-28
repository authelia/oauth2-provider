package jwt

import "time"

var (
	MarshalSingleStringAsArray = true
	TimePrecision              = time.Second
	TimeFunc                   = time.Now
)
