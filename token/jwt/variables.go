package jwt

import "time"

var (
	MarshalSingleStringAsArray = true
	TimePrecision              = time.Second

	// TODO: inject clock?
	TimeFunc                   = time.Now
)
