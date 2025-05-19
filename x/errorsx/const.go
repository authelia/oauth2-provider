package errorsx

const (
	fieldError            = "error"
	fieldErrorDescription = "error_description"
	fieldErrorHint        = "error_hint"
	fieldStatusCode       = "status_code"
)

type RFCError interface {
	GetDescription() string
	Error() string
	Reason() string
	StatusCode() int
}
