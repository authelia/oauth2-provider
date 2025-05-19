package errorsx

const (
	fieldError            = "error"
	fieldErrorDescription = "error_description"
	fieldErrorHint        = "error_hint"
)

type RFCError interface {
	GetDescription() string
	Error() string
	Reason() string
}
