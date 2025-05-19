package consts

const (
	HeaderContentType     = "Content-Type"
	HeaderCacheControl    = "Cache-Control"
	HeaderPragma          = "Pragma"
	HeaderAuthorization   = "Authorization"
	HeaderLocation        = "Location"
	HeaderAcceptLanguage  = "Accept-Language"
	HeaderWWWAuthenticate = "WWW-Authenticate"
)

const (
	ContentTypeApplicationURLEncodedForm        = "application/x-www-form-urlencoded"
	ContentTypeApplicationJSON                  = "application/json; charset=utf-8"
	ContentTypeApplicationTokenIntrospectionJWT = "application/token-introspection+jwt; charset=utf-8"
	ContentTypeTextHTML                         = "text/html; charset=utf-8"
)

const (
	PragmaNoCache       = "no-cache"
	CacheControlNoStore = "no-store"
)

const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)
