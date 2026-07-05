package rfc9449

import (
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

func singleDPoPHeader(r *http.Request) (header string, err error) {
	if len(r.Header.Values(consts.HeaderDPoP)) > 1 {
		return "", errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request contains more than one DPoP proof but only one is allowed."))
	}

	return r.Header.Get(consts.HeaderDPoP), nil
}

// requestURL reconstructs the request target URI (htu) from the request, discarding query and fragment. When the
// request did not arrive over TLS directly it falls back to the X-Forwarded-Proto header to determine the scheme;
// deployments MUST therefore ensure that header is set (and any client-supplied value stripped) by a trusted edge
// proxy, otherwise a client could influence the reconstructed htu scheme.
func requestURL(r *http.Request) string {
	scheme := consts.SchemeHTTPS

	if r.TLS == nil {
		if proto := r.Header.Get(consts.HeaderXForwardedProto); proto != "" {
			scheme = proto
		} else {
			scheme = consts.SchemeHTTP
		}
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	return scheme + "://" + host + r.URL.Path
}
