// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"html/template"
	"io"
	"net/url"
)

var DefaultFormPostTemplate = template.Must(template.New("form_post").Parse(`<html>
   <head>
      <title>Submit This Form</title>
   </head>
   <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="{{ .RedirURL }}">
         {{ range $key,$value := .Parameters }}
            {{ range $parameter:= $value }}
		      <input type="hidden" name="{{ $key }}" value="{{ $parameter }}"/>
            {{ end }}
         {{ end }}
      </form>
   </body>
</html>`))

type FormPostResponseWriter func(wr io.Writer, template *template.Template, redirectURL string, parameters url.Values)

// DefaultFormPostResponseWriter renders the given template using the supplied redirect URL and parameters and writes
// the result to rw. It is the default FormPostResponseWriter used when none is configured on the provider, and produces
// an auto-submitting HTML form per the OAuth 2.0 Form Post Response Mode specification.
func DefaultFormPostResponseWriter(rw io.Writer, template *template.Template, redirectURL string, parameters url.Values) {
	_ = template.Execute(rw, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   redirectURL,
		Parameters: parameters,
	})
}

// GetPostFormHTMLTemplate returns the configured form_post HTML template from c, or DefaultFormPostTemplate when the
// provider returns nil.
func GetPostFormHTMLTemplate(ctx context.Context, c FormPostHTMLTemplateProvider) *template.Template {
	if t := c.GetFormPostHTMLTemplate(ctx); t != nil {
		return t
	}

	return DefaultFormPostTemplate
}
