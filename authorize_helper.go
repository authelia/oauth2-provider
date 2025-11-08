// Copyright © 2023 Ory Corp
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

func DefaultFormPostResponseWriter(rw io.Writer, template *template.Template, redirectURL string, parameters url.Values) {
	_ = template.Execute(rw, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   redirectURL,
		Parameters: parameters,
	})
}

func GetPostFormHTMLTemplate(ctx context.Context, c FormPostHTMLTemplateProvider) *template.Template {
	if t := c.GetFormPostHTMLTemplate(ctx); t != nil {
		return t
	}

	return DefaultFormPostTemplate
}
