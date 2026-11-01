// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

const (
	semanticExecuteAll = "execute_all"

	httpEvaluatorTimeout      = 5 * time.Second
	httpEvaluatorResponseSize = 1 << 20
)

// Entity is an AuthZEN subject or resource.
type Entity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Action is an AuthZEN action.
type Action struct {
	Name string `json:"name"`
}

// Evaluation is a single item of an Access Evaluations request.
type Evaluation struct {
	Subject  Entity `json:"subject"`
	Action   Action `json:"action"`
	Resource Entity `json:"resource"`
}

// Options are the options of an Access Evaluations request.
type Options struct {
	EvaluationsSemantic string `json:"evaluations_semantic"`
}

// EvaluationsRequest is an Access Evaluations request.
type EvaluationsRequest struct {
	Context     map[string]any `json:"context,omitempty"`
	Evaluations []Evaluation   `json:"evaluations"`
	Options     Options        `json:"options"`
}

// Decision is a single decision of an Access Evaluations response. A nil Decision is a malformed response.
type Decision struct {
	Decision *bool          `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationsResponse is an Access Evaluations response, whose decisions are in the order of the request.
type EvaluationsResponse struct {
	Evaluations []Decision `json:"evaluations"`
}

// Evaluator conveys an Access Evaluations request to a Policy Decision Point, which may run in process.
type Evaluator interface {
	// Evaluate returns the response to the request, or an error if a decision could not be obtained.
	Evaluate(ctx context.Context, request *EvaluationsRequest) (response *EvaluationsResponse, err error)
}

// HTTPEvaluator implements Evaluator with the HTTPS JSON binding of the Authorization API.
//
// See: https://openid.net/specs/authorization-api-1_0.html
type HTTPEvaluator struct {
	// Endpoint is the 'access_evaluations_endpoint' of the Policy Decision Point.
	Endpoint string

	// Client is the HTTP client. When nil a client with a short timeout which does not follow redirects is used.
	Client *http.Client

	// Authorize applies the credentials of the Policy Enforcement Point to a request.
	Authorize func(ctx context.Context, request *http.Request) (err error)
}

// Evaluate implements Evaluator.
func (e *HTTPEvaluator) Evaluate(ctx context.Context, request *EvaluationsRequest) (response *EvaluationsResponse, err error) {
	var body []byte

	if body, err = json.Marshal(request); err != nil {
		return nil, err
	}

	var r *http.Request

	if r, err = http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body)); err != nil {
		return nil, err
	}

	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	if e.Authorize != nil {
		if err = e.Authorize(ctx, r); err != nil {
			return nil, err
		}
	}

	var res *http.Response

	if res, err = e.client().Do(r); err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the policy decision point responded with status %d", res.StatusCode)
	}

	response = &EvaluationsResponse{}

	if err = json.NewDecoder(io.LimitReader(res.Body, httpEvaluatorResponseSize)).Decode(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (e *HTTPEvaluator) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}

	return &http.Client{
		Timeout: httpEvaluatorTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
