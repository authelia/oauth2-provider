// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestSingleDPoPHeader(t *testing.T) {
	testCases := []struct {
		name    string
		values  []string
		want    string
		wantErr error
	}{
		{
			name: "None",
			want: "",
		},
		{
			name:   "One",
			values: []string{"proof-a"},
			want:   "proof-a",
		},
		{
			name:    "Multiple",
			values:  []string{"proof-a", "proof-b"},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			for _, v := range tc.values {
				r.Header.Add(consts.HeaderDPoP, v)
			}

			got, err := singleDPoPHeader(r)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRequestURL(t *testing.T) {
	testCases := []struct {
		name   string
		tls    bool
		xfp    string
		host   string
		rawURL string
		want   string
	}{
		{
			name:   "TLSDirect",
			tls:    true,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token",
			want:   "https://as.example.com/token",
		},
		{
			name:   "TLSDirectIgnoresForwardedProto",
			tls:    true,
			xfp:    consts.SchemeHTTP,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token",
			want:   "https://as.example.com/token",
		},
		{
			name:   "ForwardedProtoHTTPS",
			xfp:    consts.SchemeHTTPS,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token",
			want:   "https://as.example.com/token",
		},
		{
			name:   "ForwardedProtoHTTP",
			xfp:    consts.SchemeHTTP,
			host:   "as.example.com",
			rawURL: "http://as.example.com/token",
			want:   "http://as.example.com/token",
		},
		{
			name:   "NoTLSNoForwardedProtoDefaultsHTTP",
			host:   "as.example.com",
			rawURL: "http://as.example.com/token",
			want:   "http://as.example.com/token",
		},
		{
			name:   "HostFallsBackToURLHost",
			xfp:    consts.SchemeHTTPS,
			host:   "",
			rawURL: "https://fallback.example.com/token",
			want:   "https://fallback.example.com/token",
		},
		{
			name:   "DiscardsQuery",
			tls:    true,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token?access_token=secret",
			want:   "https://as.example.com/token",
		},
		{
			name:   "PreservesEncodedQueryDelimiter",
			tls:    true,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token%3Fx=1",
			want:   "https://as.example.com/token%3Fx=1",
		},
		{
			name:   "PreservesEncodedFragmentDelimiter",
			tls:    true,
			host:   "as.example.com",
			rawURL: "https://as.example.com/token%23frag",
			want:   "https://as.example.com/token%23frag",
		},
		{
			name:   "PreservesEncodedSpace",
			tls:    true,
			host:   "as.example.com",
			rawURL: "https://as.example.com/to%20ken",
			want:   "https://as.example.com/to%20ken",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			require.NoError(t, err)

			r := &http.Request{Header: http.Header{}, URL: u, Host: tc.host}

			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}

			if tc.xfp != "" {
				r.Header.Set(consts.HeaderXForwardedProto, tc.xfp)
			}

			assert.Equal(t, tc.want, requestURL(r))
		})
	}
}

func TestNormalizeHTU(t *testing.T) {
	testCases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "NoChange",
			raw:  "https://as.example.com/token",
			want: "https://as.example.com/token",
		},
		{
			name: "StripsDefaultHTTPSPort",
			raw:  "https://as.example.com:443/token",
			want: "https://as.example.com/token",
		},
		{
			name: "StripsDefaultHTTPPort",
			raw:  "http://as.example.com:80/token",
			want: "http://as.example.com/token",
		},
		{
			name: "KeepsNonDefaultPort",
			raw:  "https://as.example.com:8443/token",
			want: "https://as.example.com:8443/token",
		},
		{
			name: "KeepsHTTPSPortOnHTTP",
			raw:  "http://as.example.com:443/token",
			want: "http://as.example.com:443/token",
		},
		{
			name: "LowercasesSchemeAndHost",
			raw:  "HTTPS://AS.EXAMPLE.COM/Token",
			want: "https://as.example.com/Token",
		},
		{
			name: "StripsQuery",
			raw:  "https://as.example.com/token?access_token=secret",
			want: "https://as.example.com/token",
		},
		{
			name: "StripsFragment",
			raw:  "https://as.example.com/token#frag",
			want: "https://as.example.com/token",
		},
		{
			name: "RemovesParentDotSegments",
			raw:  "https://as.example.com/token/../admin",
			want: "https://as.example.com/admin",
		},
		{
			name: "RemovesCurrentDotSegments",
			raw:  "https://as.example.com/./token",
			want: "https://as.example.com/token",
		},
		{
			name: "RemovesPercentEncodedDotSegments",
			raw:  "https://as.example.com/token/%2E%2E/admin",
			want: "https://as.example.com/admin",
		},
		{
			name: "PreservesEmptySegments",
			raw:  "https://as.example.com/a//token",
			want: "https://as.example.com/a//token",
		},
		{
			name: "PreservesTrailingSlash",
			raw:  "https://as.example.com/token/",
			want: "https://as.example.com/token/",
		},
		{
			name: "DecodesUnreservedPercentEncoding",
			raw:  "https://as.example.com/%7Etoken",
			want: "https://as.example.com/~token",
		},
		{
			name: "UppercasesPercentEncoding",
			raw:  "https://as.example.com/a%2fb",
			want: "https://as.example.com/a%2Fb",
		},
		{
			name: "PreservesEncodedSlash",
			raw:  "https://as.example.com/a%2Fb",
			want: "https://as.example.com/a%2Fb",
		},
		{
			name: "AddsRootPathWhenEmpty",
			raw:  "https://as.example.com",
			want: "https://as.example.com/",
		},
		{
			name:    "ParseError",
			raw:     "http://[::1",
			wantErr: true,
		},
		{
			name:    "RejectsRelativeURI",
			raw:     "/token",
			wantErr: true,
		},
		{
			name:    "RejectsMissingHost",
			raw:     "https:///token",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeHTU(tc.raw)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRemoveDotSegments(t *testing.T) {
	testCases := []struct {
		path string
		want string
	}{
		{path: "/a/b/c/./../../g", want: "/a/g"},
		{path: "/a/b/c/../../../g", want: "/g"},
		{path: "/../a", want: "/a"},
		{path: "/a/..", want: "/"},
		{path: "/a/../..", want: "/"},
		{path: "/a/b/", want: "/a/b/"},
		{path: "/a/b/.", want: "/a/b/"},
		{path: "/a/b/..", want: "/a/"},
		{path: "/", want: "/"},
		{path: "//a", want: "//a"},
		{path: "/a//", want: "/a//"},
		{path: "/.", want: "/"},
		{path: "/..", want: "/"},
		{path: "", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, removeDotSegments(tc.path))
		})
	}
}

func TestNormalizePercentEncoding(t *testing.T) {
	testCases := []struct {
		name string
		path string
		want string
	}{
		{name: "Unchanged", path: "/token", want: "/token"},
		{name: "DecodesUnreserved", path: "/%7E%61%2D%2E%5F", want: "/~a-._"},
		{name: "UppercasesReserved", path: "/a%2fb%3fc", want: "/a%2Fb%3Fc"},
		{name: "KeepsReservedEncoded", path: "/a%2Fb", want: "/a%2Fb"},
		{name: "IgnoresTruncatedTriplet", path: "/a%2", want: "/a%2"},
		{name: "IgnoresNonHexTriplet", path: "/a%zzb", want: "/a%zzb"},
		{name: "Empty", path: "", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizePercentEncoding(tc.path))
		})
	}
}
