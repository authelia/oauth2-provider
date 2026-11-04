// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpecialUseAddressGuardControl(t *testing.T) {
	testCases := []struct {
		server  string
		address string
		allowed bool
	}{
		{"", "127.0.0.1:443", false},
		{"", "[::1]:443", false},
		{"", "[::ffff:127.0.0.1]:443", false},
		{"", "8.8.8.8:443", true},
		{"", "[::ffff:8.8.8.8]:443", true},
		{"", "[2606:4700:4700::1111]:443", true},
		{"", "[::8.8.8.8]:443", false},
		{"", "not-an-address", false},
		{"", "/var/run/x.sock", false},

		{"127.0.0.1", "127.0.0.1:443", true},
		{"127.0.0.1", "[::ffff:127.0.0.1]:443", true},
		{"127.0.0.1", "127.0.0.2:443", false},
		{"127.0.0.1", "[::1]:443", false},
		{"127.0.0.1", "[::127.0.0.1]:443", false},
		{"127.0.0.1", "10.0.0.1:443", false},
		{"127.0.0.1", "169.254.169.254:80", false},
		{"127.0.0.1", "[fe80::1%eth0]:443", false},
		{"127.0.0.1", "8.8.8.8:443", true},
		{"127.0.0.1", "not-an-address", false},

		{"127.0.0.2", "127.0.0.2:443", true},
		{"127.0.0.2", "127.0.0.1:443", false},

		{"::ffff:127.0.0.1", "127.0.0.1:443", true},

		{"::1", "[::1]:443", true},
		{"::1", "127.0.0.1:443", false},
		{"::1", "[fe80::1%eth0]:443", false},
		{"::1", "[2606:4700:4700::1111]:443", true},

		{"10.0.0.1", "10.0.0.1:443", false},
		{"10.0.0.1", "127.0.0.1:443", false},
		{"169.254.169.254", "169.254.169.254:80", false},
		{"8.8.8.8", "127.0.0.1:443", false},
		{"8.8.8.8", "8.8.8.8:443", true},
		{"fe80::1%eth0", "[fe80::1%eth0]:443", false},
		{"invalid", "127.0.0.1:443", false},
		{"invalid", "[::1]:443", false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("server=%s,addr=%s", tc.server, tc.address), func(t *testing.T) {
			guard := &specialUseAddressGuard{}

			switch tc.server {
			case "":
			case "invalid":
				WithSpecialUseAddressGuardAllowLoopback(netip.Addr{})(guard)
			default:
				WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr(tc.server))(guard)
			}

			err := guard.control("tcp", tc.address, nil)

			if tc.allowed {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrSpecialUseAddress)
			}
		})
	}
}

func TestIsSpecialUseAddress(t *testing.T) {
	testCases := []struct {
		addr    string
		special bool
	}{
		{"0.0.0.0", true},
		{"0.255.255.255", true},
		{"1.0.0.0", false},
		{"9.255.255.255", false},
		{"10.0.0.1", true},
		{"11.0.0.0", false},
		{"100.63.255.255", false},
		{"100.64.0.1", true},
		{"100.128.0.0", false},
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"128.0.0.0", false},
		{"169.254.169.254", true},
		{"169.255.0.0", false},
		{"172.15.255.255", false},
		{"172.16.0.1", true},
		{"172.32.0.0", false},
		{"192.0.0.1", true},
		{"192.0.1.0", false},
		{"192.0.2.1", true},
		{"192.31.196.1", true},
		{"192.52.193.1", true},
		{"192.88.99.1", true},
		{"192.168.1.1", true},
		{"192.169.0.0", false},
		{"192.175.48.1", true},
		{"198.17.255.255", false},
		{"198.18.0.1", true},
		{"198.20.0.0", false},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"203.0.114.0", false},
		{"223.255.255.255", false},
		{"224.0.0.1", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"8.8.8.8", false},
		{"::", true},
		{"::1", true},
		{"::8.8.8.8", true},
		{"::127.0.0.1", true},
		{"::ffff:ffff", true},
		{"::1:0:0", false},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},
		{"64:ff9b::a00:1", true},
		{"64:ff9b:1::1", true},
		{"100::1", true},
		{"100:0:0:1::1", true},
		{"100:0:0:2::1", false},
		{"2001::1", true},
		{"2001:1ff:ffff::1", true},
		{"2001:200::1", false},
		{"2001:db8::1", true},
		{"2002::1", true},
		{"2620:4f:8000::1", true},
		{"3fff::1", true},
		{"5f00::1", true},
		{"fc00::1", true},
		{"fd12:3456::1", true},
		{"fe80::1", true},
		{"fe80::1%eth0", true},
		{"febf:ffff::1", true},
		{"fec0::1", true},
		{"feff:ffff::1", true},
		{"ff02::1", true},
		{"2606:4700:4700::1111", false},
	}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			assert.Equal(t, tc.special, IsSpecialUseAddress(netip.MustParseAddr(tc.addr)))
		})
	}

	assert.True(t, IsSpecialUseAddress(netip.Addr{}))
}

func TestNewSpecialUseAddressGuardedHTTPClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(rw, r, "/", http.StatusFound)

			return
		}

		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("ShouldRefuseLoopbackByDefault", func(t *testing.T) {
		client := guardedTestClient(server)

		_, err := client.Get(server.URL) //nolint:bodyclose

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSpecialUseAddress)
	})

	t.Run("ShouldRefuseNameResolvingToLoopback", func(t *testing.T) {
		client := guardedTestClient(server)

		_, err := client.Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1)) //nolint:bodyclose

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSpecialUseAddress)
	})

	t.Run("ShouldReachLoopbackWhenAllowed", func(t *testing.T) {
		client := guardedTestClient(server, WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))

		response, err := client.Get(server.URL)

		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("ShouldNotFollowRedirects", func(t *testing.T) {
		client := guardedTestClient(server, WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))

		response, err := client.Get(server.URL + "/redirect")

		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, http.StatusFound, response.StatusCode)
	})

	t.Run("ShouldIgnoreProxyAndNotRetry", func(t *testing.T) {
		client := NewSpecialUseAddressGuardedHTTPClient()

		transport, ok := client.HTTPClient.Transport.(*http.Transport)

		require.True(t, ok)
		assert.Nil(t, transport.Proxy)
		assert.Equal(t, 0, client.RetryMax)
		assert.Equal(t, 10*time.Second, client.HTTPClient.Timeout)
		assert.Equal(t, 4, transport.MaxConnsPerHost)
	})
}

func guardedTestClient(server *httptest.Server, opts ...SpecialUseAddressGuardOption) *retryablehttp.Client {
	client := NewSpecialUseAddressGuardedHTTPClient(opts...)

	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	return client
}
