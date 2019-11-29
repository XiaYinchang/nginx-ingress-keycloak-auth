/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
	"github.com/coreos/go-oidc/jose"
	"github.com/stretchr/testify/assert"
)

func TestNewKeycloakProxy(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.DiscoveryURL = testfake.NewFakeAuthServer().GetLocation()
	cfg.Listen = "127.0.0.1:0"
	cfg.ListenHTTP = ""

	proxy, err := NewProxy(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.Router)
	assert.NotNil(t, proxy.endpoint)
	assert.NoError(t, proxy.Run())
}

func TestReverseProxyHeaders(t *testing.T) {
	p := testfake.NewFakeProxy(nil)
	token := testfake.NewTestToken(p.Idp.GetLocation())
	token.AddRealmRoles([]string{testfake.FakeAdminRole})
	signed, _ := p.Idp.SignToken(token.Claims)
	requests := []testfake.FakeRequest{
		{
			URI:           "/auth_all/test",
			RawToken:      signed.Encode(),
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Roles":    "role:admin",
				"X-Auth-Subject":  token.Claims["sub"].(string),
				"X-Auth-Token":    signed.Encode(),
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestForwardingProxy(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = testfake.ValidUsername
	cfg.ForwardingPassword = testfake.ValidPassword
	s := httptest.NewServer(&testfake.FakeUpstreamService{})
	requests := []testfake.FakeRequest{
		{
			URL:                     s.URL + "/test",
			ProxyRequest:            true,
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Bearer ey",
		},
	}
	p := testfake.NewFakeProxy(cfg)
	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.ForbiddenPage = "templates/forbidden.html.tmpl"
	cfg.Resources = []*resource.Resource{
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeAdminRole},
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:                     "/test",
			Redirects:               false,
			HasToken:                true,
			ExpectedCode:            http.StatusForbidden,
			ExpectedContentContains: "403 Permission Denied",
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestRequestIDHeader(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableRequestID = true
	requests := []testfake.FakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedHeaders: map[string]string{
				"X-Request-ID": "",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestAuthTokenHeaderDisabled(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableTokenHeader = false
	p := testfake.NewFakeProxy(c)
	token := testfake.NewTestToken(p.Idp.GetLocation())
	signed, _ := p.Idp.SignToken(token.Claims)

	requests := []testfake.FakeRequest{
		{
			URI:                    "/auth_all/test",
			RawToken:               signed.Encode(),
			ExpectedNoProxyHeaders: []string{"X-Auth-Token"},
			ExpectedProxy:          true,
			ExpectedCode:           http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestAudienceHeader(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.NoRedirects = false
	requests := []testfake.FakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Audience": "test",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestDefaultDenial(t *testing.T) {
	config := testfake.NewFakeKeycloakConfig()
	config.EnableDefaultDeny = true
	config.Resources = []*resource.Resource{
		{
			URL:         "/public/*",
			Methods:     common.AllHTTPMethods,
			WhiteListed: true,
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:           "/public/allowed",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(config).RunTests(t, requests)
}

func TestAuthorizationTemplate(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.SignInPage = "templates/sign_in.html.tmpl"
	cfg.Resources = []*resource.Resource{
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeAdminRole},
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:                     cfg.WithOAuthURI(common.AuthorizationURL),
			Redirects:               true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Sign In",
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestProxyProtocol(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableProxyProtocol = true
	requests := []testfake.FakeRequest{
		{
			URI:           testfake.FakeAuthAllURL + "/test",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           testfake.FakeAuthAllURL + "/test",
			HasToken:      true,
			ProxyProtocol: "189.10.10.1",
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "189.10.10.1",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestTokenEncryption(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableEncryptedToken = true
	c.EncryptionKey = "US36S5kubc4BXbfzCIKTQcTzG6lvixVv"
	requests := []testfake.FakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		// the token must be encrypted
		{
			URI:          "/auth_all/test",
			HasToken:     true,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestCustomResponseHeaders(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.ResponseHeaders = map[string]string{
		"CustomReponseHeader": "True",
	}
	p := testfake.NewFakeProxy(c)

	requests := []testfake.FakeRequest{
		{
			URI:       "/auth_all/test",
			HasLogin:  true,
			Redirects: true,
			ExpectedHeaders: map[string]string{
				"CustomReponseHeader": "True",
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestSkipClientIDDisabled(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	p := testfake.NewFakeProxy(c)
	// create two token, one with a bad client id
	bad := testfake.NewTestToken(p.Idp.GetLocation())
	bad.Merge(jose.Claims{"aud": "bad_client_id"})
	badSigned, _ := p.Idp.SignToken(bad.Claims)
	// and the good
	good := testfake.NewTestToken(p.Idp.GetLocation())
	goodSigned, _ := p.Idp.SignToken(good.Claims)
	requests := []testfake.FakeRequest{
		{
			URI:           "/auth_all/test",
			RawToken:      goodSigned.Encode(),
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/auth_all/test",
			RawToken:     badSigned.Encode(),
			ExpectedCode: http.StatusForbidden,
		},
	}
	p.RunTests(t, requests)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	p := testfake.NewFakeProxy(nil)
	token := testfake.NewTestToken(p.Idp.GetLocation())
	signed, _ := p.Idp.SignToken(token.Claims)

	requests := []testfake.FakeRequest{
		{
			URI:      "/auth_all/test",
			RawToken: signed.Encode(),
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Token": signed.Encode(),
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestDisableAuthorizationCookie(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableAuthorizationCookies = false
	p := testfake.NewFakeProxy(c)
	token := testfake.NewTestToken(p.Idp.GetLocation())
	signed, _ := p.Idp.SignToken(token.Claims)

	requests := []testfake.FakeRequest{
		{
			URI: "/auth_all/test",
			Cookies: []*http.Cookie{
				{Name: c.CookieAccessName, Value: signed.Encode()},
				{Name: "mycookie", Value: "myvalue"},
			},
			HasToken:                true,
			ExpectedContentContains: "kc-access=censored; mycookie=myvalue",
			ExpectedCode:            http.StatusOK,
			ExpectedProxy:           true,
		},
	}
	p.RunTests(t, requests)
}

func newFakeHTTPRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		Header: make(map[string][]string),
		Host:   "127.0.0.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1",
			Path:   path,
		},
	}
}
