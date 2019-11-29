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
	"testing"
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/util"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/config"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
	"github.com/coreos/go-oidc/jose"
	"github.com/rs/cors"
	"github.com/stretchr/testify/assert"
	"gopkg.in/resty.v1"
)

func TestOauthRequests(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	requests := []testfake.FakeRequest{
		{
			URI:          "/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URI:          "/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestOauthRequestsWithBaseURI(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.BaseURI = "/base-uri"
	requests := []testfake.FakeRequest{
		{
			URI:          "/base-uri/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URI:          "/base-uri/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/base-uri/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           "/oauth/authorize",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/callback",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/health",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestMethodExclusions(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []*resource.Resource{
		{
			URL:     "/post",
			Methods: []string{http.MethodPost, http.MethodPut},
		},
	}
	requests := []testfake.FakeRequest{
		{ // we should get a 401
			URI:          "/post",
			Method:       http.MethodPost,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // we should be permitted
			URI:           "/post",
			Method:        http.MethodGet,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestStrangeRoutingError(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []*resource.Resource{
		{
			URL:     "/api/v1/events/123456789",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"user"},
		},
		{
			URL:     "/api/v1/events/404",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"monitoring"},
		},
		{
			URL:     "/api/v1/audit/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"auditor", "dev"},
		},
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"dev"},
		},
	}
	requests := []testfake.FakeRequest{
		{ // should work
			URI:           "/api/v1/events/123456789",
			HasToken:      true,
			Redirects:     true,
			Roles:         []string{"user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // should break with bad role
			URI:          "/api/v1/events/123456789",
			HasToken:     true,
			Redirects:    true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // good
			URI:           "/api/v1/events/404",
			HasToken:      true,
			Redirects:     false,
			Roles:         []string{"monitoring", "test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // this should fail with no roles - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // this should fail with bad role - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work with catch-all
			URI:           "/api/v1/event/1000",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"dev"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}

	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestNoProxyingRequests(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.Resources = []resource.Resource{
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
		},
	}
	requests := []testfake.FakeRequest{
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "/../%2e",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

const testAdminURI = "/admin/test"

func TestStrangeAdminRequests(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []resource.Resource{
		{
			URL:     "/admin*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeAdminRole},
		},
	}
	requests := []testfake.FakeRequest{
		{ // check for escaping
			URI:          "//admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:          "/" + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs
			URI:          testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/.." + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for it works
			URI:           "/" + testAdminURI,
			HasToken:      true,
			Roles:         []string{testfake.FakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for is doens't work
			URI:          "//admin//test",
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/help/../admin/test/21",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []resource.Resource{
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeTestRole},
		},
		{
			URL:         "/whitelist*",
			WhiteListed: true,
			Methods:     common.AllHTTPMethods,
		},
	}
	requests := []testfake.FakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			Roles:         []string{testfake.FakeTestRole},
			ExpectedCode:  http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestRequireAnyRoles(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []resource.Resource{
		{
			URL:            "/require_any_role/*",
			Methods:        common.AllHTTPMethods,
			RequireAnyRole: true,
			Roles:          []string{"admin", "guest"},
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:          "/require_any_role/test",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/require_any_role/test",
			HasToken:      true,
			Roles:         []string{"guest"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/require_any_role/test",
			HasToken:     true,
			Roles:        []string{"guest1"},
			ExpectedCode: http.StatusForbidden,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestGroupPermissionsMiddleware(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []resource.Resource{
		{
			URL:     "/with_role_and_group*",
			Methods: common.AllHTTPMethods,
			Groups:  []string{"admin"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/with_group*",
			Methods: common.AllHTTPMethods,
			Groups:  []string{"admin"},
		},
		{
			URL:     "/with_many_groups*",
			Methods: common.AllHTTPMethods,
			Groups:  []string{"admin", "user", "tester"},
		},
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Roles:        []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Groups:       []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_role_and_group/test",
			HasToken:      true,
			Groups:        []string{"admin"},
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_groupdd",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"test", "admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_many_groups/test",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"user"},
			Roles:         []string{"test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"tester", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"bad", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.Resources = []resource.Resource{
		{
			URL:     "/admin*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{testfake.FakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{testfake.FakeAdminRole, testfake.FakeTestRole},
		},
		{
			URL:     "/section/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeAdminRole},
		},
		{
			URL:     "/section/one",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"one"},
		},
		{
			URL:     "/whitelist",
			Methods: []string{"GET"},
			Roles:   []string{},
		},
		{
			URL:     "/*",
			Methods: common.AllHTTPMethods,
			Roles:   []string{testfake.FakeTestRole},
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:          "/",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check with a token but not test role
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"one", "two"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:          "/test",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, but post method
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token
			URI:           "/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token on base
			URI:           "/",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token, not signed
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			NotSigned:    true,
			Roles:        []string{testfake.FakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed
			URI:          "/admin/page",
			Method:       http.MethodPost,
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{testfake.FakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles (10)
			URI:          "/admin/page",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{testfake.FakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:           "/admin/page",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeTestRole, testfake.FakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url
			URI:          "/admin/..//admin/page",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:          "/admin/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"hehe"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token, role (15)
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, but good token
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, wrong roles
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{testfake.FakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token admin test role
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token but without both roles
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Roles:        []string{testfake.FakeAdminRole},
		},
		{ // check with a token with both roles (20)
			URI:           "/test_admin_role",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeAdminRole, testfake.FakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/test1",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{testfake.FakeTestRole, testfake.FakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/one",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{testfake.FakeTestRole, testfake.FakeAdminRole},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/one",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"one"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Cors    cors.Options
		Request testfake.FakeRequest
	}{
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
			},
			Request: testfake.FakeRequest{
				URI: testfake.FakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*", "https://examples.com"},
			},
			Request: testfake.FakeRequest{
				URI: testfake.FakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			Request: testfake.FakeRequest{
				URI:    testfake.FakeAuthAllURL,
				Method: http.MethodOptions,
				Headers: map[string]string{
					"Origin":                        "127.0.0.1",
					"Access-Control-Request-Method": "GET",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin":  "*",
					"Access-Control-Allow-Methods": "GET",
				},
			},
		},
	}

	for _, c := range cases {
		cfg := testfake.NewFakeKeycloakConfig()
		cfg.CorsCredentials = c.Cors.AllowCredentials
		cfg.CorsExposedHeaders = c.Cors.ExposedHeaders
		cfg.CorsHeaders = c.Cors.AllowedHeaders
		cfg.CorsMaxAge = time.Duration(c.Cors.MaxAge) * time.Second
		cfg.CorsMethods = c.Cors.AllowedMethods
		cfg.CorsOrigins = c.Cors.AllowedOrigins

		testfake.NewFakeProxy(cfg).RunTests(t, []testfake.FakeRequest{c.Request})
	}
}

func TestCheckRefreshTokens(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EncryptionKey = testfake.TestEncryptionKey
	fn := func(no int, req *resty.Request, resp *resty.Response) {
		if no == 0 {
			<-time.After(1000 * time.Millisecond)
		}
	}
	p := testfake.NewFakeProxy(cfg)
	p.Idp.SetTokenExpiration(1000 * time.Millisecond)

	requests := []testfake.FakeRequest{
		{
			URI:           testfake.FakeAuthAllURL,
			HasLogin:      true,
			Redirects:     true,
			OnResponse:    fn,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:             testfake.FakeAuthAllURL,
			Redirects:       false,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
		},
	}
	p.RunTests(t, requests)
}

func TestCheckEncryptedCookie(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = true
	cfg.Verbose = true
	cfg.EnableLogging = true
	cfg.EncryptionKey = testfake.TestEncryptionKey
	testEncryptedToken(t, cfg)
}

func TestCheckForcedEncryptedCookie(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = false
	cfg.ForceEncryptedCookie = true
	cfg.Verbose = true
	cfg.EnableLogging = true
	cfg.EncryptionKey = testfake.TestEncryptionKey
	testEncryptedToken(t, cfg)
}

func testEncryptedToken(t *testing.T, cfg *config.Config) {
	fn := func(no int, req *resty.Request, resp *resty.Response) {
		if no == 0 {
			<-time.After(1000 * time.Millisecond)
		}
	}
	val := func(value string) bool {
		// check the cookie value is an encrypted token
		accessToken, err := util.DecodeText(value, cfg.EncryptionKey)
		if err != nil {
			return false
		}
		jwt, err := jose.ParseJWT(accessToken)
		if err != nil {
			return false
		}
		claims, err := jwt.Claims()
		if err != nil {
			return false
		}
		return assert.Contains(t, claims, "aud") && assert.Contains(t, claims, "email")
	}
	p := testfake.NewFakeProxy(cfg)
	p.Idp.SetTokenExpiration(1000 * time.Millisecond)

	requests := []testfake.FakeRequest{
		{
			URI:           testfake.FakeAuthAllURL,
			HasLogin:      true,
			Redirects:     true,
			OnResponse:    fn,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:                      testfake.FakeAuthAllURL,
			Redirects:                false,
			ExpectedProxy:            true,
			ExpectedCode:             http.StatusOK,
			ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
			ExpectedCookiesValidator: map[string]func(string) bool{cfg.CookieAccessName: val},
		},
	}
	p.RunTests(t, requests)
}

func TestCustomHeadersHandler(t *testing.T) {
	requests := []struct {
		Match   []string
		Request testfake.FakeRequest
	}{
		{
			Match: []string{"subject", "userid", "email", "username"},
			Request: testfake.FakeRequest{
				URI:      testfake.FakeAuthAllURL,
				HasToken: true,
				TokenClaims: jose.Claims{
					"sub":                "test-subject",
					"username":           "rohith",
					"preferred_username": "rohith",
					"email":              "gambol99@gmail.com",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Match: []string{"given_name", "family_name"},
			Request: testfake.FakeRequest{
				URI:      testfake.FakeAuthAllURL,
				HasToken: true,
				TokenClaims: jose.Claims{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Given-Name":  "Rohith",
					"X-Auth-Family-Name": "Jayawardene",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := testfake.NewFakeKeycloakConfig()
		cfg.AddClaims = c.Match
		testfake.NewFakeProxy(cfg).RunTests(t, []testfake.FakeRequest{c.Request})
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []resource.Resource{
		{
			URL:     "/admin",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: common.AllHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: common.AllHTTPMethods,
		},
	}
	requests := []testfake.FakeRequest{
		{
			URI:          "/admin",
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/admin",
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/test",
			Roles:         []string{"test"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/either",
			Roles:         []string{"test", "admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/either",
			Roles:        []string{"no_roles"},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

// check to see if custom headers are hitting the upstream
func TestCustomHeaders(t *testing.T) {
	requests := []struct {
		Headers map[string]string
		Request testfake.FakeRequest
	}{
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
			},
			Request: testfake.FakeRequest{
				URI:           "/gambol99.htm",
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeader": "test",
			},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeader": "test",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
				"TestHeaderTwo": "two",
			},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
					"TestHeaderTwo": "two",
				},
			},
		},
	}
	for _, c := range requests {
		cfg := testfake.NewFakeKeycloakConfig()
		cfg.Resources = []resource.Resource{{URL: "/admin*", Methods: common.AllHTTPMethods}}
		cfg.Headers = c.Headers
		testfake.NewFakeProxy(cfg).RunTests(t, []testfake.FakeRequest{c.Request})
	}
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	requests := []struct {
		Matches map[string]string
		Request testfake.FakeRequest
	}{
		// jose.StringClaim test
		{
			Matches: map[string]string{"cal": "test"},
			Request: testfake.FakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: testfake.FakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "tes"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "not_match"},
			Request: testfake.FakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: testfake.FakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: testfake.FakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: jose.Claims{
					"item":  "tester",
					"found": "something",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": ".*"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*$"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		// jose.StringsClaim test
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{"nonMatchingClaim", "test", "anotherNonMatching"}},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{"1test", "2test", "3test"}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: testfake.FakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{
				"item1": "^t.*t",
				"item2": "^another",
			},
			Request: testfake.FakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: jose.Claims{
					"item1": []string{"randomItem", "test"},
					"item2": []string{"randomItem", "anotherItem"},
					"item3": []string{"randomItem2", "anotherItem3"},
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := testfake.NewFakeKeycloakConfig()
		cfg.Resources = []resource.Resource{{URL: "/admin*", Methods: common.AllHTTPMethods}}
		cfg.MatchClaims = c.Matches
		testfake.NewFakeProxy(cfg).RunTests(t, []testfake.FakeRequest{c.Request})
	}
}
