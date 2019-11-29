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
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
)

func TestDebugHandler(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.Resources = make([]*resource.Resource, 0)
	c.EnableProfiling = true
	requests := []testfake.FakeRequest{
		{URI: "/debug/pprof/no_there", ExpectedCode: http.StatusNotFound},
		{URI: "/debug/pprof/heap", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/goroutine", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/block", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/threadcreate", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/cmdline", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/trace", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestExpirationHandler(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	uri := cfg.WithOAuthURI(common.ExpiredURL)
	requests := []testfake.FakeRequest{
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      -48 * time.Hour,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      14 * time.Hour,
			ExpectedCode: http.StatusOK,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestOauthRequestNotProxying(t *testing.T) {
	requests := []testfake.FakeRequest{
		{URI: "/oauth/test"},
		{URI: "/oauth/..//oauth/test/"},
		{URI: "/oauth/expired", Method: http.MethodPost, ExpectedCode: http.StatusMethodNotAllowed},
		{URI: "/oauth/expiring", Method: http.MethodPost},
		{URI: "/oauth%2F///../test%2F%2Foauth"},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestLoginHandlerDisabled(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableLoginHandler = false
	requests := []testfake.FakeRequest{
		{URI: c.WithOAuthURI(common.LoginURL), Method: http.MethodPost, ExpectedCode: http.StatusNotImplemented},
		{URI: c.WithOAuthURI(common.LoginURL), ExpectedCode: http.StatusMethodNotAllowed},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.EnableLoginHandler = true
	requests := []testfake.FakeRequest{
		{URI: "/oauth/login", Method: http.MethodPost, ExpectedCode: http.StatusBadRequest},
	}
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func TestLoginHandler(t *testing.T) {
	uri := testfake.NewFakeKeycloakConfig().WithOAuthURI(common.LoginURL)
	requests := []testfake.FakeRequest{
		{
			URI:          uri,
			Method:       http.MethodPost,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"username": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"password": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "test",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "notmypassword",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerBadRequest(t *testing.T) {
	requests := []testfake.FakeRequest{
		{
			URI:          testfake.NewFakeKeycloakConfig().WithOAuthURI(common.LogoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	requests := []testfake.FakeRequest{
		{
			URI:          c.WithOAuthURI(common.LogoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            c.WithOAuthURI(common.LogoutURL),
			HasCookieToken: true,
			RawToken:       "this.is.a.bad.token",
			ExpectedCode:   http.StatusUnauthorized,
		},
		{
			URI:          c.WithOAuthURI(common.LogoutURL),
			RawToken:     "this.is.a.bad.token",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerGood(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	requests := []testfake.FakeRequest{
		{
			URI:          c.WithOAuthURI(common.LogoutURL),
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              c.WithOAuthURI(common.LogoutURL) + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusTemporaryRedirect,
			ExpectedLocation: "http://example.com",
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestTokenHandler(t *testing.T) {
	uri := testfake.NewFakeKeycloakConfig().WithOAuthURI(common.TokenURL)
	goodToken := testfake.NewTestToken("example").getToken()
	requests := []testfake.FakeRequest{
		{
			URI:          uri,
			HasToken:     true,
			RawToken:     (&goodToken).Encode(),
			ExpectedCode: http.StatusOK,
		},
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			RawToken:     "niothing",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            uri,
			HasToken:       true,
			HasCookieToken: true,
			ExpectedCode:   http.StatusOK,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestServiceRedirect(t *testing.T) {
	requests := []testfake.FakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedCode:     http.StatusTemporaryRedirect,
			ExpectedLocation: "/oauth/authorize?state",
		},
		{
			URI:          "/admin",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestAuthorizationURLWithSkipToken(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	c.SkipTokenVerification = true
	testfake.NewFakeProxy(c).RunTests(t, []testfake.FakeRequest{
		{
			URI:          c.WithOAuthURI(common.AuthorizationURL),
			ExpectedCode: http.StatusNotAcceptable,
		},
	})
}

func TestAuthorizationURL(t *testing.T) {
	requests := []testfake.FakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/admin/test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/help/../admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/admin?test=yes&test1=test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:          "/oauth/test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
		{
			URI:          "/oauth/callback/..//test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestCallbackURL(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	requests := []testfake.FakeRequest{
		{
			URI:          cfg.WithOAuthURI(common.CallbackURL),
			Method:       http.MethodPost,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
		{
			URI:          cfg.WithOAuthURI(common.CallbackURL),
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:              cfg.WithOAuthURI(common.CallbackURL) + "?code=fake",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              cfg.WithOAuthURI(common.CallbackURL) + "?code=fake&state=/admin",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              cfg.WithOAuthURI(common.CallbackURL) + "?code=fake&state=L2FkbWlu",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestHealthHandler(t *testing.T) {
	c := testfake.NewFakeKeycloakConfig()
	requests := []testfake.FakeRequest{
		{
			URI:             c.WithOAuthURI(common.HealthURL),
			ExpectedCode:    http.StatusOK,
			ExpectedContent: "OK\n",
		},
		{
			URI:          c.WithOAuthURI(common.HealthURL),
			Method:       http.MethodHead,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}
