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

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
	"github.com/stretchr/testify/assert"
)

func TestRedirectToAuthorizationUnauthorized(t *testing.T) {
	requests := []testfake.FakeRequest{
		{URI: "/admin", ExpectedCode: http.StatusUnauthorized},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestRedirectToAuthorization(t *testing.T) {
	requests := []testfake.FakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
	}
	testfake.NewFakeProxy(nil).RunTests(t, requests)
}

func TestRedirectToAuthorizationWith303Enabled(t *testing.T) {
	cfg := testfake.NewFakeKeycloakConfig()
	cfg.InvalidAuthRedirectsWith303 = true

	requests := []testfake.FakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	testfake.NewFakeProxy(cfg).RunTests(t, requests)
}

func TestRedirectToAuthorizationSkipToken(t *testing.T) {
	requests := []testfake.FakeRequest{
		{URI: "/admin", ExpectedCode: http.StatusUnauthorized},
	}
	c := testfake.NewFakeKeycloakConfig()
	c.SkipTokenVerification = true
	testfake.NewFakeProxy(c).RunTests(t, requests)
}

func assertAlmostEquals(t *testing.T, expected time.Duration, actual time.Duration) {
	delta := expected - actual
	if delta < 0 {
		delta = -delta
	}
	assert.True(t, delta < time.Duration(1)*time.Minute, "Diff should be less than a minute but delta is %s", delta)
}

func TestGetAccessCookieExpiration_NoExp(t *testing.T) {
	token := testfake.NewTestToken("foo").GetToken()
	refreshToken := token.Encode()
	c := testfake.NewFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := testfake.NewFakeProxy(c).Proxy
	duration := proxy.getAccessCookieExpiration(token, refreshToken)
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_ZeroExp(t *testing.T) {
	ft := testfake.NewTestToken("foo")
	ft.SetExpiration(time.Unix(0, 0))
	token := ft.GetToken()
	refreshToken := token.Encode()
	c := testfake.NewFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := testfake.NewFakeProxy(c).Proxy
	duration := proxy.getAccessCookieExpiration(token, refreshToken)
	assert.True(t, duration > 0, "duration should be positive")
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_PastExp(t *testing.T) {
	ft := testfake.NewTestToken("foo")
	ft.SetExpiration(time.Now().AddDate(-1, 0, 0))
	token := ft.GetToken()
	refreshToken := token.Encode()
	c := testfake.NewFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := testfake.NewFakeProxy(c).Proxy
	duration := proxy.getAccessCookieExpiration(token, refreshToken)
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_ValidExp(t *testing.T) {
	ft := testfake.NewTestToken("foo")
	token := ft.GetToken()
	refreshToken := token.Encode()
	c := testfake.NewFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := testfake.NewFakeProxy(c).Proxy
	duration := proxy.getAccessCookieExpiration(token, refreshToken)
	val, ok, _ := ft.Claims.TimeClaim("exp")
	assert.True(t, ok)
	expectedDuration := time.Until(val)
	assertAlmostEquals(t, expectedDuration, duration)
}
