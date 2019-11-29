package testfake

import (
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/config"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
)

const (
	FakeAdminRole          = "role:admin"
	fakeAdminRoleURL       = "/admin*"
	FakeAuthAllURL         = "/auth_all/*"
	fakeClientID           = "test"
	fakeSecret             = "test"
	fakeTestAdminRolesURL  = "/test_admin_roles"
	FakeTestRole           = "role:test"
	fakeTestRoleURL        = "/test_role"
	fakeTestWhitelistedURL = "/auth_all/white_listed*"
	testProxyAccepted      = "Proxy-Accepted"
	ValidUsername          = "test"
	ValidPassword          = "test"
)

func NewFakeKeycloakConfig() *config.Config {
	return &config.Config{
		ClientID:                   fakeClientID,
		ClientSecret:               fakeSecret,
		CookieAccessName:           "kc-access",
		CookieRefreshName:          "kc-state",
		DisableAllLogging:          true,
		DiscoveryURL:               "127.0.0.1:0",
		EnableAuthorizationCookies: true,
		EnableAuthorizationHeader:  true,
		EnableLogging:              false,
		EnableLoginHandler:         true,
		EnableTokenHeader:          true,
		Listen:                     "127.0.0.1:0",
		OAuthURI:                   "/oauth",
		OpenIDProviderTimeout:      time.Second * 5,
		Scopes:                     []string{},
		Verbose:                    false,
		Resources: []*resource.Resource{
			{
				URL:     fakeAdminRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeAdminRole},
			},
			{
				URL:     fakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeTestRole},
			},
			{
				URL:     fakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeAdminRole, FakeTestRole},
			},
			{
				URL:     FakeAuthAllURL,
				Methods: common.AllHTTPMethods,
				Roles:   []string{},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     common.AllHTTPMethods,
				Roles:       []string{},
			},
		},
	}
}
