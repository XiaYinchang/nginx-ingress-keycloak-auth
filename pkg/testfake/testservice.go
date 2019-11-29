package testfake

import (
	"net/http/httptest"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/config"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/server"
)

func NewTestService() string {
	_, _, u := NewTestProxyService(nil)
	return u
}

func NewTestProxyService(config *config.Config) (*server.OauthProxy, *FakeAuthServer, string) {
	auth := NewFakeAuthServer()
	if config == nil {
		config = NewFakeKeycloakConfig()
	}
	config.DiscoveryURL = auth.GetLocation()
	config.RevocationEndpoint = auth.GetRevocationURL()
	config.Verbose = false
	config.EnableLogging = false

	proxy, err := server.NewProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.Upstream = new(FakeUpstreamService)
	service := httptest.NewServer(proxy.Router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	if proxy.Client, proxy.Idp, proxy.IdpClient, err = proxy.NewOpenIDClient(); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}
