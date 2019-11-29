package testfake

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/config"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/server"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/util"
	"github.com/coreos/go-oidc/jose"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gopkg.in/resty.v1"
)

const (
	TestEncryptionKey = "ZSeCYDUxIlhDrmPpa1Ldc7il384esSF2"
)

type FakeRequest struct {
	BasicAuth               bool
	Cookies                 []*http.Cookie
	Expires                 time.Duration
	FormValues              map[string]string
	Groups                  []string
	HasCookieToken          bool
	HasLogin                bool
	HasToken                bool
	Headers                 map[string]string
	Method                  string
	NotSigned               bool
	OnResponse              func(int, *resty.Request, *resty.Response)
	Password                string
	ProxyProtocol           string
	ProxyRequest            bool
	RawToken                string
	Redirects               bool
	Roles                   []string
	TokenClaims             jose.Claims
	URI                     string
	URL                     string
	Username                string
	ExpectedCode            int
	ExpectedContent         string
	ExpectedContentContains string
	ExpectedCookies         map[string]string
	ExpectedHeaders         map[string]string
	ExpectedLocation        string
	ExpectedNoProxyHeaders  []string
	ExpectedProxy           bool
	ExpectedProxyHeaders    map[string]string

	// advanced test cases
	ExpectedCookiesValidator map[string]func(string) bool
}

type FakeProxy struct {
	config  *config.Config
	Idp     *FakeAuthServer
	Proxy   *server.OauthProxy
	cookies map[string]*http.Cookie
}

func NewFakeProxy(c *config.Config) *FakeProxy {
	log.SetOutput(ioutil.Discard)
	if c == nil {
		c = NewFakeKeycloakConfig()
	}
	auth := NewFakeAuthServer()
	c.DiscoveryURL = auth.GetLocation()
	c.RevocationEndpoint = auth.GetRevocationURL()
	c.Verbose = true
	proxy, err := server.NewProxy(c)
	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}
	proxy.Log = zap.NewNop()
	proxy.Upstream = &FakeUpstreamService{}
	if err = proxy.Run(); err != nil {
		panic("failed to create the proxy service, error: " + err.Error())
	}
	c.RedirectionURL = fmt.Sprintf("http://%s", proxy.Listener.Addr().String())
	// step: we need to update the client configs
	if proxy.Client, proxy.Idp, proxy.IdpClient, err = proxy.NewOpenIDClient(); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return &FakeProxy{c, auth, proxy, make(map[string]*http.Cookie)}
}

func (f *FakeProxy) getServiceURL() string {
	return fmt.Sprintf("http://%s", f.Proxy.Listener.Addr().String())
}

// RunTests performs a series of requests against a fake proxy service
func (f *FakeProxy) RunTests(t *testing.T, requests []FakeRequest) {
	defer func() {
		f.Idp.Close()
		f.Proxy.Server.Close()
	}()

	for i := range requests {
		c := requests[i]
		var upstream FakeUpstreamResponse

		f.config.NoRedirects = !c.Redirects
		// we need to set any defaults
		if c.Method == "" {
			c.Method = http.MethodGet
		}
		// create a http client
		client := resty.New()
		request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		if c.ProxyProtocol != "" {
			client.SetTransport(&http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						return nil, err
					}
					header := fmt.Sprintf("PROXY TCP4 %s 10.0.0.1 1000 2000\r\n", c.ProxyProtocol)
					_, _ = conn.Write([]byte(header))

					return conn, nil
				},
			})
		}

		// are we performing a oauth login beforehand
		if c.HasLogin {
			if err := f.PerformUserLogin(c.URI); err != nil {
				t.Errorf("case %d, unable to login to oauth server, error: %s", i, err)
				return
			}
		}
		if len(f.cookies) > 0 {
			for _, k := range f.cookies {
				client.SetCookie(k)
			}
		}
		if c.ExpectedProxy {
			request.SetResult(&upstream)
		}
		if c.ProxyRequest {
			client.SetProxy(f.getServiceURL())
		}
		if c.BasicAuth {
			request.SetBasicAuth(c.Username, c.Password)
		}
		if c.RawToken != "" {
			setRequestAuthentication(f.config, client, request, &c, c.RawToken)
		}
		if len(c.Cookies) > 0 {
			client.SetCookies(c.Cookies)
		}
		if len(c.Headers) > 0 {
			request.SetHeaders(c.Headers)
		}
		if c.FormValues != nil {
			request.SetFormData(c.FormValues)
		}
		if c.HasToken {
			token := NewTestToken(f.Idp.GetLocation())
			if c.TokenClaims != nil && len(c.TokenClaims) > 0 {
				token.Merge(c.TokenClaims)
			}
			if len(c.Roles) > 0 {
				token.AddRealmRoles(c.Roles)
			}
			if len(c.Groups) > 0 {
				token.AddGroups(c.Groups)
			}
			if c.Expires > 0 || c.Expires < 0 {
				token.SetExpiration(time.Now().Add(c.Expires))
			}
			if c.NotSigned {
				authToken := token.GetToken()
				setRequestAuthentication(f.config, client, request, &c, authToken.Encode())
			} else {
				signed, _ := f.Idp.SignToken(token.Claims)
				setRequestAuthentication(f.config, client, request, &c, signed.Encode())
			}
		}

		// step: execute the request
		var resp *resty.Response
		var err error
		switch c.URL {
		case "":
			resp, err = request.Execute(c.Method, f.getServiceURL()+c.URI)
		default:
			resp, err = request.Execute(c.Method, c.URL)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "auto redirect is disabled") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}
		status := resp.StatusCode()
		if c.ExpectedCode != 0 {
			assert.Equal(t, c.ExpectedCode, status, "case %d, expected status code: %d, got: %d", i, c.ExpectedCode, status)
		}
		if c.ExpectedLocation != "" {
			l, _ := url.Parse(resp.Header().Get("Location"))
			assert.True(t, strings.Contains(l.String(), c.ExpectedLocation), "expected location to contain %s", l.String())
			if l.Query().Get("state") != "" {
				state, err := uuid.FromString(l.Query().Get("state"))
				if err != nil {
					assert.Fail(t, "expected state parameter with valid UUID, got: %s with error %s", state.String(), err)
				}
			}
		}
		if len(c.ExpectedHeaders) > 0 {
			for k, v := range c.ExpectedHeaders {
				e := resp.Header().Get(k)
				assert.Equal(t, v, e, "case %d, expected header %s=%s, got: %s", i, k, v, e)
			}
		}
		if c.ExpectedProxy {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted), "case %d, did not proxy request", i)
		} else {
			assert.Empty(t, resp.Header().Get(testProxyAccepted), "case %d, should NOT proxy request", i)
		}
		if c.ExpectedProxyHeaders != nil && len(c.ExpectedProxyHeaders) > 0 {
			for k, v := range c.ExpectedProxyHeaders {
				headers := upstream.Headers
				switch v {
				case "":
					assert.NotEmpty(t, headers.Get(k), "case %d, expected the proxy header: %s to exist", i, k)
				default:
					assert.Equal(t, v, headers.Get(k), "case %d, expected proxy header %s=%s, got: %s", i, k, v, headers.Get(k))
				}
			}
		}
		if len(c.ExpectedNoProxyHeaders) > 0 {
			for _, k := range c.ExpectedNoProxyHeaders {
				assert.Empty(t, upstream.Headers.Get(k), "case %d, header: %s was not expected to exist", i, k)
			}
		}

		if c.ExpectedContent != "" {
			e := string(resp.Body())
			assert.Equal(t, c.ExpectedContent, e, "case %d, expected content: %s, got: %s", i, c.ExpectedContent, e)
		}
		if c.ExpectedContentContains != "" {
			e := string(resp.Body())
			assert.Contains(t, e, c.ExpectedContentContains, "case %d, expected content: %s, got: %s", i, c.ExpectedContentContains, e)
		}
		if len(c.ExpectedCookies) > 0 {
			for k, v := range c.ExpectedCookies {
				cookie := util.FindCookie(k, resp.Cookies())
				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}
				if v != "" {
					assert.Equal(t, cookie.Value, v, "case %d, expected cookie value: %s, got: %s", i, v, cookie.Value)
				}
			}
			for k, v := range c.ExpectedCookiesValidator {
				cookie := util.FindCookie(k, resp.Cookies())
				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}
				if v != nil {
					assert.True(t, v(cookie.Value), "case %d, invalid cookie value: %s", i, cookie.Value)
				}
			}
		}
		if c.OnResponse != nil {
			c.OnResponse(i, request, resp)
		}
	}
}

func (f *FakeProxy) PerformUserLogin(uri string) error {
	resp, err := MakeTestCodeFlowLogin(f.getServiceURL() + uri)
	if err != nil {
		return err
	}
	for _, c := range resp.Cookies() {
		if c.Name == f.config.CookieAccessName || c.Name == f.config.CookieRefreshName {
			f.cookies[c.Name] = &http.Cookie{
				Name:   c.Name,
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  c.Value,
			}
		}
	}
	defer resp.Body.Close()

	return nil
}

func setRequestAuthentication(cfg *config.Config, client *resty.Client, request *resty.Request, c *FakeRequest, token string) {
	switch c.HasCookieToken {
	case true:
		client.SetCookie(&http.Cookie{
			Name:  cfg.CookieAccessName,
			Path:  "/",
			Value: token,
		})
	default:
		request.SetAuthToken(token)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	cfg := NewFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	requests := []FakeRequest{
		{
			URI:                     cfg.WithOAuthURI(common.MetricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
		},
		{
			URI: cfg.WithOAuthURI(common.MetricsURL),
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
	}
	NewFakeProxy(cfg).RunTests(t, requests)
}

func MakeTestCodeFlowLogin(location string) (*http.Response, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}
		// step: make the request
		resp, err = http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTemporaryRedirect {
			return nil, errors.New("no redirection found in resp")
		}
		location = resp.Header.Get("Location")
		if !strings.HasPrefix(location, "http") {
			location = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
		}
	}
	return resp, nil
}
