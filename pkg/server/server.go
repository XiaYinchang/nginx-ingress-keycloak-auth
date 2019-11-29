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
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	httplog "log"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/config"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/store"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/util"
	proxyproto "github.com/armon/go-proxyproto"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/elazarl/goproxy"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

type OauthProxy struct {
	Client         *oidc.Client
	config         *config.Config
	endpoint       *url.URL
	Idp            oidc.ProviderConfig
	IdpClient      *http.Client
	Listener       net.Listener
	Log            *zap.Logger
	metricsHandler http.Handler
	Router         http.Handler
	Server         *http.Server
	store          common.Storage
	templates      *template.Template
	Upstream       common.ReverseProxy
}

func init() {
	_, _ = time.LoadLocation("UTC")      // ensure all time is in UTC [NOTE(fredbi): no this does just nothing]
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
	prometheus.MustRegister(common.CertificateRotationMetric)
	prometheus.MustRegister(common.LatencyMetric)
	prometheus.MustRegister(common.OauthLatencyMetric)
	prometheus.MustRegister(common.OauthTokensMetric)
	prometheus.MustRegister(common.StatusMetric)
}

// NewProxy create's a new proxy from configuration
func NewProxy(config *config.Config) (*OauthProxy, error) {
	// create the service logger
	Log, err := createLogger(config)
	if err != nil {
		return nil, err
	}

	Log.Info("starting the service", zap.String("prog", common.Prog), zap.String("author", common.Author), zap.String("version", common.Version))
	svc := &OauthProxy{
		config:         config,
		Log:            Log,
		metricsHandler: promhttp.Handler(),
	}

	// parse the upstream endpoint
	if svc.endpoint, err = url.Parse(config.Upstream); err != nil {
		return nil, err
	}

	// initialize the store if any
	if config.StoreURL != "" {
		if svc.store, err = store.CreateStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// initialize the openid client
	if !config.SkipTokenVerification {
		if svc.Client, svc.Idp, svc.IdpClient, err = svc.NewOpenIDClient(); err != nil {
			return nil, err
		}
	} else {
		Log.Warn("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		Log.Warn("client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	// are we running in forwarding mode?
	if config.EnableForwarding {
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// createLogger is responsible for creating the service logger
func createLogger(config *config.Config) (*zap.Logger, error) {
	httplog.SetOutput(ioutil.Discard) // disable the http logger
	if config.DisableAllLogging {
		return zap.NewNop(), nil
	}

	c := zap.NewProductionConfig()
	c.DisableStacktrace = true
	c.DisableCaller = true
	// are we enabling json logging?
	if !config.EnableJSONLogging {
		c.Encoding = "console"
	}
	// are we running verbose mode?
	if config.Verbose {
		httplog.SetOutput(os.Stderr)
		c.DisableCaller = false
		c.Development = true
		c.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	return c.Build()
}

// createReverseProxy creates a reverse proxy
func (r *OauthProxy) createReverseProxy() error {
	r.Log.Info("enabled reverse proxy mode, upstream url", zap.String("url", r.config.Upstream))
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}
	engine := chi.NewRouter()
	engine.MethodNotAllowed(EmptyHandler)
	engine.NotFound(EmptyHandler)
	engine.Use(middleware.Recoverer)
	// @check if the request tracking id middleware is enabled
	if r.config.EnableRequestID {
		r.Log.Info("enabled the correlation request id middlware")
		engine.Use(r.requestIDMiddleware(r.config.RequestIDHeader))
	}
	// @step: enable the entrypoint middleware
	engine.Use(EntrypointMiddleware)

	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}

	if len(r.config.CorsOrigins) > 0 {
		c := cors.New(cors.Options{
			AllowedOrigins:   r.config.CorsOrigins,
			AllowedMethods:   r.config.CorsMethods,
			AllowedHeaders:   r.config.CorsHeaders,
			AllowCredentials: r.config.CorsCredentials,
			ExposedHeaders:   r.config.CorsExposedHeaders,
			MaxAge:           int(r.config.CorsMaxAge.Seconds()),
			Debug:            r.config.Verbose,
		})
		engine.Use(c.Handler)
	}

	engine.Use(r.proxyMiddleware)
	r.Router = engine

	if len(r.config.ResponseHeaders) > 0 {
		engine.Use(r.responseHeaderMiddleware(r.config.ResponseHeaders))
	}

	// step: add the routing for oauth
	engine.With(proxyDenyMiddleware).Route(r.config.BaseURI+r.config.OAuthURI, func(e chi.Router) {
		e.MethodNotAllowed(methodNotAllowHandlder)
		e.HandleFunc(common.AuthorizationURL, r.oauthAuthorizationHandler)
		e.Get(common.CallbackURL, r.oauthCallbackHandler)
		e.Get(common.ExpiredURL, r.expirationHandler)
		e.Get(common.HealthURL, r.healthHandler)
		e.With(r.authenticationMiddleware()).Get(common.LogoutURL, r.logoutHandler)
		e.With(r.authenticationMiddleware()).Get(common.TokenURL, r.tokenHandler)
		e.Post(common.LoginURL, r.loginHandler)
		if r.config.EnableMetrics {
			r.Log.Info("enabled the service metrics middleware", zap.String("path", r.config.WithOAuthURI(common.MetricsURL)))
			e.Get(common.MetricsURL, r.proxyMetricsHandler)
		}
	})

	if r.config.EnableProfiling {
		engine.With(proxyDenyMiddleware).Route(common.DebugURL, func(e chi.Router) {
			r.Log.Warn("enabling the debug profiling on /debug/pprof")
			e.Get("/{name}", r.debugHandler)
			e.Post("/{name}", r.debugHandler)
		})
		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.Log.Warn("you must disable the server write timeout (--server-write-timeout) when using pprof profiling")
		}
	}

	if r.config.EnableSessionCookies {
		r.Log.Info("using session cookies only for access and refresh tokens")
	}

	// step: load the templates if any
	if err := r.createTemplates(); err != nil {
		return err
	}
	// step: provision in the protected resources
	enableDefaultDeny := r.config.EnableDefaultDeny
	for _, x := range r.config.Resources {
		if x.URL[len(x.URL)-1:] == "/" {
			r.Log.Warn("the resource url is not a prefix",
				zap.String("resource", x.URL),
				zap.String("change", x.URL),
				zap.String("amended", strings.TrimRight(x.URL, "/")))
		}
		if x.URL == "/*" && r.config.EnableDefaultDeny {
			switch x.WhiteListed {
			case true:
				return errors.New("you've asked for a default denial but whitelisted everything")
			default:
				enableDefaultDeny = false
			}
		}
	}

	if enableDefaultDeny {
		r.Log.Info("adding a default denial into the protected resources")
		r.config.Resources = append(r.config.Resources, &resource.Resource{URL: "/*", Methods: common.AllHTTPMethods})
	}

	for _, x := range r.config.Resources {
		r.Log.Info("protecting resource", zap.String("resource", x.String()))
		e := engine.With(
			r.authenticationMiddleware(),
			r.admissionMiddleware(x),
			r.identityHeadersMiddleware(r.config.AddClaims))

		for _, m := range x.Methods {
			if !x.WhiteListed {
				e.MethodFunc(m, x.URL, EmptyHandler)
				continue
			}
			engine.MethodFunc(m, x.URL, EmptyHandler)
		}
	}

	for name, value := range r.config.MatchClaims {
		r.Log.Info("token must contain", zap.String("claim", name), zap.String("value", value))
	}
	if r.config.RedirectionURL == "" {
		r.Log.Warn("no redirection url has been set, will use host headers")
	}
	if r.config.EnableEncryptedToken {
		r.Log.Info("session access tokens will be encrypted")
	}

	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *OauthProxy) createForwardingProxy() error {
	r.Log.Info("enabling forward signing mode, listening on", zap.String("interface", r.config.Listen))

	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}
	//nolint:bodyclose
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy := r.Upstream.(*goproxy.ProxyHttpServer)
	r.Router = proxy

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start := ctx.UserData.(time.Time)
			latency := time.Since(start)
			common.LatencyMetric.Observe(latency.Seconds())
			r.Log.Info("client request",
				zap.String("method", resp.Request.Method),
				zap.String("path", resp.Request.URL.Path),
				zap.Int("status", resp.StatusCode),
				zap.Int64("bytes", resp.ContentLength),
				zap.String("host", resp.Request.Host),
				zap.String("path", resp.Request.URL.Path),
				zap.String("latency", latency.String()))
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// Run starts the proxy service
func (r *OauthProxy) Run() error {
	listener, err := r.createHTTPListener(listenerConfig{
		hostnames:           r.config.Hostnames,
		listen:              r.config.Listen,
		proxyProtocol:       r.config.EnableProxyProtocol,
		redirectionURL:      r.config.RedirectionURL,
		useFileTLS:          false,
		useLetsEncryptTLS:   false,
		useSelfSignedTLS:    false,
	})

	if err != nil {
		return err
	}
	// step: create the http server
	server := &http.Server{
		Addr:         r.config.Listen,
		Handler:      r.Router,
		ReadTimeout:  r.config.ServerReadTimeout,
		WriteTimeout: r.config.ServerWriteTimeout,
		IdleTimeout:  r.config.ServerIdleTimeout,
	}
	r.Server = server
	r.Listener = listener

	go func() {
		r.Log.Info("keycloak proxy service starting", zap.String("interface", r.config.Listen))
		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.Log.Fatal("failed to start the http service", zap.Error(err))
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.Log.Info("keycloak proxy http service starting", zap.String("interface", r.config.ListenHTTP))
		httpListener, err := r.createHTTPListener(listenerConfig{
			listen:        r.config.ListenHTTP,
			proxyProtocol: r.config.EnableProxyProtocol,
		})
		if err != nil {
			return err
		}
		httpsvc := &http.Server{
			Addr:         r.config.ListenHTTP,
			Handler:      r.Router,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}
		go func() {
			if err := httpsvc.Serve(httpListener); err != nil {
				r.Log.Fatal("failed to start the http redirect service", zap.Error(err))
			}
		}()
	}

	return nil
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCert          string   // the path to a client certificate to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useFileTLS          bool     // indicates we are using certificates from files
	useLetsEncryptTLS   bool     // indicates we are using letsencrypt
	useSelfSignedTLS    bool     // indicates we are using the self-signed tls
}

// ErrHostNotConfigured indicates the hostname was not configured
var ErrHostNotConfigured = errors.New("acme/autocert: host not configured")

// createHTTPListener is responsible for creating a listening socket
func (r *OauthProxy) createHTTPListener(config listenerConfig) (net.Listener, error) {
	var listener net.Listener
	var err error

	// are we create a unix socket or tcp listener?
	if strings.HasPrefix(config.listen, "unix://") {
		socket := config.listen[7:]
		if exists := util.FileExists(socket); exists {
			if err = os.Remove(socket); err != nil {
				return nil, err
			}
		}
		r.Log.Info("listening on unix socket", zap.String("interface", config.listen))
		if listener, err = net.Listen("unix", socket); err != nil {
			return nil, err
		}
	} else { //nolint:gocritic
		if listener, err = net.Listen("tcp", config.listen); err != nil {
			return nil, err
		}
	}

	// does it require proxy protocol?
	if config.proxyProtocol {
		r.Log.Info("enabling the proxy protocol on listener", zap.String("interface", config.listen))
		listener = &proxyproto.Listener{Listener: listener}
	}

	return listener, nil
}

// createUpstreamProxy create a reverse http proxy from the upstream
func (r *OauthProxy) createUpstreamProxy(upstream *url.URL) error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		r.Log.Info("using unix socket for upstream", zap.String("socket", fmt.Sprintf("%s%s", upstream.Host, upstream.Path)))

		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = common.UnsecureScheme
	}
	// create the upstream tls configure
	//nolint:gas
	tlsConfig := &tls.Config{InsecureSkipVerify: true}


	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()

	// headers formed by middleware before proxying to upstream shall be
	// kept in response. This is true for CORS headers ([KEYCOAK-9045])
	// and for refreshed cookies (htts://github.com/keycloak/keycloak-gatekeeper/pulls/456])
	proxy.KeepDestinationHeaders = true
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	r.Upstream = proxy

	// update the tls configuration of the reverse proxy
	r.Upstream.(*goproxy.ProxyHttpServer).Tr = &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
		MaxIdleConns:          r.config.MaxIdleConns,
		MaxIdleConnsPerHost:   r.config.MaxIdleConnsPerHost,
	}

	return nil
}

// createTemplates loads the custom template
func (r *OauthProxy) createTemplates() error {
	var list []string

	if r.config.SignInPage != "" {
		r.Log.Debug("loading the custom sign in page", zap.String("page", r.config.SignInPage))
		list = append(list, r.config.SignInPage)
	}

	if r.config.ForbiddenPage != "" {
		r.Log.Debug("loading the custom sign forbidden page", zap.String("page", r.config.ForbiddenPage))
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		r.Log.Info("loading the custom templates", zap.String("templates", strings.Join(list, ",")))
		r.templates = template.Must(template.ParseFiles(list...))
	}

	return nil
}

// NewOpenIDClient initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func (r *OauthProxy) NewOpenIDClient() (*oidc.Client, oidc.ProviderConfig, *http.Client, error) {
	var err error
	var config oidc.ProviderConfig

	// step: fix up the url if required, the underlining lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration") {
		r.config.DiscoveryURL = strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration")
	}

	// step: create a idp http client
	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				if r.config.OpenIDProviderProxy != "" {
					idpProxyURL, erp := url.Parse(r.config.OpenIDProviderProxy)
					if erp != nil {
						r.Log.Warn("invalid proxy address for open IDP provider proxy", zap.Error(erp))
						return nil, nil
					}
					return idpProxyURL, nil
				}

				return nil, nil
			},
			TLSClientConfig: &tls.Config{
				//nolint:gas
				InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
			},
		},
		Timeout: time.Second * 10,
	}

	// step: attempt to retrieve the provider configuration
	completeCh := make(chan bool)
	go func() {
		for {
			r.Log.Info("attempting to retrieve configuration discovery url",
				zap.String("url", r.config.DiscoveryURL),
				zap.String("timeout", r.config.OpenIDProviderTimeout.String()))
			if config, err = oidc.FetchProviderConfig(hc, r.config.DiscoveryURL); err == nil {
				break // break and complete
			}
			r.Log.Warn("failed to get provider configuration from discovery", zap.Error(err))
			time.Sleep(time.Second * 3)
		}
		completeCh <- true
	}()
	// wait for timeout or successful retrieval
	select {
	case <-time.After(r.config.OpenIDProviderTimeout):
		return nil, config, nil, errors.New("failed to retrieve the provider configuration from discovery url")
	case <-completeCh:
		r.Log.Info("successfully retrieved openid configuration from the discovery")
	}

	client, err := oidc.NewClient(oidc.ClientConfig{
		Credentials: oidc.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		HTTPClient:     hc,
		RedirectURL:    fmt.Sprintf("%s/oauth/callback", r.config.RedirectionURL),
		ProviderConfig: config,
		Scope:          append(r.config.Scopes, oidc.DefaultScope...),
	})
	if err != nil {
		return nil, config, hc, err
	}
	// start the provider sync for key rotation
	client.SyncProviderConfig(r.config.DiscoveryURL)

	return client, config, hc, nil
}

// Render implements the echo Render interface
func (r *OauthProxy) Render(w io.Writer, name string, data interface{}) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

// store

// useStore checks if we are using a store to hold the refresh tokens
func (r *OauthProxy) useStore() bool {
	return r.store != nil
}

// StoreRefreshToken the token to the store
func (r *OauthProxy) StoreRefreshToken(token jose.JWT, value string) error {
	return r.store.Set(util.GetHashKey(&token), value)
}

// Get retrieves a token from the store, the key we are using here is the access token
func (r *OauthProxy) GetRefreshToken(token jose.JWT) (string, error) {
	// step: the key is the access token
	v, err := r.store.Get(util.GetHashKey(&token))
	if err != nil {
		return v, err
	}
	if v == "" {
		return v, common.ErrNoSessionStateFound
	}

	return v, nil
}

// DeleteRefreshToken removes a key from the store
func (r *OauthProxy) DeleteRefreshToken(token jose.JWT) error {
	if err := r.store.Delete(util.GetHashKey(&token)); err != nil {
		r.Log.Error("unable to delete token", zap.Error(err))

		return err
	}

	return nil
}

// Close is used to close off any resources
func (r *OauthProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
}
