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

package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"path/filepath"
	"encoding/json"
	"io/ioutil"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	yaml "gopkg.in/yaml.v2"
)

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen" usage:"the interface the service should be listening on" env:"LISTEN"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `json:"listen-http" yaml:"listen-http" usage:"interface we should be listening" env:"LISTEN_HTTP"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery-url" yaml:"discovery-url" usage:"discovery url to retrieve the openid configuration" env:"DISCOVERY_URL"`
	// ClientID is the client id
	ClientID string `json:"client-id" yaml:"client-id" usage:"client id used to authenticate to the oauth service" env:"CLIENT_ID"`
	// ClientSecret is the secret for AS
	ClientSecret string `json:"client-secret" yaml:"client-secret" usage:"client secret used to authenticate to the oauth service" env:"CLIENT_SECRET"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection-url" yaml:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header is absent" env:"REDIRECTION_URL"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `json:"revocation-url" yaml:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" env:"REVOCATION_URL"`
	// SkipOpenIDProviderTLSVerify skips the tls verification for openid provider communication
	SkipOpenIDProviderTLSVerify bool `json:"skip-openid-provider-tls-verify" yaml:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider"`
	// OpenIDProviderProxy proxy for openid provider communication
	OpenIDProviderProxy string `json:"openid-provider-proxy" yaml:"openid-provider-proxy" usage:"proxy for communication with the openid provider"`
	// OpenIDProviderTimeout is the timeout used to pulling the openid configuration from the provider
	OpenIDProviderTimeout time.Duration `json:"openid-provider-timeout" yaml:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration"`
	// BaseURI is prepended to all the generated URIs
	BaseURI string `json:"base-uri" yaml:"base-uri" usage:"common prefix for all URIs" env:"BASE_URI"`
	// OAuthURI is the uri for the oauth endpoints for the proxy
	OAuthURI string `json:"oauth-uri" yaml:"oauth-uri" usage:"the uri for proxy oauth endpoints" env:"OAUTH_URI"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes" usage:"list of scopes requested when authenticating the user"`
	// Resources is a list of protected resources
	Resources []*resource.Resource `json:"resources" yaml:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers" usage:"custom headers to the upstream request, key=value"`
	// PreserveHost preserves the host header of the proxied request in the upstream request
	PreserveHost bool `json:"preserve-host" yaml:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request"`
	// RequestIDHeader is the header name for request ids
	RequestIDHeader string `json:"request-id-header" yaml:"request-id-header" usage:"the http header name for request id" env:"REQUEST_ID_HEADER"`
	// ResponseHeader is a map of response headers to add to the response
	ResponseHeaders map[string]string `json:"response-headers" yaml:"response-headers" usage:"custom headers to added to the http response key=value"`

	// EnableRequestID indicates the proxy should add request id if none if found
	EnableRequestID bool `json:"enable-request-id" yaml:"enable-request-id" usage:"indicates we should add a request id if none found" env:"ENABLE_REQUEST_ID"`
	// EnableLogoutRedirect indicates we should redirect to the identity provider for logging out
	EnableLogoutRedirect bool `json:"enable-logout-redirect" yaml:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out"`
	// EnableDefaultDeny indicates we should deny by default all requests
	EnableDefaultDeny bool `json:"enable-default-deny" yaml:"enable-default-deny" usage:"enables a default denial on all requests, you have to explicitly say what is permitted (recommended)"`
	// EnableEncryptedToken indicates the access token should be encoded
	EnableEncryptedToken bool `json:"enable-encrypted-token" yaml:"enable-encrypted-token" usage:"enable encryption for the access tokens"`
	// ForceEncryptedCookie indicates that the access token in the cookie should be encoded, regardless what EnableEncryptedToken says. This way, gatekeeper may receive tokens in header in the clear, whereas tokens in cookies remain encrypted
	ForceEncryptedCookie bool `json:"force-encrypted-cookie" yaml:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies"`
	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `json:"enable-logging" yaml:"enable-logging" usage:"enable http logging of the requests"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `json:"enable-json-logging" yaml:"enable-json-logging" usage:"switch on json logging rather than text"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `json:"enable-forwarding" yaml:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter" usage:"enables the security filter handler" env:"ENABLE_SECURITY_FILTER"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" env:"ENABLE_REFRESH_TOKEN"`
	// EnableSessionCookies indicates the cookies, both token and refresh should not be persisted
	EnableSessionCookies bool `json:"enable-session-cookies" yaml:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `json:"enable-login-handler" yaml:"enable-login-handler" usage:"enables the handling of the refresh tokens" env:"ENABLE_LOGIN_HANDLER"`
	// EnableTokenHeader adds the JWT token to the upstream authentication headers
	EnableTokenHeader bool `json:"enable-token-header" yaml:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream"`
	// EnableAuthorizationHeader indicates we should pass the authorization header to the upstream endpoint
	EnableAuthorizationHeader bool `json:"enable-authorization-header" yaml:"enable-authorization-header" usage:"adds the authorization header to the proxy request" env:"ENABLE_AUTHORIZATION_HEADER"`
	// EnableAuthorizationCookies indicates we should pass the authorization cookies to the upstream endpoint
	EnableAuthorizationCookies bool `json:"enable-authorization-cookies" yaml:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" env:"ENABLE_AUTHORIZATION_COOKIES"`
	// EnableHTTPSRedirect indicate we should redirection http -> https
	EnableHTTPSRedirect bool `json:"enable-https-redirection" yaml:"enable-https-redirection" usage:"enable the http to https redirection on the http service"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `json:"enable-profiling" yaml:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc"`
	// EnableMetrics indicates if the metrics is enabled
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `json:"filter-browser-xss" yaml:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `json:"filter-content-nosniff" yaml:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `json:"filter-frame-deny" yaml:"filter-frame-deny" usage:"enable to the frame deny header"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `json:"content-security-policy" yaml:"content-security-policy" usage:"specify the content security policy"`
	// LocalhostMetrics indicated the metrics can only be consume via localhost
	LocalhostMetrics bool `json:"localhost-metrics" yaml:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1"`

	// AccessTokenDuration is default duration applied to the access token cookie
	AccessTokenDuration time.Duration `json:"access-token-duration" yaml:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens"`
	// ClientAuthMethod defines the method for authenticating the oauth client to the server
	ClientAuthMethod string `json:"client-auth-method" yaml:"client-auth-method" usage:"the auth method to use with oauth (secret-basic, secret-body)" env:"CLIENT_AUTH_METHOD"`
	// CookieDomain is a list of domains the cookie is available to
	CookieDomain string `json:"cookie-domain" yaml:"cookie-domain" usage:"domain the access cookie is available to, defaults host header"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `json:"cookie-access-name" yaml:"cookie-access-name" usage:"name of the cookie use to hold the access token"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `json:"cookie-refresh-name" yaml:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `json:"secure-cookie" yaml:"secure-cookie" usage:"enforces the cookie to be secure"`
	// HTTPOnlyCookie enforces the cookie as http only
	HTTPOnlyCookie bool `json:"http-only-cookie" yaml:"http-only-cookie" usage:"enforces the cookie is in http only mode"`
	// SameSiteCookie enforces cookies to be send only to same site requests.
	SameSiteCookie string `json:"same-site-cookie" yaml:"same-site-cookie" usage:"enforces cookies to be send only to same site requests according to the policy (can be Strict|Lax|None)"`

	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" yaml:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" yaml:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" yaml:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" yaml:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" yaml:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" yaml:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)"`
	// CorsCredentials set the credentials flag
	CorsCredentials bool `json:"cors-credentials" yaml:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `json:"cors-max-age" yaml:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)"`
	// Hostnames is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames" usage:"list of hostnames the service will respond to"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key" usage:"encryption key used to encryption the session state" env:"ENCRYPTION_KEY"`

	// InvalidAuthRedirectsWith303 will make requests with invalid auth headers redirect using HTTP 303 instead of HTTP 307.  See github.com/keycloak/keycloak-gatekeeper/issues/292 for context.
	InvalidAuthRedirectsWith303 bool `json:"invalid-auth-redirects-with-303" yaml:"invalid-auth-redirects-with-303" usage:"use HTTP 303 redirects instead of 307 for invalid auth tokens"`
	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them"`
	// SkipTokenVerification tells the service to skipp verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced"`
	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete
	UpstreamTimeout time.Duration `json:"upstream-timeout" yaml:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete"`
	// UpstreamKeepaliveTimeout is the upstream keepalive timeout
	UpstreamKeepaliveTimeout time.Duration `json:"upstream-keepalive-timeout" yaml:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection"`
	// UpstreamTLSHandshakeTimeout is the timeout for upstream to tls handshake
	UpstreamTLSHandshakeTimeout time.Duration `json:"upstream-tls-handshake-timeout" yaml:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream"`
	// UpstreamResponseHeaderTimeout is the timeout for upstream header response
	UpstreamResponseHeaderTimeout time.Duration `json:"upstream-response-header-timeout" yaml:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream"`
	// UpstreamExpectContinueTimeout is the timeout expect continue for upstream
	UpstreamExpectContinueTimeout time.Duration `json:"upstream-expect-continue-timeout" yaml:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream"`

	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose" usage:"switch on debug / verbose logging"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `json:"enabled-proxy-protocol" yaml:"enabled-proxy-protocol" usage:"enable proxy protocol"`

	// MaxIdleConns is the max idle connections to keep alive, ready for reuse
	MaxIdleConns int `json:"max-idle-connections" yaml:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse"`
	// MaxIdleConnsPerHost limits the number of idle connections maintained per host
	MaxIdleConnsPerHost int `json:"max-idle-connections-per-host" yaml:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host"`

	// ServerReadTimeout is the read timeout on the http server
	ServerReadTimeout time.Duration `json:"server-read-timeout" yaml:"server-read-timeout" usage:"the server read timeout on the http server"`
	// ServerWriteTimeout is the write timeout on the http server
	ServerWriteTimeout time.Duration `json:"server-write-timeout" yaml:"server-write-timeout" usage:"the server write timeout on the http server"`
	// ServerIdleTimeout is the idle timeout on the http server
	ServerIdleTimeout time.Duration `json:"server-idle-timeout" yaml:"server-idle-timeout" usage:"the server idle timeout on the http server"`

	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `json:"forwarding-username" yaml:"forwarding-username" usage:"username to use when logging into the openid provider" env:"FORWARDING_USERNAME"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `json:"forwarding-password" yaml:"forwarding-password" usage:"password to use when logging into the openid provider" env:"FORWARDING_PASSWORD"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" yaml:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned"`

	// DisableAllLogging indicates no logging at all
	DisableAllLogging bool `json:"disable-all-logging" yaml:"disable-all-logging" usage:"disables all logging to stdout and stderr"`
}

// NewDefaultConfig returns a initialized config
func NewDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(720) * time.Hour,
		ClientAuthMethod:              common.AuthMethodBasic,
		CookieAccessName:              common.AccessCookie,
		CookieRefreshName:             common.RefreshCookie,
		EnableAuthorizationCookies:    true,
		EnableAuthorizationHeader:     true,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
		HTTPOnlyCookie:                true,
		Headers:                       make(map[string]string),
		MatchClaims:                   make(map[string]string),
		MaxIdleConns:                  100,
		MaxIdleConnsPerHost:           50,
		OAuthURI:                      "/oauth",
		OpenIDProviderTimeout:         30 * time.Second,
		PreserveHost:                  false,
		RequestIDHeader:               "X-Request-ID",
		ResponseHeaders:               make(map[string]string),
		SameSiteCookie:                common.SameSiteLax,
		SecureCookie:                  true,
		ServerIdleTimeout:             120 * time.Second,
		ServerReadTimeout:             10 * time.Second,
		ServerWriteTimeout:            10 * time.Second,
		SkipOpenIDProviderTLSVerify:   false,
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: 10 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
	}
}

// WithOAuthURI returns the oauth uri
func (r *Config) WithOAuthURI(uri string) string {
	if r.BaseURI != "" {
		return fmt.Sprintf("%s/%s/%s", r.BaseURI, r.OAuthURI, uri)
	}

	return fmt.Sprintf("%s/%s", r.OAuthURI, uri)
}

// IsValid validates if the config is valid
func (r *Config) IsValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}
	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New("maxi-idle-connections-per-host must be a number > 0 and <= max-idle-connections")
	}
	if r.SameSiteCookie != "" && r.SameSiteCookie != common.SameSiteStrict && r.SameSiteCookie != common.SameSiteLax && r.SameSiteCookie != common.SameSiteNone {
		return errors.New("same-site-cookie must be one of Strict|Lax|None")
	}

	if r.EnableForwarding {
		if r.ClientID == "" {
			return errors.New("you have not specified the client id")
		}
		if r.DiscoveryURL == "" {
			return errors.New("you have not specified the discovery url")
		}
		if r.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}
		if r.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
	} else {

		// step: if the skip verification is off, we need the below
		if !r.SkipTokenVerification {
			if r.ClientID == "" {
				return errors.New("you have not specified the client id")
			}
			if r.DiscoveryURL == "" {
				return errors.New("you have not specified the discovery url")
			}
			if strings.HasSuffix(r.RedirectionURL, "/") {
				r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
			}
			if !r.EnableSecurityFilter {
				if r.EnableHTTPSRedirect {
					return errors.New("the security filter must be switch on for this feature: http-redirect")
				}
				if r.EnableBrowserXSSFilter {
					return errors.New("the security filter must be switch on for this feature: brower-xss-filter")
				}
				if r.EnableFrameDeny {
					return errors.New("the security filter must be switch on for this feature: frame-deny-filter")
				}
				if r.ContentSecurityPolicy != "" {
					return errors.New("the security filter must be switch on for this feature: content-security-policy")
				}
				if len(r.Hostnames) > 0 {
					return errors.New("the security filter must be switch on for this feature: hostnames")
				}
			}
			if (r.EnableEncryptedToken || r.ForceEncryptedCookie) && r.EncryptionKey == "" {
				return errors.New("you have not specified an encryption key for encoding the access token")
			}
			if r.EnableRefreshTokens && r.EncryptionKey == "" {
				return errors.New("you have not specified an encryption key for encoding the session state")
			}
			if r.EnableRefreshTokens && (len(r.EncryptionKey) != 16 && len(r.EncryptionKey) != 32) {
				return fmt.Errorf("the encryption key (%d) must be either 16 or 32 characters for AES-128/AES-256 selection", len(r.EncryptionKey))
			}
			if !r.NoRedirects && r.SecureCookie && r.RedirectionURL != "" && !strings.HasPrefix(r.RedirectionURL, "https") {
				return errors.New("the cookie is set to secure but your redirection url is non-tls")
			}
			if r.StoreURL != "" {
				if _, err := url.Parse(r.StoreURL); err != nil {
					return fmt.Errorf("the store url is invalid, error: %s", err)
				}
			}
			if r.ClientAuthMethod != common.AuthMethodBasic && r.ClientAuthMethod != common.AuthMethodBody {
				return fmt.Errorf("invalid client auth method %q (valid values: %s, %s)", r.ClientAuthMethod, common.AuthMethodBasic, common.AuthMethodBody)
			}
		}
		// check: ensure each of the resource are valid
		for _, resource := range r.Resources {
			if err := resource.Valid(); err != nil {
				return err
			}
		}
		// step: validate the claims are validate regex's
		for k, claim := range r.MatchClaims {
			if _, err := regexp.Compile(claim); err != nil {
				return fmt.Errorf("the claim matcher: %s for claim: %s is not a valid regex", claim, k)
			}
		}
	}

	return nil
}

// fileExists check if a file exists
func fileExists(filename string) bool {
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// ReadConfigFile reads and parses the configuration file
func ReadConfigFile(filename string, config *Config) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	return err
}
