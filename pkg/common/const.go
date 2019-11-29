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

package common

const (
	Prog        = "keycloak-gatekeeper"
	Author      = "Keycloak"
	Email       = "keycloak-user@lists.jboss.org"
	Description = "is a proxy using the keycloak service for auth and authorization"

	AuthorizationHeader = "Authorization"
	EnvPrefix           = "PROXY_"
	HeaderUpgrade       = "Upgrade"
	VersionHeader       = "X-Auth-Proxy-Version"

	AuthorizationURL = "/authorize"
	CallbackURL      = "/callback"
	ExpiredURL       = "/expired"
	HealthURL        = "/health"
	LoginURL         = "/login"
	LogoutURL        = "/logout"
	MetricsURL       = "/metrics"
	TokenURL         = "/token"
	DebugURL         = "/debug/pprof"

	ClaimAudience       = "aud"
	ClaimPreferredName  = "preferred_username"
	ClaimRealmAccess    = "realm_access"
	ClaimResourceAccess = "resource_access"
	ClaimResourceRoles  = "roles"
	ClaimGroups         = "groups"

	AccessCookie       = "kc-access"
	RefreshCookie      = "kc-state"
	RequestURICookie   = "request_uri"
	RequestStateCookie = "OAuth_Token_Request_State"
	UnsecureScheme     = "http"
	SecureScheme       = "https"
	AnyMethod          = "ANY"
	AuthMethodBasic    = "secret-basic"
	AuthMethodBody     = "secret-body"

	_ contextKey = iota
	ContextScopeName
)

const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
)

const (
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"
)
