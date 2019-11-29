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
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/resource"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/usercontext"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/util"
	"github.com/coreos/go-oidc/jose"
	"github.com/go-chi/chi/middleware"
	uuid "github.com/satori/go.uuid"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// normalizeFlags is the options to purell
	normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes
)

// EntrypointMiddleware is custom filtering for incoming requests
func EntrypointMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		keep := req.URL.Path
		purell.NormalizeURL(req.URL, normalizeFlags)

		// ensure we have a slash in the url
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}
		req.RequestURI = req.URL.RawPath
		req.URL.RawPath = req.URL.Path

		// @step: create a context for the request
		scope := &usercontext.RequestScope{}
		resp := middleware.NewWrapResponseWriter(w, 1)
		start := time.Now()
		next.ServeHTTP(resp, req.WithContext(context.WithValue(req.Context(), common.ContextScopeName, scope)))

		// @metric record the time taken then response code
		common.LatencyMetric.Observe(time.Since(start).Seconds())
		common.StatusMetric.WithLabelValues(fmt.Sprintf("%d", resp.Status()), req.Method).Inc()

		// place back the original uri for proxying request
		req.URL.Path = keep
		req.URL.RawPath = keep
		req.RequestURI = keep
	})
}

// requestIDMiddleware is responsible for adding a request id if none found
func (r *OauthProxy) requestIDMiddleware(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if v := req.Header.Get(header); v == "" {
				req.Header.Set(header, uuid.NewV1().String())
			}

			next.ServeHTTP(w, req)
		})
	}
}

// loggingMiddleware is a custom http logger
func (r *OauthProxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		resp := w.(middleware.WrapResponseWriter)
		next.ServeHTTP(resp, req)
		addr := req.RemoteAddr
		r.Log.Info("client request",
			zap.Duration("latency", time.Since(start)),
			zap.Int("status", resp.Status()),
			zap.Int("bytes", resp.BytesWritten()),
			zap.String("client_ip", addr),
			zap.String("method", req.Method),
			zap.String("path", req.URL.Path))
	})
}

// authenticationMiddleware is responsible for verifying the access token
func (r *OauthProxy) authenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			clientIP := req.RemoteAddr
			// grab the user identity from the request
			user, err := r.getIdentity(req)
			if err != nil {
				r.Log.Error("no session found in request, redirecting for authorization", zap.Error(err))
				next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
				return
			}
			// create the request scope
			scope := req.Context().Value(common.ContextScopeName).(*usercontext.RequestScope)
			scope.Identity = user
			ctx := context.WithValue(req.Context(), common.ContextScopeName, scope)

			// step: skip if we are running skip-token-verification
			if r.config.SkipTokenVerification {
				r.Log.Warn("skip token verification enabled, skipping verification - TESTING ONLY")
				if user.IsExpired() {
					r.Log.Error("the session has expired and verification switch off",
						zap.String("client_ip", clientIP),
						zap.String("username", user.Name),
						zap.String("expired_on", user.ExpiresAt.String()))

					next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
					return
				}
			} else { //nolint:gocritic
				if err := verifyToken(r.Client, user.Token); err != nil {
					// step: if the error post verification is anything other than a token
					// expired error we immediately throw an access forbidden - as there is
					// something messed up in the token
					if err != common.ErrAccessTokenExpired {
						r.Log.Error("access token failed verification",
							zap.String("client_ip", clientIP),
							zap.Error(err))

						next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
						return
					}

					// step: check if we are refreshing the access tokens and if not re-auth
					if !r.config.EnableRefreshTokens {
						r.Log.Error("session expired and access token refreshing is disabled",
							zap.String("client_ip", clientIP),
							zap.String("email", user.Name),
							zap.String("expired_on", user.ExpiresAt.String()))

						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
						return
					}

					r.Log.Info("accces token for user has expired, attemping to refresh the token",
						zap.String("client_ip", clientIP),
						zap.String("email", user.Email))

					// step: check if the user has refresh token
					refresh, encrypted, err := r.retrieveRefreshToken(req.WithContext(ctx), user)
					if err != nil {
						r.Log.Error("unable to find a refresh token for user",
							zap.String("client_ip", clientIP),
							zap.String("email", user.Email),
							zap.Error(err))

						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
						return
					}

					// attempt to refresh the access token, possibly with a renewed refresh token
					//
					// NOTE: atm, this does not retrieve explicit refresh token expiry from oauth2,
					// and take identity expiry instead: with keycloak, they are the same and equal to
					// "SSO session idle" keycloak setting.
					//
					// exp: expiration of the access token
					// expiresIn: expiration of the ID token
					token, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := getRefreshedToken(r.Client, refresh)
					if err != nil {
						switch err {
						case common.ErrRefreshTokenExpired:
							r.Log.Warn("refresh token has expired, cannot retrieve access token",
								zap.String("client_ip", clientIP),
								zap.String("email", user.Email))

							r.clearAllCookies(req.WithContext(ctx), w)
						default:
							r.Log.Error("failed to refresh the access token", zap.Error(err))
						}
						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))

						return
					}

					accessExpiresIn := time.Until(accessExpiresAt)

					// get the expiration of the new refresh token
					if newRefreshToken != "" {
						refresh = newRefreshToken
					}
					if refreshExpiresIn == 0 {
						// refresh token expiry claims not available: try to parse refresh token
						refreshExpiresIn = r.getAccessCookieExpiration(token, refresh)
					}

					r.Log.Info("injecting the refreshed access token cookie",
						zap.String("client_ip", clientIP),
						zap.String("cookie_name", r.config.CookieAccessName),
						zap.String("email", user.Email),
						zap.Duration("refresh_expires_in", refreshExpiresIn),
						zap.Duration("expires_in", accessExpiresIn))

					accessToken := token.Encode()
					if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
						if accessToken, err = util.EncodeText(accessToken, r.config.EncryptionKey); err != nil {
							r.Log.Error("unable to encode the access token", zap.Error(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
					// step: inject the refreshed access token
					r.dropAccessTokenCookie(req.WithContext(ctx), w, accessToken, accessExpiresIn)

					// step: inject the renewed refresh token
					if newRefreshToken != "" {
						r.Log.Debug("renew refresh cookie with new refresh token",
							zap.Duration("refresh_expires_in", refreshExpiresIn))
						encryptedRefreshToken, err := util.EncodeText(newRefreshToken, r.config.EncryptionKey)
						if err != nil {
							r.Log.Error("failed to encrypt the refresh token", zap.Error(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						r.dropRefreshTokenCookie(req.WithContext(ctx), w, encryptedRefreshToken, refreshExpiresIn)
					}

					if r.useStore() {
						go func(old, new jose.JWT, encrypted string) {
							if err := r.DeleteRefreshToken(old); err != nil {
								r.Log.Error("failed to remove old token", zap.Error(err))
							}
							if err := r.StoreRefreshToken(new, encrypted); err != nil {
								r.Log.Error("failed to store refresh token", zap.Error(err))
								return
							}
						}(user.Token, token, encrypted)
					}
					// update the with the new access token and inject into the context
					user.Token = token
					ctx = context.WithValue(req.Context(), common.ContextScopeName, scope)
				}
			}

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// checkClaim checks whether claim in userContext matches claimName, match. It can be String or Strings claim.
func (r *OauthProxy) checkClaim(user *usercontext.UserContext, claimName string, match *regexp.Regexp, resourceURL string) bool {
	errFields := []zapcore.Field{
		zap.String("claim", claimName),
		zap.String("access", "denied"),
		zap.String("email", user.Email),
		zap.String("resource", resourceURL),
	}

	if _, found := user.Claims[claimName]; !found {
		r.Log.Warn("the token does not have the claim", errFields...)
		return false
	}

	// Check string claim.
	valueStr, foundStr, errStr := user.Claims.StringClaim(claimName)
	// We have found string claim, so let's check whether it matches.
	if foundStr {
		if match.MatchString(valueStr) {
			return true
		}
		r.Log.Warn("claim requirement does not match claim in token", append(errFields,
			zap.String("issued", valueStr),
			zap.String("required", match.String()),
		)...)

		return false
	}

	// Check strings claim.
	valueStrs, foundStrs, errStrs := user.Claims.StringsClaim(claimName)
	// We have found strings claim, so let's check whether it matches.
	if foundStrs {
		for _, value := range valueStrs {
			if match.MatchString(value) {
				return true
			}
		}
		r.Log.Warn("claim requirement does not match any element claim group in token", append(errFields,
			zap.String("issued", fmt.Sprintf("%v", valueStrs)),
			zap.String("required", match.String()),
		)...)

		return false
	}

	// If this fails, the claim is probably float or int.
	if errStr != nil && errStrs != nil {
		r.Log.Error("unable to extract the claim from token (tried string and strings)", append(errFields,
			zap.Error(errStr),
			zap.Error(errStrs),
		)...)
		return false
	}

	r.Log.Warn("unexpected error", errFields...)
	return false
}

// admissionMiddleware is responsible checking the access token against the protected resource
func (r *OauthProxy) admissionMiddleware(resource *resource.Resource) func(http.Handler) http.Handler {
	claimMatches := make(map[string]*regexp.Regexp)
	for k, v := range r.config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope := req.Context().Value(common.ContextScopeName).(*usercontext.RequestScope)
			if scope.AccessDenied {
				next.ServeHTTP(w, req)
				return
			}
			user := scope.Identity

			// @step: we need to check the roles
			if !util.HasAccess(resource.Roles, user.Roles, !resource.RequireAnyRole) {
				r.Log.Warn("access denied, invalid roles",
					zap.String("access", "denied"),
					zap.String("email", user.Email),
					zap.String("resource", resource.URL),
					zap.String("roles", resource.GetRoles()))

				next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
				return
			}

			// @step: check if we have any groups, the groups are there
			if !util.HasAccess(resource.Groups, user.Groups, false) {
				r.Log.Warn("access denied, invalid groups",
					zap.String("access", "denied"),
					zap.String("email", user.Email),
					zap.String("resource", resource.URL),
					zap.String("groups", strings.Join(resource.Groups, ",")))

				next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
				return
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				if !r.checkClaim(user, claimName, match, resource.URL) {
					next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
					return
				}
			}

			r.Log.Debug("access permitted to resource",
				zap.String("access", "permitted"),
				zap.String("email", user.Email),
				zap.Duration("expires", time.Until(user.ExpiresAt)),
				zap.String("resource", resource.URL))

			next.ServeHTTP(w, req)
		})
	}
}

// responseHeaderMiddleware is responsible for adding response headers
func (r *OauthProxy) responseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// @step: inject any custom response headers
			for k, v := range headers {
				w.Header().Set(k, v)
			}

			next.ServeHTTP(w, req)
		})
	}
}

// identityHeadersMiddleware is responsible for add the authentication headers for the upstream
func (r *OauthProxy) identityHeadersMiddleware(custom []string) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)
	for _, x := range custom {
		customClaims[x] = fmt.Sprintf("X-Auth-%s", util.ToHeader(x))
	}

	cookieFilter := []string{r.config.CookieAccessName, r.config.CookieRefreshName}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			scope := req.Context().Value(common.ContextScopeName).(*usercontext.RequestScope)
			if scope.Identity != nil {
				user := scope.Identity
				req.Header.Set("X-Auth-Audience", strings.Join(user.Audiences, ","))
				req.Header.Set("X-Auth-Email", user.Email)
				req.Header.Set("X-Auth-ExpiresIn", user.ExpiresAt.String())
				req.Header.Set("X-Auth-Groups", strings.Join(user.Groups, ","))
				req.Header.Set("X-Auth-Roles", strings.Join(user.Roles, ","))
				req.Header.Set("X-Auth-Subject", user.ID)
				req.Header.Set("X-Auth-Userid", user.Name)
				req.Header.Set("X-Auth-Username", user.Name)

				// should we add the token header?
				if r.config.EnableTokenHeader {
					req.Header.Set("X-Auth-Token", user.Token.Encode())
				}
				// add the authorization header if requested
				if r.config.EnableAuthorizationHeader {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.Token.Encode()))
				}
				// are we filtering out the cookies
				if !r.config.EnableAuthorizationCookies {
					_ = filterCookies(req, cookieFilter)
				}
				// inject any custom claims
				for claim, header := range customClaims {
					if claim, found := user.Claims[claim]; found {
						req.Header.Set(header, fmt.Sprintf("%v", claim))
					}
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *OauthProxy) securityMiddleware(next http.Handler) http.Handler {
	r.Log.Info("enabling the security filter middleware")
	secure := secure.New(secure.Options{
		AllowedHosts:          r.config.Hostnames,
		BrowserXssFilter:      r.config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.config.EnableContentNoSniff,
		FrameDeny:             r.config.EnableFrameDeny,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		SSLRedirect:           r.config.EnableHTTPSRedirect,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := secure.Process(w, req); err != nil {
			r.Log.Warn("failed security middleware", zap.Error(err))
			next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
			return
		}

		next.ServeHTTP(w, req)
	})
}

// proxyDenyMiddleware just block everything
func proxyDenyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sc := req.Context().Value(common.ContextScopeName)
		var scope *usercontext.RequestScope
		if sc == nil {
			scope = &usercontext.RequestScope{}
		} else {
			scope = sc.(*usercontext.RequestScope)
		}
		scope.AccessDenied = true
		// update the request context
		ctx := context.WithValue(req.Context(), common.ContextScopeName, scope)

		next.ServeHTTP(w, req.WithContext(ctx))
	})
}
