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
	"strings"
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/usercontext"
	"github.com/coreos/go-oidc/jose"
	"go.uber.org/zap"
)

// filterCookies is responsible for censoring any cookies we don't want sent
func filterCookies(req *http.Request, filter []string) error {
	// @NOTE: there doesn't appear to be a way of removing a cookie from the http.Request as
	// AddCookie() just append
	cookies := req.Cookies()
	// @step: empty the current cookies
	req.Header.Set("Cookie", "")
	// @step: iterate the cookies and filter out anything we
	for _, x := range cookies {
		var found bool
		// @step: does this cookie match our filter?
		for _, n := range filter {
			if strings.HasPrefix(x.Name, n) {
				req.AddCookie(&http.Cookie{Name: x.Name, Value: "censored"})
				found = true
				break
			}
		}
		if !found {
			req.AddCookie(x)
		}
	}

	return nil
}

// revokeProxy is responsible to stopping the middleware from proxying the request
func (r *OauthProxy) revokeProxy(w http.ResponseWriter, req *http.Request) context.Context {
	var scope *usercontext.RequestScope
	sc := req.Context().Value(common.ContextScopeName)
	switch sc {
	case nil:
		scope = &usercontext.RequestScope{AccessDenied: true}
	default:
		scope = sc.(*usercontext.RequestScope)
	}
	scope.AccessDenied = true

	return context.WithValue(req.Context(), common.ContextScopeName, scope)
}

// accessForbidden redirects the user to the forbidden page
func (r *OauthProxy) accessForbidden(w http.ResponseWriter, req *http.Request) context.Context {
	w.WriteHeader(http.StatusForbidden)
	return r.revokeProxy(w, req)
}

// redirectToURL redirects the user and aborts the context
func (r *OauthProxy) redirectToURL(url string, w http.ResponseWriter, req *http.Request, statusCode int) context.Context {
	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	http.Redirect(w, req, url, statusCode)

	return r.revokeProxy(w, req)
}

// redirectToAuthorization redirects the user to authorization handler
func (r *OauthProxy) redirectToAuthorization(w http.ResponseWriter, req *http.Request) context.Context {
	if r.config.NoRedirects {
		w.WriteHeader(http.StatusUnauthorized)
		return r.revokeProxy(w, req)
	}

	// step: add a state referrer to the authorization page
	uuid := r.writeStateParameterCookie(req, w)
	authQuery := fmt.Sprintf("?state=%s", uuid)

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		r.Log.Error("refusing to redirection to authorization endpoint, skip token verification switched on")
		w.WriteHeader(http.StatusForbidden)
		return r.revokeProxy(w, req)
	}
	if r.config.InvalidAuthRedirectsWith303 {
		r.redirectToURL(r.config.WithOAuthURI(common.AuthorizationURL+authQuery), w, req, http.StatusSeeOther)
	} else {
		r.redirectToURL(r.config.WithOAuthURI(common.AuthorizationURL+authQuery), w, req, http.StatusTemporaryRedirect)
	}

	return r.revokeProxy(w, req)
}

// getAccessCookieExpiration calculates the expiration of the access token cookie
func (r *OauthProxy) getAccessCookieExpiration(token jose.JWT, refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := r.config.AccessTokenDuration
	if _, ident, err := parseToken(refresh); err == nil {
		delta := time.Until(ident.ExpiresAt)
		if delta > 0 {
			duration = delta
		}
		r.Log.Debug("parsed refresh token with new duration", zap.Duration("new duration", delta))
	} else {
		r.Log.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}
