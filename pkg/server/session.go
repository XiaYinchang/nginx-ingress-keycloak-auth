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
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/usercontext"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/util"
	"github.com/coreos/go-oidc/jose"
	"go.uber.org/zap"
)

// getIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
func (r *OauthProxy) getIdentity(req *http.Request) (*usercontext.UserContext, error) {
	var isBearer bool
	// step: check for a bearer token or cookie with jwt token
	access, isBearer, err := getTokenInRequest(req, r.config.CookieAccessName)
	if err != nil {
		return nil, err
	}
	if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie && !isBearer {
		if access, err = util.DecodeText(access, r.config.EncryptionKey); err != nil {
			return nil, common.ErrDecryption
		}
	}
	token, err := jose.ParseJWT(access)
	if err != nil {
		return nil, err
	}
	user, err := usercontext.ExtractIdentity(token)
	if err != nil {
		return nil, err
	}
	user.BearerToken = isBearer

	r.Log.Debug("found the user identity",
		zap.String("id", user.ID),
		zap.String("name", user.Name),
		zap.String("email", user.Email),
		zap.String("roles", strings.Join(user.Roles, ",")),
		zap.String("groups", strings.Join(user.Groups, ",")))

	return user, nil
}

// getRefreshTokenFromCookie returns the refresh token from the cookie if any
func (r *OauthProxy) getRefreshTokenFromCookie(req *http.Request) (string, error) {
	token, err := getTokenInCookie(req, r.config.CookieRefreshName)
	if err != nil {
		return "", err
	}

	return token, nil
}

// getTokenInRequest returns the access token from the http request
func getTokenInRequest(req *http.Request, name string) (string, bool, error) {
	bearer := true
	// step: check for a token in the authorization header
	token, err := getTokenInBearer(req)
	if err != nil {
		if err != common.ErrSessionNotFound {
			return "", false, err
		}
		if token, err = getTokenInCookie(req, name); err != nil {
			return token, false, err
		}
		bearer = false
	}

	return token, bearer, nil
}

// getTokenInBearer retrieves a access token from the authorization header
func getTokenInBearer(req *http.Request) (string, error) {
	token := req.Header.Get(common.AuthorizationHeader)
	if token == "" {
		return "", common.ErrSessionNotFound
	}

	items := strings.Split(token, " ")
	if len(items) != 2 {
		return "", common.ErrInvalidSession
	}

	return items[1], nil
}

// getTokenInCookie retrieves the access token from the request cookies
func getTokenInCookie(req *http.Request, name string) (string, error) {
	var token bytes.Buffer

	if cookie := util.FindCookie(name, req.Cookies()); cookie != nil {
		token.WriteString(cookie.Value)
	}

	// add also divided cookies
	for i := 1; i < 600; i++ {
		cookie := util.FindCookie(name+"-"+strconv.Itoa(i), req.Cookies())
		if cookie == nil {
			break
		} else {
			token.WriteString(cookie.Value)
		}
	}

	if token.Len() == 0 {
		return "", common.ErrSessionNotFound
	}

	return token.String(), nil
}
