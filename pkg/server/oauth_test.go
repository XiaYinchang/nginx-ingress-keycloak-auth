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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
)


func TestGetUserinfo(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := testfake.NewTestToken(idp.getLocation()).GetToken()
	client, _ := px.client.OAuthClient()
	claims, err := getUserinfo(client, px.idp.UserInfoEndpoint.String(), token.Encode())
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)
}

func TestTokenExpired(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := testfake.NewTestToken(idp.getLocation())
	cs := []struct {
		Expire time.Duration
		OK     bool
	}{
		{
			Expire: 1 * time.Hour,
			OK:     true,
		},
		{
			Expire: -5 * time.Hour,
		},
	}
	for i, x := range cs {
		token.SetExpiration(time.Now().Add(x.Expire))
		signed, err := idp.signToken(token.Claims)
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", i, err)
			continue
		}
		err = verifyToken(px.client, *signed)
		if x.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", i, x.OK, err)
		}
		if !x.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", i, x.OK)
		}
	}
}


