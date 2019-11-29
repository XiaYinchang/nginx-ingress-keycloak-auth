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

package usercontext

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/testfake"
)

func TestIsAudience(t *testing.T) {
	user := &UserContext{
		Audiences: []string{"test", "test2"},
	}
	if !user.IsAudience("test") {
		t.Error("return should not have been false")
	}
	if user.IsAudience("test1") {
		t.Error("return should not have been true")
	}
	if !user.IsAudience("test2") {
		t.Error("return should not have been false")
	}
}

func TestGetUserRoles(t *testing.T) {
	user := &UserContext{
		Roles: []string{"1", "2", "3"},
	}
	if user.GetRoles() != "1,2,3" {
		t.Error("we should have received a true resposne")
	}
	if user.GetRoles() == "nothing" {
		t.Error("we should have received a false response")
	}
}

func TestIsExpired(t *testing.T) {
	user := &UserContext{
		ExpiresAt: time.Now(),
	}
	if !user.IsExpired() {
		t.Error("we should have been false")
	}
}

func TestIsBearerToken(t *testing.T) {
	user := &UserContext{
		BearerToken: true,
	}
	assert.True(t, user.IsBearer())
	assert.False(t, user.IsCookie())
}

func TestIsCookie(t *testing.T) {
	user := &UserContext{
		BearerToken: false,
	}
	assert.False(t, user.IsBearer())
	assert.True(t, user.IsCookie())
}

func TestGetUserContext(t *testing.T) {
	realmRoles := []string{"realm:realm"}
	clientRoles := []string{"client:client"}
	token := testfake.NewTestToken("test")
	token.AddRealmRoles(realmRoles)
	token.AddClientRoles("client", []string{"client"})
	context, err := ExtractIdentity(token.GetToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.Equal(t, "1e11e539-8256-4b3b-bda8-cc0d56cddb48", context.ID)
	assert.Equal(t, "gambol99@gmail.com", context.Email)
	assert.Equal(t, "rjayawardene", context.preferredName)
	assert.Equal(t, append(realmRoles, clientRoles...), context.Roles)
}

func TestGetUserRealmRoleContext(t *testing.T) {
	roles := []string{"dsp-dev-vpn", "vpn-user", "dsp-prod-vpn", "openvpn:dev-vpn"}
	token := testfake.NewTestToken("test")
	token.AddRealmRoles(roles)
	context, err := ExtractIdentity(token.GetToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.Equal(t, "1e11e539-8256-4b3b-bda8-cc0d56cddb48", context.ID)
	assert.Equal(t, "gambol99@gmail.com", context.Email)
	assert.Equal(t, "rjayawardene", context.preferredName)
	assert.Equal(t, roles, context.Roles)
}

func TestUserContextString(t *testing.T) {
	token := testfake.NewTestToken("test")
	context, err := ExtractIdentity(token.GetToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.NotEmpty(t, context.String())
}
