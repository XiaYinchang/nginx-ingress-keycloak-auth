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
	"fmt"
	"strings"
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
)

// UserContext holds the information extracted the token
type UserContext struct {
	// the id of the user
	ID string
	// the audience for the token
	Audiences []string
	// whether the context is from a session cookie or authorization header
	BearerToken bool
	// the claims associated to the token
	Claims jose.Claims
	// the email associated to the user
	Email string
	// the expiration of the access token
	ExpiresAt time.Time
	// groups is a collection of groups the user in in
	Groups []string
	// a name of the user
	Name string
	// preferredName is the name of the user
	preferredName string
	// roles is a collection of roles the users holds
	Roles []string
	// the access token itself
	Token jose.JWT
}

// RequestScope is a request level context scope passed between middleware
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied on
	AccessDenied bool
	// Identity is the user Identity of the request
	Identity *UserContext
}

// ExtractIdentity parse the jwt token and extracts the various elements is order to construct
func ExtractIdentity(token jose.JWT) (*UserContext, error) {
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName, found, err := claims.StringClaim(common.ClaimPreferredName)
	if err != nil || !found {
		preferredName = identity.Email
	}

	var audiences []string
	aud, found, err := claims.StringClaim(common.ClaimAudience)
	if err == nil && found {
		audiences = append(audiences, aud)
	} else {
		aud, found, erc := claims.StringsClaim(common.ClaimAudience)
		if erc != nil || !found {
			return nil, common.ErrNoTokenAudience
		}
		audiences = aud
	}

	// @step: extract the realm roles
	var roleList []string
	if realmRoles, found := claims[common.ClaimRealmAccess].(map[string]interface{}); found {
		if roles, found := realmRoles[common.ClaimResourceRoles]; found {
			for _, r := range roles.([]interface{}) {
				roleList = append(roleList, fmt.Sprintf("%s", r))
			}
		}
	}

	// @step: extract the client roles from the access token
	if accesses, found := claims[common.ClaimResourceAccess].(map[string]interface{}); found {
		for name, list := range accesses {
			scopes := list.(map[string]interface{})
			if roles, found := scopes[common.ClaimResourceRoles]; found {
				for _, r := range roles.([]interface{}) {
					roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
				}
			}
		}
	}

	// @step: extract any group information from the tokens
	groups, _, err := claims.StringsClaim(common.ClaimGroups)
	if err != nil {
		return nil, err
	}

	return &UserContext{
		Audiences:     audiences,
		Claims:        claims,
		Email:         identity.Email,
		ExpiresAt:     identity.ExpiresAt,
		Groups:        groups,
		ID:            identity.ID,
		Name:          preferredName,
		preferredName: preferredName,
		Roles:         roleList,
		Token:         token,
	}, nil
}

// backported from https://github.com/coreos/go-oidc/blob/master/oidc/verification.go#L28-L37
// I'll raise another PR to make it public in the go-oidc package so we can just use `oidc.ContainsString()`
func containsString(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// IsAudience checks the audience
func (r *UserContext) IsAudience(aud string) bool {
	return containsString(aud, r.Audiences)
}

// GetRoles returns a list of roles
func (r *UserContext) GetRoles() string {
	return strings.Join(r.Roles, ",")
}

// IsExpired checks if the token has expired
func (r *UserContext) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// IsBearer checks if the token
func (r *UserContext) IsBearer() bool {
	return r.BearerToken
}

// IsCookie checks if it's by a cookie
func (r *UserContext) IsCookie() bool {
	return !r.IsBearer()
}

// String returns a string representation of the user context
func (r *UserContext) String() string {
	return fmt.Sprintf("user: %s, expires: %s, roles: %s", r.preferredName, r.ExpiresAt.String(), strings.Join(r.Roles, ","))
}
