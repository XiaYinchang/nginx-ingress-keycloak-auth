package testfake

import (
	"time"

	"github.com/coreos/go-oidc/jose"
)

var (
	defaultTestTokenClaims = jose.Claims{
		"aud":                "test",
		"azp":                "clientid",
		"client_session":     "f0105893-369a-46bc-9661-ad8c747b1a69",
		"email":              "gambol99@gmail.com",
		"family_name":        "Jayawardene",
		"given_name":         "Rohith",
		"iat":                "1450372669",
		"iss":                "test",
		"jti":                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"name":               "Rohith Jayawardene",
		"nbf":                0,
		"preferred_username": "rjayawardene",
		"session_state":      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":                "Bearer",
	}
)

type FakeToken struct {
	Claims jose.Claims
}

func NewTestToken(issuer string) *FakeToken {
	Claims := make(jose.Claims)
	for k, v := range defaultTestTokenClaims {
		Claims[k] = v
	}
	Claims.Add("exp", float64(time.Now().Add(1*time.Hour).Unix()))
	Claims.Add("iat", float64(time.Now().Unix()))
	Claims.Add("iss", issuer)

	return &FakeToken{Claims: Claims}
}

// Merge is responsible for merging Claims into the token
func (t *FakeToken) Merge(Claims jose.Claims) {
	for k, v := range Claims {
		t.Claims.Add(k, v)
	}
}

// GetToken returns a JWT token from the clains
func (t *FakeToken) GetToken() jose.JWT {
	tk, _ := jose.NewJWT(jose.JOSEHeader{"alg": "RS256"}, t.Claims)
	return tk
}

// SetExpiration sets the expiration of the token
func (t *FakeToken) SetExpiration(tm time.Time) {
	t.Claims.Add("exp", float64(tm.Unix()))
}

// AddGroups adds groups to then token
func (t *FakeToken) AddGroups(groups []string) {
	t.Claims.Add("groups", groups)
}

// AddRealmRoles adds realms roles to token
func (t *FakeToken) AddRealmRoles(roles []string) {
	t.Claims.Add("realm_access", map[string]interface{}{
		"roles": roles,
	})
}

// AddClientRoles adds client roles to the token
func (t *FakeToken) AddClientRoles(client string, roles []string) {
	t.Claims.Add("resource_access", map[string]interface{}{
		client: map[string]interface{}{
			"roles": roles,
		},
	})
}
