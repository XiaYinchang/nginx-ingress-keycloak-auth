package testfake

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
	"time"

	"github.com/XiaYinchang/nginx-ingress-keycloak-auth/pkg/common"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type FakeAuthServer struct {
	location   *url.URL
	key        jose.JWK
	signer     jose.Signer
	server     *httptest.Server
	expiration time.Duration
}

const fakePrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxMLIwi//YG6GPdYUPaV0PCXBEXjg2Xhf8/+NMB/1nt+wip4Z
rrAQf14PTCTlN4sbc2QGgRGtYikJBHQyfg/lCthrnasfdgL8c6SErr7Db524SqiD
m+/yKGI680LmBUIPkA0ikCJgb4cYVCiJ3HuYnFZUTsUAeK14SoXgcJdWulj0h6aP
iUIg5VrehuqAG+1RlK+GURgr9DbOmXJ/SYVKX/QArdBzjZ3BiQ1nxWWwBCLHfwv4
8bWxPJIbDDnUNl6LolpSJkxg4qlp+0I/xgEveK1n1CMEA0mHuXFHeekKO72GDKAk
h89C9qVF2GmpDfo8G0D3lFm2m3jFNyMQTWkSkwIDAQABAoIBADwhOrD9chHKNQQY
tD7SnV70OrhYNH7BJrGuWztlyO4wdgcmobqc263Q1OP0Mohy3oS5ALPY7x+cYsEV
sYiM2vYhhWG9tfOenf/JOzMb4SXvES7fqLiy71IgEtvcieb5dUAUg4eAue/bXTf6
24ahztWYHFOmKKq4eJZtq1U9KqfvlW1T4bg3mXV70huvfoMhYKwYryTOsQ5yiYCf
Yo4UGUBLfg3capIB5gxQdcqdDk+UTe9be7GQBj+3oziALb1nIhW7cpy0nw/r22A5
pv1FbRqND2VYKjZCQyUbxnjty5eDIW7fKBIh0Ez9yZHqz4KHb1u/KlFm31NGZpMU
Xs/WN+ECgYEA+kcAi7fTUjagqov5a4Y595ptu2gmU4Cxr+EBhMWadJ0g7enCXjTI
HAFEsVi2awbSRswjxdIG533SiKg8NIXThMntfbTm+Kw3LSb0/++Zyr7OuKJczKvQ
KfjAHvqsV8yJqy1gApYqVOeU4/jMLDs2sMY59/IQNkUVHNncZO09aa8CgYEAyUKG
BUyvxSim++YPk3OznBFZhqJqR75GYtWSu91BgZk/YmgYM4ht2u5q96AIRbJ664Ks
v93varNfqyKN1BN3JPLw8Ph8uX/7k9lMmECXoNp2Tm3A54zlsHyNOGOSvU7axvUg
PfIhpvRZKA0QQK3c1CZDghs94siJeBSIpuzCsl0CgYEA8Z28LCZiT3tHbn5FY4Wo
zp36k7L/VRvn7niVg71U2IGc+bHzoAjqqwaab2/KY9apCAop+t9BJRi2OJHZ1Ybg
5dAfg30ygh2YAvIaEj8YxL+iSGMOndS82Ng5eW7dFMH0ohnjF3wrD96mQdO+IHFl
4hDsg67f8dSNhlXYzGKwKCcCgYEAlAsrKprOcOkGbCU/L+fcJuFcSX0PUNbWT71q
wmZu2TYxOeH4a2/f3zuh06UUcLBpWvQ0vq4yfvqTVP+F9IqdCcDrG1at6IYMOSWP
AjABWYFZpTd2vt0V2EzGVMRqHHb014VYwjhqKLV1H9D8M5ew6R18ayg+zaNV+86e
9qsSTMECgYEA322XUN8yUBTTWBkXY7ipzTHSWkxMuj1Pa0gtBd6Qqqu3v7qI+jMZ
hlWS2akhJ+3e7f3+KCslG8YMItld4VvAK0eHKQbQM/onav/+/iiR6C2oRBm3OwqO
Ka0WPQGKjQJhZRtqDAT3sfnrEEUa34+MkXQeKFCu6Yi0dRFic4iqOYU=
-----END RSA PRIVATE KEY-----
`

type FakeDiscoveryResponse struct {
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint       string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// NewFakeAuthServer simulates a oauth service
func NewFakeAuthServer() *FakeAuthServer {
	// step: load the private key
	block, _ := pem.Decode([]byte(fakePrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse the private key, error: " + err.Error())
	}
	service := &FakeAuthServer{
		key: jose.JWK{
			ID:       "test-kid",
			Type:     "RSA",
			Alg:      "RS256",
			Use:      "sig",
			Exponent: privateKey.PublicKey.E,
			Modulus:  privateKey.PublicKey.N,
			Secret:   block.Bytes,
		},
		signer: jose.NewSignerRSA("test-kid", *privateKey),
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/auth/realms/hod-test/.well-known/openid-configuration", service.DiscoveryHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/certs", service.KeysHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/token", service.TokenHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/auth", service.AuthHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/userinfo", service.UserInfoHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/logout", service.LogoutHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.TokenHandler)

	service.server = httptest.NewServer(r)
	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.expiration = time.Duration(1) * time.Hour

	return service
}

func (r *FakeAuthServer) Close() {
	r.server.Close()
}

func (r *FakeAuthServer) GetLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *FakeAuthServer) GetRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Scheme, r.location.Host)
}

func (r *FakeAuthServer) SignToken(claims jose.Claims) (*jose.JWT, error) {
	return jose.NewSignedJWT(claims, r.signer)
}

func (r *FakeAuthServer) SetTokenExpiration(tm time.Duration) *FakeAuthServer {
	r.expiration = tm
	return r
}

func (r *FakeAuthServer) DiscoveryHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, FakeDiscoveryResponse{
		AuthorizationEndpoint:            fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Host),
		EndSessionEndpoint:               fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Host),
		Issuer:                           fmt.Sprintf("http://%s/auth/realms/hod-test", r.location.Host),
		JwksURI:                          fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Host),
		RegistrationEndpoint:             fmt.Sprintf("http://%s/auth/realms/hod-test/clients-registrations/openid-connect", r.location.Host),
		TokenEndpoint:                    fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Host),
		TokenIntrospectionEndpoint:       fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token/introspect", r.location.Host),
		UserinfoEndpoint:                 fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Host),
		GrantTypesSupported:              []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseModesSupported:           []string{"query", "fragment", "form_post"},
		ResponseTypesSupported:           []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:            []string{"public"},
	})
}

func (r *FakeAuthServer) KeysHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, jose.JWKSet{Keys: []jose.JWK{r.key}})
}

func (r *FakeAuthServer) AuthHandler(w http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}
	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, getRandomString(32))

	http.Redirect(w, req, redirectionURL, http.StatusTemporaryRedirect)
}

func (r *FakeAuthServer) LogoutHandler(w http.ResponseWriter, req *http.Request) {
	if refreshToken := req.FormValue("refresh_token"); refreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *FakeAuthServer) UserInfoHandler(w http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get("Authorization"), " ")
	if len(items) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	decoded, err := jose.ParseJWT(items[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := decoded.Claims()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, w, req, map[string]interface{}{
		"sub":                claims["sub"],
		"name":               claims["name"],
		"given_name":         claims["given_name"],
		"family_name":        claims["familty_name"],
		"preferred_username": claims["preferred_username"],
		"email":              claims["email"],
		"picture":            claims["picture"],
	})
}

func (r *FakeAuthServer) TokenHandler(w http.ResponseWriter, req *http.Request) {
	expires := time.Now().Add(r.expiration)
	unsigned := NewTestToken(r.GetLocation())
	unsigned.SetExpiration(expires)

	// sign the token with the private key
	token, err := jose.NewSignedJWT(unsigned.Claims, r.signer)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case oauth2.GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if username == ValidUsername && password == ValidPassword {
			renderJSON(http.StatusOK, w, req, common.TokenResponse{
				IDToken:      token.Encode(),
				AccessToken:  token.Encode(),
				RefreshToken: token.Encode(),
				ExpiresIn:    expires.UTC().Second(),
			})
			return
		}
		renderJSON(http.StatusUnauthorized, w, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case oauth2.GrantTypeRefreshToken:
		fallthrough
	case oauth2.GrantTypeAuthCode:
		renderJSON(http.StatusOK, w, req, common.TokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: token.Encode(),
			ExpiresIn:    expires.Second(),
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func renderJSON(code int, w http.ResponseWriter, req *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func getRandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
