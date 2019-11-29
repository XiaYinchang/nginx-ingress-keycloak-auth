package testfake

import (
	"encoding/json"
	"net/http"
)

// FakeUpstreamResponse is the response from fake upstream
type FakeUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
}

// FakeUpstreamService acts as a fake upstream service, returns the headers and request
type FakeUpstreamService struct{}

func (f *FakeUpstreamService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(testProxyAccepted, "true")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	content, _ := json.Marshal(&FakeUpstreamResponse{
		URI:     r.RequestURI,
		Method:  r.Method,
		Address: r.RemoteAddr,
		Headers: r.Header,
	})
	_, _ = w.Write(content)
}
