package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeResolvesApplicationFromClientID(t *testing.T) {
	var gotGraphPath string
	var gotGraphQuery string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(request.Body)
			if !strings.Contains(string(body), "client_secret=secret-value") {
				t.Errorf("token request did not contain the client secret form value")
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"token_type":"Bearer","access_token":"test-token"}`))
		case http.MethodGet:
			gotGraphPath = request.URL.Path
			gotGraphQuery = request.URL.Query().Get("$filter")
			if request.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("missing Graph bearer token")
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"value":[{"id":"object-id","displayName":"Test app","passwordCredentials":[{"keyId":"key-id","displayName":"current","endDateTime":"2030-01-02T03:04:05Z"}]}]}`))
		default:
			t.Errorf("unexpected HTTP method %s", request.Method)
		}
	}))
	defer server.Close()

	// Rewrite requests to the test server while preserving the production request paths.
	client := server.Client()
	client.Transport = rewriteTransport{base: server.URL, delegate: http.DefaultTransport}
	result, err := probe(context.Background(), client, probeConfig{
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret-value",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if result.ApplicationObjectID != "object-id" || result.DisplayName != "Test app" {
		t.Fatalf("unexpected application result: %+v", result)
	}
	if !result.Expiry.Equal(time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("unexpected expiry: %v", result.Expiry)
	}
	if gotGraphPath != "/v1.0/applications" || gotGraphQuery != "appId eq 'client-id'" {
		t.Fatalf("unexpected Graph lookup: %s?%s", gotGraphPath, gotGraphQuery)
	}
}

type rewriteTransport struct {
	base     string
	delegate http.RoundTripper
}

func (transport rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	baseRequest, err := http.NewRequestWithContext(request.Context(), request.Method, transport.base+request.URL.RequestURI(), request.Body)
	if err != nil {
		return nil, err
	}
	cloned.URL = baseRequest.URL
	cloned.Host = baseRequest.Host
	return transport.delegate.RoundTrip(cloned)
}

func TestProbeRejectsAmbiguousCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			_, _ = writer.Write([]byte(`{"token_type":"Bearer","access_token":"test-token"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"value":[{"id":"object-id","passwordCredentials":[{"keyId":"one","endDateTime":"2030-01-01T00:00:00Z"},{"keyId":"two","endDateTime":"2030-01-02T00:00:00Z"}]}]}`))
	}))
	defer server.Close()

	client := server.Client()
	client.Transport = rewriteTransport{base: server.URL, delegate: http.DefaultTransport}
	_, err := probe(context.Background(), client, probeConfig{
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret-value",
		Timeout:      time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "multiple password credentials") {
		t.Fatalf("expected ambiguous credential error, got %v", err)
	}
}
