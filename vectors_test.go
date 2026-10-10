package murkio

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type vectors struct {
	ApplicationID string          `json:"application_id"`
	Issuer        string          `json:"issuer"`
	JWKS          json.RawMessage `json:"jwks"`
	Cases         []struct {
		Name    string `json:"name"`
		Token   string `json:"token"`
		Expect  string `json:"expect"`
		Session *struct {
			UserID    string   `json:"user_id"`
			SessionID string   `json:"session_id"`
			Roles     []string `json:"roles"`
		} `json:"session"`
	} `json:"cases"`
	CookieHash map[string]string `json:"cookie_hash"`
}

// The vectors in libs/spec/server are shared by every server SDK: the same
// tokens must get the same verdict in Go, Node, Python, PHP, Ruby and Java.
func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../spec/server/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"application_id": v.ApplicationID, "issuer": v.Issuer, "jwks_url": "/jwks.json", "config": map[string]any{}, "canvas": map[string]any{},
		}})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(v.JWKS) })
	server := httptest.NewServer(mux)
	defer server.Close()

	for value, want := range v.CookieHash {
		if got := fnv1a32(value); got != want {
			t.Errorf("fnv1a32(%q) = %s, want %s", value, got, want)
		}
	}

	for _, tc := range v.Cases {
		client, err := New(Config{PublishableKey: "pk_vectors", APIURL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		session, err := client.Verify(context.Background(), tc.Token)
		switch tc.Expect {
		case "valid":
			if err != nil || session.UserID != tc.Session.UserID || session.SessionID != tc.Session.SessionID || len(session.Roles) != len(tc.Session.Roles) {
				t.Errorf("%s: expected a valid session, got %+v, %v", tc.Name, session, err)
			}
		case "expired":
			if !errors.Is(err, ErrExpiredToken) {
				t.Errorf("%s: expected ErrExpiredToken, got %v", tc.Name, err)
			}
		default:
			if err == nil || errors.Is(err, ErrExpiredToken) {
				t.Errorf("%s: expected a rejection, got %+v, %v", tc.Name, session, err)
			}
		}
	}
}
