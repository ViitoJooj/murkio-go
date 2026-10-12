package murkio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "pk_go_test"

type fakeAPI struct {
	server   *httptest.Server
	private  ed25519.PrivateKey
	meCalls  atomic.Int32
	revoked  map[string]bool
	jwksHits atomic.Int32
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{private: private, revoked: map[string]bool{}}
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, body any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("GET /v1/client", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reply(w, map[string]any{"data": map[string]any{
			"application_id": "app-1", "issuer": "enterprise-auth", "jwks_url": "/v1/applications/app-1/jwks.json",
			"config": map[string]any{}, "canvas": map[string]any{"version": 0, "document": map[string]any{"note": "</script><b>"}},
		}})
	})
	mux.HandleFunc("GET /v1/applications/app-1/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		api.jwksHits.Add(1)
		reply(w, map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(public)}}})
	})
	mux.HandleFunc("POST /v1/me", func(w http.ResponseWriter, r *http.Request) {
		api.meCalls.Add(1)
		email := "ana@example.com"
		reply(w, map[string]any{"data": User{ID: "user-1", Email: &email, EmailVerified: true, Roles: []string{"user"}}})
	})
	mux.HandleFunc("POST /v1/sessions/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reply(w, map[string]any{"data": map[string]any{"active": !api.revoked[body.AccessToken]}})
	})
	api.server = httptest.NewServer(mux)
	t.Cleanup(api.server.Close)
	return api
}

func (api *fakeAPI) token(t *testing.T, claims map[string]any, alg, kid string) string {
	t.Helper()
	base := map[string]any{
		"iss": "enterprise-auth", "sub": "user-1", "aud": "app-1", "aid": "app-1", "sid": "session-1",
		"roles": []string{"user"}, "iat": time.Now().Unix(), "exp": time.Now().Add(15 * time.Minute).Unix(), "jti": "j1",
	}
	for k, v := range claims {
		base[k] = v
	}
	encode := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signing := encode(map[string]string{"alg": alg, "kid": kid}) + "." + encode(base)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(api.private, []byte(signing)))
}

func (api *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{PublishableKey: testKey, APIURL: api.server.URL, HTTPClient: api.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestHashMatchesTheBrowserSDK(t *testing.T) {
	for value, want := range map[string]string{"": "811c9dc5", "a": "e40c292c", "foobar": "bf9cf968"} {
		if got := fnv1a32(value); got != want {
			t.Errorf("fnv1a32(%q) = %s, want %s", value, got, want)
		}
	}
}

func TestNewRefusesSecretKeys(t *testing.T) {
	if _, err := New(Config{PublishableKey: "sk_secret"}); err == nil {
		t.Fatal("a secret key must be refused")
	}
}

func TestVerify(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)
	ctx := context.Background()

	session, err := client.Verify(ctx, api.token(t, map[string]any{"roles": []string{"admin"}}, "EdDSA", "k1"))
	if err != nil || session.UserID != "user-1" || session.SessionID != "session-1" || !session.HasRole("admin") {
		t.Fatalf("unexpected session %+v, %v", session, err)
	}

	cases := map[string]struct {
		token string
		want  error
	}{
		"expired":          {api.token(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, "EdDSA", "k1"), ErrExpiredToken},
		"other app":        {api.token(t, map[string]any{"aud": "app-2"}, "EdDSA", "k1"), ErrInvalidToken},
		"other issuer":     {api.token(t, map[string]any{"iss": "someone"}, "EdDSA", "k1"), ErrInvalidToken},
		"alg none":         {api.token(t, nil, "none", "k1"), ErrInvalidToken},
		"unknown kid":      {api.token(t, nil, "EdDSA", "k9"), ErrInvalidToken},
		"tampered payload": {strings.Replace(api.token(t, nil, "EdDSA", "k1"), ".", ".x", 1), ErrInvalidToken},
		"garbage":          {"not-a-token", ErrMalformedToken},
	}
	for name, tc := range cases {
		if _, err := client.Verify(ctx, tc.token); err != tc.want {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	if hits := api.jwksHits.Load(); hits != 1 {
		t.Fatalf("an unknown kid within a minute must not refetch the JWKS, got %d fetches", hits)
	}
}

func get(path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com"+path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestAuthenticate(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)
	token := api.token(t, nil, "EdDSA", "k1")
	cookie := "__Host-murkio_session_" + fnv1a32(testKey) + "=" + token

	if result := client.Authenticate(get("/api", map[string]string{"Authorization": "Bearer " + token})); result.Session == nil {
		t.Fatalf("bearer token: %+v", result)
	}
	if result := client.Authenticate(get("/api", map[string]string{"Authorization": "Bearer " + testKey})); result.Reason != ReasonMissing {
		t.Fatalf("an api key is not a session: %+v", result)
	}
	if result := client.Authenticate(get("/page", map[string]string{"Cookie": cookie})); result.Session == nil {
		t.Fatalf("session cookie on a navigation: %+v", result)
	}

	post := httptest.NewRequest(http.MethodPost, "https://app.example.com/api", nil)
	post.Header.Set("Cookie", cookie)
	post.Header.Set("Sec-Fetch-Site", "cross-site")
	if result := client.Authenticate(post); result.Reason != ReasonCSRF {
		t.Fatalf("cookie on a cross-site POST: %+v", result)
	}
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	if result := client.Authenticate(post); result.Session == nil {
		t.Fatalf("cookie on a same-origin POST: %+v", result)
	}

	plain := "murkio_session_" + fnv1a32(testKey) + "=" + token
	if result := client.Authenticate(get("/page", map[string]string{"Cookie": plain})); result.Reason != ReasonMissing {
		t.Fatalf("the unprefixed cookie must be ignored on a real host: %+v", result)
	}
	local := httptest.NewRequest(http.MethodGet, "http://localhost:8080/page", nil)
	local.Header.Set("Cookie", plain)
	if result := client.Authenticate(local); result.Session == nil {
		t.Fatalf("the unprefixed cookie works on localhost: %+v", result)
	}
}

func TestUserAndRevocationAreCached(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)
	token := api.token(t, nil, "EdDSA", "k1")
	r := get("/", map[string]string{"Authorization": "Bearer " + token})

	for range 2 {
		result := client.Authenticate(r, WithUser(), CheckRevocation())
		if result.User == nil || *result.User.Email != "ana@example.com" {
			t.Fatalf("unexpected result %+v", result)
		}
	}
	if calls := api.meCalls.Load(); calls != 1 {
		t.Fatalf("expected one /v1/me call, got %d", calls)
	}

	revoked := api.token(t, map[string]any{"jti": "revoked"}, "EdDSA", "k1")
	api.revoked[revoked] = true
	if result := client.Authenticate(get("/", map[string]string{"Authorization": "Bearer " + revoked}), CheckRevocation()); result.Reason != ReasonRevoked {
		t.Fatalf("expected a revoked session, got %+v", result)
	}
}

func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

func TestMiddleware(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)
	token := api.token(t, nil, "EdDSA", "k1")
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + SessionFrom(r.Context()).UserID))
	})
	page := map[string]string{"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}

	protected := client.Middleware(Required(), SignInURL("/login"))(ok)
	if rec := serve(protected, get("/api", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api without a session: %d", rec.Code)
	}
	rec := serve(protected, get("/dashboard?tab=1", page))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login?redirect=%2Fdashboard%3Ftab%3D1" {
		t.Fatalf("page without a session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serve(protected, get("/api", map[string]string{"Authorization": "Bearer " + token})); rec.Body.String() != "hello user-1" {
		t.Fatalf("signed in: %d %s", rec.Code, rec.Body)
	}

	admin := client.Middleware(Roles("admin"))(ok)
	if rec := serve(admin, get("/admin", map[string]string{"Authorization": "Bearer " + token})); rec.Code != http.StatusForbidden {
		t.Fatalf("missing role: %d", rec.Code)
	}

	open := client.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionFrom(r.Context()) != nil {
			t.Error("no session expected")
		}
	}))
	if rec := serve(open, get("/", nil)); rec.Code != http.StatusOK {
		t.Fatalf("optional auth: %d", rec.Code)
	}
}

func TestHandshake(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)
	handler := client.Middleware(Required())(http.NotFoundHandler())
	headers := map[string]string{"Accept": "text/html", "Cookie": "__Host-murkio_uat_" + fnv1a32(testKey) + "=1"}

	rec := serve(handler, get("/dashboard", headers))
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := strings.TrimSuffix(strings.SplitN(strings.SplitN(csp, "'nonce-", 2)[1], "'", 2)[0], "'")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `nonce="`+nonce+`"`) || !strings.Contains(rec.Body.String(), `data-murkio-key="`+testKey+`"`) {
		t.Fatalf("expected the handshake page, got %d %s", rec.Code, rec.Body)
	}
	guard := rec.Header().Get("Set-Cookie")
	if !strings.Contains(guard, "murkio_handshake=1") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected handshake headers %v", rec.Header())
	}
	if !strings.Contains(guard, "HttpOnly") || !strings.Contains(guard, "SameSite=Lax") {
		t.Fatalf("the guard cookie must be out of reach of scripts, got %q", guard)
	}

	headers["Cookie"] += "; murkio_handshake=1"
	if rec := serve(handler, get("/dashboard", headers)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the guard cookie must stop the loop, got %d", rec.Code)
	}
}

func TestTemplates(t *testing.T) {
	api := newFakeAPI(t)
	client := api.client(t)

	page := template.Must(template.New("page").Funcs(client.TemplateFuncs(HeadOptions{AfterLogin: "/home"})).Parse(
		`<head>{{ murkioHead }}</head><body>{{ murkioCanvas }}{{ murkioEmailInput "input" }}{{ murkioLoginButton "Entrar" "btn \" onclick=\"x" }}</body>`))
	var out bytes.Buffer
	if err := page.Execute(&out, nil); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{
		`integrity="` + BrowserSDK.Integrity + `"`,
		`data-murkio-key="` + testKey + `"`,
		`data-murkio-after-login="/home"`,
		`<murkio-identity-canvas></murkio-identity-canvas>`,
		`<murkio-identity-email-input class="input"></murkio-identity-email-input>`,
		`class="btn &#34; onclick=&#34;x"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in %s", want, html)
		}
	}

	inline, err := client.BootstrapScript(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(inline), "</script><b>") || !strings.Contains(string(inline), `</script>`) || !strings.Contains(string(inline), "data-generated-at=") {
		t.Fatalf("the inline bootstrap is not escaped: %s", inline)
	}
}
