// Package murkio is the Murkio identity SDK for Go backends.
//
// It tells who is behind each request and writes the login components into
// the pages you render, with only the application's publishable key:
//
//	m, err := murkio.FromEnv() // MURKIO_PUBLISHABLE_KEY, MURKIO_API_URL
//	http.Handle("/dashboard", m.Middleware(murkio.Required(), murkio.SignInURL("/login"))(dashboard))
//
//	func dashboard(w http.ResponseWriter, r *http.Request) {
//		session := murkio.SessionFrom(r.Context()) // UserID, SessionID, Roles...
//	}
//
// Access tokens are verified locally (Ed25519 with the application's JWKS,
// issuer, audience and expiry), so a request costs no call to the API. The
// backend never signs anyone in: the browser SDK does that against the API.
package murkio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultAPIURL is the hosted identity API.
const DefaultAPIURL = "https://api.mukio.com"

const (
	bootstrapTTL  = time.Minute
	userTTL       = time.Minute
	revocationTTL = 30 * time.Second
	jwksRetry     = time.Minute
	cacheLimit    = 10000
)

// Errors returned by Verify.
var (
	ErrMalformedToken = errors.New("murkio: malformed token")
	ErrInvalidToken   = errors.New("murkio: invalid token")
	ErrExpiredToken   = errors.New("murkio: expired token")
)

// Config configures a Client. Only PublishableKey is required.
type Config struct {
	// PublishableKey is the application's publishable key (pk_...).
	PublishableKey string
	// APIURL is the identity API. Defaults to DefaultAPIURL.
	APIURL string
	// CookieDomain is the cookie domain set in the browser SDK, when the
	// session cookie is shared with subdomains.
	CookieDomain string
	// ScriptURL and Integrity point Head() and the handshake page to a
	// self-hosted copy of the browser SDK (the same version).
	ScriptURL string
	Integrity string
	// HTTPClient calls the API. Defaults to a client with a 10 s timeout.
	HTTPClient *http.Client
}

// Bootstrap is GET /v1/client: the application, how to verify its tokens,
// its public config and its published login canvas.
type Bootstrap struct {
	ApplicationID string          `json:"application_id"`
	Issuer        string          `json:"issuer"`
	JWKSURL       string          `json:"jwks_url"`
	Config        json.RawMessage `json:"config"`
	Canvas        json.RawMessage `json:"canvas"`
}

// Claims are the verified access token claims.
type Claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	ApplicationID string   `json:"aid"`
	SessionID     string   `json:"sid"`
	Roles         []string `json:"roles"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	ID            string   `json:"jti"`
}

// Session is a verified access token.
type Session struct {
	UserID        string
	SessionID     string
	ApplicationID string
	Roles         []string
	Claims        Claims
	Token         string
}

// HasRole reports whether the session has one of the roles.
func (s *Session) HasRole(roles ...string) bool {
	for _, want := range roles {
		for _, role := range s.Roles {
			if role == want {
				return true
			}
		}
	}
	return false
}

// User is the profile of POST /v1/me.
type User struct {
	ID            string   `json:"id"`
	SessionID     string   `json:"session_id"`
	Email         *string  `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles"`
	MFAEnabled    bool     `json:"mfa_enabled"`
	CreatedAt     string   `json:"created_at"`
}

// APIError is an error answer of the identity API.
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("murkio: api answered %d (%s)", e.Status, e.Code)
}

type cached[T any] struct {
	at    time.Time
	value T
}

// Client verifies the sessions of one application. Create one per process
// and share it: it caches the bootstrap, the signing keys, the profiles and
// the revocation checks.
type Client struct {
	publishableKey string
	apiURL         string
	keyHash        string
	cookieDomain   string
	scriptURL      string
	integrity      string
	http           *http.Client

	mu        sync.Mutex
	bootstrap *cached[*Bootstrap]
	keys      map[string]ed25519.PublicKey
	keysAt    time.Time
	users     map[string]cached[*User]
	actives   map[string]cached[bool]
}

// New creates a Client.
func New(config Config) (*Client, error) {
	if !strings.HasPrefix(config.PublishableKey, "pk_") {
		return nil, errors.New("murkio: PublishableKey must be the application's publishable key (pk_...)")
	}
	apiURL := strings.TrimRight(config.APIURL, "/")
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		publishableKey: config.PublishableKey,
		apiURL:         apiURL,
		keyHash:        fnv1a32(config.PublishableKey),
		cookieDomain:   config.CookieDomain,
		scriptURL:      config.ScriptURL,
		integrity:      config.Integrity,
		http:           client,
		keys:           map[string]ed25519.PublicKey{},
		users:          map[string]cached[*User]{},
		actives:        map[string]cached[bool]{},
	}, nil
}

// FromEnv creates a Client from MURKIO_PUBLISHABLE_KEY, MURKIO_API_URL,
// MURKIO_SCRIPT_URL and MURKIO_SCRIPT_INTEGRITY.
func FromEnv() (*Client, error) {
	return New(Config{
		PublishableKey: os.Getenv("MURKIO_PUBLISHABLE_KEY"),
		APIURL:         os.Getenv("MURKIO_API_URL"),
		ScriptURL:      os.Getenv("MURKIO_SCRIPT_URL"),
		Integrity:      os.Getenv("MURKIO_SCRIPT_INTEGRITY"),
	})
}

func (c *Client) call(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.publishableKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var envelope struct {
		Data    json.RawMessage `json:"data"`
		Details []struct {
			Code string `json:"code"`
		} `json:"details"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&envelope); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if res.StatusCode >= 300 || len(envelope.Data) == 0 {
		code := fmt.Sprintf("http-%d", res.StatusCode)
		if len(envelope.Details) > 0 {
			code = envelope.Details[0].Code
		}
		return &APIError{Status: res.StatusCode, Code: code}
	}
	return json.Unmarshal(envelope.Data, out)
}

// Bootstrap returns GET /v1/client, cached for a minute.
func (c *Client) Bootstrap(ctx context.Context) (*Bootstrap, error) {
	c.mu.Lock()
	if c.bootstrap != nil && time.Since(c.bootstrap.at) < bootstrapTTL {
		value := c.bootstrap.value
		c.mu.Unlock()
		return value, nil
	}
	c.mu.Unlock()

	var bootstrap Bootstrap
	if err := c.call(ctx, http.MethodGet, "/v1/client", nil, &bootstrap); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.bootstrap = &cached[*Bootstrap]{at: time.Now(), value: &bootstrap}
	c.mu.Unlock()
	return &bootstrap, nil
}

// publicKey returns the signing key of kid, fetching the JWKS again only for
// an unknown kid (a key rotation) and at most once a minute.
func (c *Client) publicKey(ctx context.Context, bootstrap *Bootstrap, kid string) (ed25519.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	if time.Since(c.keysAt) < jwksRetry {
		return nil, ErrInvalidToken
	}
	c.keysAt = time.Now()

	jwksURL, err := url.Parse(c.apiURL + "/")
	if err != nil {
		return nil, err
	}
	jwksURL, err = jwksURL.Parse(bootstrap.JWKSURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}

	keys := map[string]ed25519.PublicKey{}
	for _, key := range body.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(key.X)
		if key.Kty != "OKP" || key.Crv != "Ed25519" || err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys[key.Kid] = ed25519.PublicKey(raw)
	}
	c.keys = keys

	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, ErrInvalidToken
}

func decodeSegment(segment string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// Verify checks an access token locally: an EdDSA signature by one of the
// application's keys, the issuer, the audience (the application) and the
// expiry. It returns ErrExpiredToken, ErrInvalidToken or ErrMalformedToken.
func (c *Client) Verify(ctx context.Context, token string) (*Session, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "EdDSA" {
		return nil, ErrInvalidToken
	}

	bootstrap, err := c.Bootstrap(ctx)
	if err != nil {
		return nil, err
	}
	key, err := c.publicKey(ctx, bootstrap, header.Kid)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, ErrMalformedToken
	}
	if claims.Issuer != bootstrap.Issuer || claims.Audience != bootstrap.ApplicationID || claims.Subject == "" || claims.SessionID == "" {
		return nil, ErrInvalidToken
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrExpiredToken
	}

	roles := claims.Roles
	if roles == nil {
		roles = []string{}
	}
	return &Session{
		UserID:        claims.Subject,
		SessionID:     claims.SessionID,
		ApplicationID: bootstrap.ApplicationID,
		Roles:         roles,
		Claims:        claims,
		Token:         token,
	}, nil
}

// User returns the profile of the session's user (POST /v1/me), cached for a
// minute per session.
func (c *Client) User(ctx context.Context, session *Session) (*User, error) {
	c.mu.Lock()
	if hit, ok := c.users[session.SessionID]; ok && time.Since(hit.at) < userTTL {
		c.mu.Unlock()
		return hit.value, nil
	}
	c.mu.Unlock()

	var user User
	if err := c.call(ctx, http.MethodPost, "/v1/me", map[string]string{"access_token": session.Token}, &user); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if len(c.users) >= cacheLimit {
		c.users = map[string]cached[*User]{}
	}
	c.users[session.SessionID] = cached[*User]{at: time.Now(), value: &user}
	c.mu.Unlock()
	return &user, nil
}

// Active asks the API whether the session is still active (not logged out,
// banned or revoked), cached for 30 seconds. Local verification alone
// accepts a revoked token until it expires (15 minutes).
func (c *Client) Active(ctx context.Context, session *Session) (bool, error) {
	key := session.Claims.ID
	if key == "" {
		key = session.Token
	}

	c.mu.Lock()
	if hit, ok := c.actives[key]; ok && time.Since(hit.at) < revocationTTL {
		c.mu.Unlock()
		return hit.value, nil
	}
	c.mu.Unlock()

	var result struct {
		Active bool `json:"active"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/sessions/verify", map[string]string{"access_token": session.Token}, &result); err != nil {
		return false, err
	}

	c.mu.Lock()
	if len(c.actives) >= cacheLimit {
		c.actives = map[string]cached[bool]{}
	}
	c.actives[key] = cached[bool]{at: time.Now(), value: result.Active}
	c.mu.Unlock()
	return result.Active, nil
}
