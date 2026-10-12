package murkio

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Option configures Middleware and Authenticate.
type Option func(*settings)

type settings struct {
	auth           authOptions
	required       bool
	roles          []string
	signInURL      string
	noHandshake    bool
	onUnauthorized http.Handler
}

func collect(options []Option) settings {
	var s settings
	for _, option := range options {
		option(&s)
	}
	return s
}

// Required answers 401 (or redirects browsers to SignInURL) when nobody is signed in.
func Required() Option { return func(s *settings) { s.required = true } }

// Roles lets through only sessions with one of the roles (others get 403).
func Roles(roles ...string) Option {
	return func(s *settings) { s.roles = append(s.roles, roles...) }
}

// SignInURL is where browsers go when sign-in is required (the current path goes in ?redirect=).
func SignInURL(path string) Option { return func(s *settings) { s.signInURL = path } }

// WithUser also loads the profile (POST /v1/me, cached a minute per session).
func WithUser() Option { return func(s *settings) { s.auth.loadUser = true } }

// CheckRevocation asks the API whether the session was revoked (cached 30 s).
// If the API cannot be reached, the request is treated as signed out.
func CheckRevocation() Option { return func(s *settings) { s.auth.checkRevocation = true } }

// NoHandshake turns off the page that refreshes an expired session cookie.
func NoHandshake() Option { return func(s *settings) { s.noHandshake = true } }

// OnUnauthorized replaces the default 401 answer.
func OnUnauthorized(handler http.Handler) Option {
	return func(s *settings) { s.onUnauthorized = handler }
}

type contextKey struct{}

// ResultFrom returns the Result Middleware stored in the request context.
func ResultFrom(ctx context.Context) *Result {
	result, _ := ctx.Value(contextKey{}).(*Result)
	return result
}

// SessionFrom returns the request's session, or nil.
func SessionFrom(ctx context.Context) *Session {
	if result := ResultFrom(ctx); result != nil {
		return result.Session
	}
	return nil
}

// UserFrom returns the request's user profile (with WithUser()), or nil.
func UserFrom(ctx context.Context) *User {
	if result := ResultFrom(ctx); result != nil {
		return result.User
	}
	return nil
}

const handshakeGuard = "murkio_handshake"

func writeJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func navigation(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Accept"), "text/html"))
}

// Middleware authenticates each request, stores the Result in its context
// (SessionFrom, UserFrom) and, with Required or Roles, answers 401, 403 or a
// redirect instead of calling next. A page request whose session cookie
// expired while the browser still holds a session gets a short handshake
// page that refreshes the tokens and reloads, so pages see the user right
// after the 15-minute access token expires.
func (c *Client) Middleware(options ...Option) func(http.Handler) http.Handler {
	s := collect(options)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := c.Authenticate(r, options...)
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, result))

			if result.Session != nil {
				if len(s.roles) > 0 && !result.Session.HasRole(s.roles...) {
					writeJSON(w, http.StatusForbidden, "forbidden")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			if !s.noHandshake && navigation(r) && result.SignedInHint &&
				(result.Reason == ReasonMissing || result.Reason == ReasonExpired) && cookieValue(r, handshakeGuard) == "" {
				c.serveHandshake(w, r)
				return
			}

			if !s.required && len(s.roles) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if s.onUnauthorized != nil {
				s.onUnauthorized.ServeHTTP(w, r)
				return
			}
			if navigation(r) && s.signInURL != "" {
				target, err := url.Parse(s.signInURL)
				if err == nil {
					query := target.Query()
					query.Set("redirect", r.URL.RequestURI())
					target.RawQuery = query.Encode()
					w.Header().Set("Cache-Control", "no-store")
					http.Redirect(w, r, target.String(), http.StatusFound)
					return
				}
			}
			writeJSON(w, http.StatusUnauthorized, "unauthorized")
		})
	}
}

func (c *Client) serveHandshake(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	nonce := base64.StdEncoding.EncodeToString(raw)

	scriptOrigin := "https://cdn.jsdelivr.net"
	if script, err := url.Parse(c.scriptSource()); err == nil && script.Host != "" {
		scriptOrigin = script.Scheme + "://" + script.Host
	}
	apiOrigin := c.apiURL
	if api, err := url.Parse(c.apiURL); err == nil {
		apiOrigin = api.Scheme + "://" + api.Host
	}

	// Only this middleware reads the guard, so scripts cannot. It is Secure
	// whenever the request is: a plain-HTTP site in development still needs it.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the request scheme, see above
		Name: handshakeGuard, Value: "1", Path: "/", MaxAge: 30,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestScheme(r) == "https",
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"' "+scriptOrigin+"; connect-src "+apiOrigin+"; base-uri 'none'; frame-ancestors 'none'")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title>
` + string(c.scriptTag(nonce, HeadOptions{})) + `
<script nonce="` + nonce + `">(async function(){try{var m=window.Murkio&&window.Murkio.getMurkio();if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>
</head><body></body></html>`))
}
