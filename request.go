package murkio

import (
	"errors"
	"net/http"
	"strings"
)

// Reason says why a request has no session.
type Reason string

const (
	ReasonMissing Reason = "missing"
	ReasonInvalid Reason = "invalid"
	ReasonExpired Reason = "expired"
	ReasonRevoked Reason = "revoked"
	ReasonCSRF    Reason = "csrf"
)

// Result is the outcome of Authenticate.
type Result struct {
	// Session is nil when nobody is signed in on this request.
	Session *Session
	// User is set with WithUser().
	User *User
	// Reason says why Session is nil.
	Reason Reason
	// SignedInHint: the browser holds a session (its "signed in" cookie is
	// set), even if this request's token is missing or expired.
	SignedInHint bool
}

type authOptions struct {
	loadUser        bool
	checkRevocation bool
}

func requestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" || proto == "http" {
		return proto
	}
	return "http"
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// sameOrigin tells whether a request comes from a page of this same site,
// by Sec-Fetch-Site (all current browsers) or else by Origin.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	return origin != "" && origin == requestScheme(r)+"://"+requestHost(r)
}

// Authenticate finds and verifies the session of a request: the
// `Authorization: Bearer` access token (APIs called with getToken() in the
// browser), or the session cookie the browser SDK writes (page navigations).
//
// The cookie goes with every request to the site, including ones another
// site makes the browser send, so it only counts for GET, HEAD and OPTIONS
// or for same-origin requests. Anything that changes state must send the
// token in the header.
func (c *Client) Authenticate(r *http.Request, options ...Option) *Result {
	settings := collect(options)
	names := c.acceptedCookieNames(requestHost(r))

	result := &Result{}
	for _, name := range names {
		if cookieValue(r, name.uat) == "1" {
			result.SignedInHint = true
		}
	}

	token := ""
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		value := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if !strings.HasPrefix(value, "pk_") && !strings.HasPrefix(value, "sk_") {
			token = value
		}
	}
	if token == "" {
		for _, name := range names {
			if value := cookieValue(r, name.session); value != "" {
				token = value
				break
			}
		}
		if token == "" {
			result.Reason = ReasonMissing
			return result
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !sameOrigin(r) {
			result.Reason = ReasonCSRF
			return result
		}
	}

	session, err := c.Verify(r.Context(), token)
	if err != nil {
		result.Reason = ReasonInvalid
		if errors.Is(err, ErrExpiredToken) {
			result.Reason = ReasonExpired
		}
		return result
	}

	if settings.auth.checkRevocation {
		active, err := c.Active(r.Context(), session)
		if err != nil || !active {
			result.Reason = ReasonRevoked
			return result
		}
	}
	if settings.auth.loadUser {
		if user, err := c.User(r.Context(), session); err == nil {
			result.User = user
		}
	}

	result.Session = session
	return result
}
