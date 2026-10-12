package murkio

import (
	"context"
	"encoding/json"
	"html"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// HeadOptions configures the <script> of the browser SDK.
type HeadOptions struct {
	// AfterLogin is where the browser goes after signing in.
	AfterLogin string
	// Locale of the built-in screens and messages.
	Locale string
	// OAuthRedirectURL is the social sign-in return URL (must be in the
	// application's redirect URLs).
	OAuthRedirectURL string
}

func attributes(pairs ...string) string {
	var out strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			continue
		}
		out.WriteString(" " + pairs[i] + `="` + html.EscapeString(pairs[i+1]) + `"`)
	}
	return out.String()
}

func (c *Client) scriptSource() string {
	if c.scriptURL != "" {
		return c.scriptURL
	}
	return BrowserSDK.URL
}

func (c *Client) scriptTag(nonce string, options HeadOptions) template.HTML {
	integrity := c.integrity
	if c.scriptURL == "" {
		integrity = BrowserSDK.Integrity
	}
	crossorigin := ""
	if integrity != "" {
		crossorigin = "anonymous"
	}
	// murkio:allow dangerous-sink every attribute value goes through html.EscapeString
	return template.HTML("<script" + attributes(
		"src", c.scriptSource(),
		"integrity", integrity,
		"crossorigin", crossorigin,
		"nonce", nonce,
		"data-murkio-key", c.publishableKey,
		"data-murkio-api", c.apiURL,
		"data-murkio-locale", options.Locale,
		"data-murkio-after-login", options.AfterLogin,
		"data-murkio-oauth-redirect", options.OAuthRedirectURL,
	) + "></script>") // #nosec G203 -- escaped, see the comment above
}

// Head returns the <script> that loads the browser SDK, pinned with its SRI
// hash. Put it in <head>.
func (c *Client) Head(options HeadOptions) template.HTML {
	return c.scriptTag("", options)
}

// BootstrapScript inlines GET /v1/client in the page, so the browser draws
// the canvas without fetching it. encoding/json escapes <, >, & and the
// U+2028/U+2029 separators, so the JSON cannot end the <script> tag. The
// browser trusts it for two minutes after data-generated-at.
func (c *Client) BootstrapScript(ctx context.Context) (template.HTML, error) {
	bootstrap, err := c.Bootstrap(ctx)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(bootstrap)
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	// murkio:allow dangerous-sink json.Marshal escapes <, > and & as \u sequences
	return template.HTML(`<script type="application/json" id="murkio-bootstrap" data-generated-at="` + stamp + `">` + string(raw) + `</script>`), nil // #nosec G203 -- escaped, see the comment above
}

// Field configures a standalone component.
type Field struct {
	Class       string
	Form        string
	Placeholder string
	Label       string
}

func tag(name string, field Field) template.HTML {
	// murkio:allow dangerous-sink every attribute value goes through html.EscapeString
	return template.HTML("<" + name + attributes("class", field.Class, "form", field.Form, "placeholder", field.Placeholder, "label", field.Label) + "></" + name + ">") // #nosec G203 -- escaped, see the comment above
}

// Canvas configures <murkio-identity-canvas>.
type Canvas struct {
	Screen   string
	Class    string
	Locale   string
	LightDOM bool
}

// CanvasTag returns <murkio-identity-canvas>, the login canvas designed in the dashboard.
func CanvasTag(canvas Canvas) template.HTML {
	light := ""
	if canvas.LightDOM {
		light = " light-dom"
	}
	// murkio:allow dangerous-sink every attribute value goes through html.EscapeString
	return template.HTML("<murkio-identity-canvas" + attributes("screen", canvas.Screen, "class", canvas.Class, "locale", canvas.Locale) + light + "></murkio-identity-canvas>") // #nosec G203 -- escaped, see the comment above
}

// TemplateFuncs returns the functions for html/template:
//
//	{{ murkioHead }}                          in <head>
//	{{ murkioCanvas }}                        the login canvas
//	{{ murkioEmailInput "input" }}            standalone components, with your CSS classes
//	{{ murkioPasswordInput "input" }}
//	{{ murkioKeepLogged "Keep me signed in" }}
//	{{ murkioLoginButton "Sign in" "btn" }}
//	{{ murkioRegisterButton "Create account" "btn" }}
//	{{ murkioError "" }}
func (c *Client) TemplateFuncs(options HeadOptions) template.FuncMap {
	return template.FuncMap{
		"murkioHead":   func() template.HTML { return c.Head(options) },
		"murkioCanvas": func() template.HTML { return CanvasTag(Canvas{}) },
		"murkioEmailInput": func(class string) template.HTML {
			return tag("murkio-identity-email-input", Field{Class: class})
		},
		"murkioPasswordInput": func(class string) template.HTML {
			return tag("murkio-identity-password-input", Field{Class: class})
		},
		"murkioKeepLogged": func(label string) template.HTML {
			return tag("murkio-identity-keep-logged", Field{Label: label})
		},
		"murkioLoginButton": func(label, class string) template.HTML {
			return tag("murkio-identity-login-button", Field{Label: label, Class: class})
		},
		"murkioRegisterButton": func(label, class string) template.HTML {
			return tag("murkio-identity-register-button", Field{Label: label, Class: class})
		},
		"murkioError": func(class string) template.HTML {
			return tag("murkio-identity-error", Field{Class: class})
		},
	}
}
