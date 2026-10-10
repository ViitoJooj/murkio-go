package murkio

import (
	"fmt"
	"hash/fnv"
	"net"
	"strings"
)

// fnv1a32 is the hash the browser SDK uses to name the cookies of a
// publishable key (__Host-murkio_session_<hash>). It must stay FNV-1a,
// 32 bits, lowercase hex, like @murkio/html and @murkio/node.
func fnv1a32(value string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return fmt.Sprintf("%08x", hash.Sum32())
}

type cookieNames struct {
	session string
	uat     string
}

// acceptedCookieNames lists the session cookies a request may carry,
// strongest first. __Host- is what the browser SDK writes on https; __Secure-
// only when the developer set a cookie domain; the unprefixed name only on
// localhost, because on a real host any sibling subdomain could set it.
func (c *Client) acceptedCookieNames(host string) []cookieNames {
	names := []cookieNames{{session: "__Host-murkio_session_" + c.keyHash, uat: "__Host-murkio_uat_" + c.keyHash}}
	if c.cookieDomain != "" {
		names = append(names, cookieNames{session: "__Secure-murkio_session_" + c.keyHash, uat: "__Secure-murkio_uat_" + c.keyHash})
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.Trim(hostname, "[]")
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		names = append(names, cookieNames{session: "murkio_session_" + c.keyHash, uat: "murkio_uat_" + c.keyHash})
	}
	return names
}
