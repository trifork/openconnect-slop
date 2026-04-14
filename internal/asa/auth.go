// Package asa implements the Cisco AnyConnect sso-v2 XML authentication protocol.
//
// Protocol flow:
//  1. DetectAuthURL: GET host → follow redirects → final URL is the XML POST target
//  2. AuthInit: POST XML config-auth type=init → returns SSO URLs + opaque element
//  3. (caller performs SafeNet STA SAML flow → obtains acSamlv2Token cookie)
//  4. AuthReply: POST XML config-auth type=auth-reply → returns session-token + cert hash
//
// Critical header rule (from openconnect MR !75):
// MUST NOT send X-AnyConnect-Platform — that header causes a 302 redirect to
// password-based auth instead of SAML. The required headers are:
//   User-Agent: AnyConnect Linux_64 <version>
//   X-Transcend-Version: 1
//   X-Aggregate-Auth: 1
//   X-Support-HTTP-Auth: true
//   Content-Type: application/x-www-form-urlencoded  (body is raw XML despite this)
package asa

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const deviceID = "linux-64"

// InitResult holds the parsed result of an XML auth-init request.
type InitResult struct {
	SSOLoginURL     string // sso-v2-login: SafeNet STA SAML URL to start auth
	LoginFinalURL   string // sso-v2-login-final: ASA URL that receives the SAML redirect
	TokenCookieName string // sso-v2-token-cookie-name (typically "acSamlv2Token")
	OpaqueXML       string // raw <opaque …>…</opaque> bytes — preserved verbatim for auth-reply
	AuthURL         string // the URL we POSTed to; reused for auth-reply
}

// CompleteResult holds the session credentials returned by XML auth-reply.
type CompleteResult struct {
	SessionToken   string
	ServerCertHash string // e.g. "sha256:deadbeef…"
}

// DetectAuthURL GETs host and returns the final URL after following all redirects.
// That final URL is used as the POST target for auth-init and auth-reply.
func DetectAuthURL(host string, log *slog.Logger) (string, error) {
	log.Debug("detecting auth URL", "host", host)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(host)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", host, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	final := resp.Request.URL.String()
	log.Debug("auth URL detected", "url", final)
	return final, nil
}

// GetServerCertHash connects to host over TLS and returns the leaf certificate
// fingerprint as "sha256:<hex>". This is the value to pass to openconnect
// --servercert. Returns an empty string on error (non-fatal — user can skip
// fingerprint verification, though it is not recommended).
func GetServerCertHash(host string, log *slog.Logger) string {
	// Normalise: strip scheme, extract host:port.
	bare := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if !strings.Contains(bare, ":") {
		bare += ":443"
	}
	conn, err := tls.Dial("tcp", bare, &tls.Config{InsecureSkipVerify: false})
	if err != nil {
		// Try again without verification so we can still get the cert.
		conn, err = tls.Dial("tcp", bare, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Debug("TLS dial for cert hash failed", "error", err)
			return ""
		}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	// Use SPKI (SubjectPublicKeyInfo) hash in pin-sha256 format — this is what
	// openconnect --servercert expects on both Linux and macOS.
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	hash := "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
	log.Debug("server cert hash extracted via TLS", "hash", hash)
	return hash
}


func AuthInit(authURL, authGroup, acVersion string, log *slog.Logger) (*InitResult, error) {
	body := buildInitXML(authURL, authGroup, acVersion)
	log.Debug("XML auth-init", "url", authURL, "group", authGroup, "version", acVersion)

	respBody, err := postXML(authURL, body, acVersion, log)
	if err != nil {
		return nil, fmt.Errorf("auth-init POST: %w", err)
	}

	result, err := parseInitResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("parsing auth-init response: %w", err)
	}
	result.AuthURL = authURL

	log.Debug("auth-init parsed",
		"sso_login", result.SSOLoginURL,
		"login_final", result.LoginFinalURL,
		"token_cookie", result.TokenCookieName,
		"opaque_bytes", len(result.OpaqueXML),
	)
	return result, nil
}

// AuthReply posts the XML auth-reply with the SSO token and returns session credentials.
func AuthReply(init *InitResult, ssoToken, acVersion string, log *slog.Logger) (*CompleteResult, error) {
	body := buildReplyXML(init, ssoToken, acVersion)
	log.Debug("XML auth-reply", "url", init.AuthURL)

	respBody, err := postXML(init.AuthURL, body, acVersion, log)
	if err != nil {
		return nil, fmt.Errorf("auth-reply POST: %w", err)
	}

	result, err := parseReplyResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("parsing auth-reply response: %w", err)
	}
	log.Debug("auth-reply parsed", "cert_hash", result.ServerCertHash)
	return result, nil
}

func buildInitXML(authURL, authGroup, acVersion string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<config-auth client="vpn" type="init" aggregate-auth-version="2">` + "\n" +
		`  <version who="vpn">` + xmlEscape(acVersion) + `</version>` + "\n" +
		`  <device-id>` + deviceID + `</device-id>` + "\n" +
		`  <group-select>` + xmlEscape(authGroup) + `</group-select>` + "\n" +
		`  <group-access>` + xmlEscape(authURL) + `</group-access>` + "\n" +
		`  <capabilities>` + "\n" +
		`    <auth-method>single-sign-on-v2</auth-method>` + "\n" +
		`  </capabilities>` + "\n" +
		`</config-auth>`
}

func buildReplyXML(init *InitResult, ssoToken, acVersion string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">` + "\n" +
		`  <version who="vpn">` + xmlEscape(acVersion) + `</version>` + "\n" +
		`  <device-id>` + deviceID + `</device-id>` + "\n" +
		`  <session-token/>` + "\n" +
		`  <session-id/>` + "\n" +
		`  ` + init.OpaqueXML + "\n" +
		`  <auth>` + "\n" +
		`    <sso-token>` + xmlEscape(ssoToken) + `</sso-token>` + "\n" +
		`  </auth>` + "\n" +
		`</config-auth>`
}

// postXML sends a raw XML body to the given URL with the required AnyConnect headers.
// Despite the Content-Type, the body is raw XML — this is per protocol spec.
func postXML(targetURL, body, acVersion string, log *slog.Logger) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AnyConnect Linux_64 "+acVersion)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Transcend-Version", "1")
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("X-Support-HTTP-Auth", "true")
	// DO NOT set X-AnyConnect-Platform — causes 302 redirect to password auth.

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	log.Debug("XML POST response",
		"url", targetURL,
		"status", resp.StatusCode,
		"body_bytes", len(respBody),
	)
	if resp.StatusCode != http.StatusOK {
		sample := respBody
		if len(sample) > 500 {
			sample = sample[:500]
		}
		return nil, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, targetURL, string(sample))
	}

	return respBody, nil
}

// xmlInitResponse is used to unmarshal the auth-init XML response.
type xmlInitResponse struct {
	XMLName xml.Name `xml:"config-auth"`
	Auth    struct {
		SSOLogin        string `xml:"sso-v2-login"`
		SSOLoginFinal   string `xml:"sso-v2-login-final"`
		TokenCookieName string `xml:"sso-v2-token-cookie-name"`
	} `xml:"auth"`
}

func parseInitResponse(body []byte) (*InitResult, error) {
	var parsed xmlInitResponse
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("XML decode: %w (body: %s)", err, truncate(body, 500))
	}
	if parsed.Auth.SSOLogin == "" {
		return nil, fmt.Errorf("sso-v2-login not found in response (body: %s)", truncate(body, 500))
	}

	opaque := extractOpaqueXML(string(body))
	if opaque == "" {
		return nil, fmt.Errorf("opaque element not found in auth-init response")
	}

	tokenName := parsed.Auth.TokenCookieName
	if tokenName == "" {
		tokenName = "acSamlv2Token" // well-known default
	}

	return &InitResult{
		SSOLoginURL:     parsed.Auth.SSOLogin,
		LoginFinalURL:   parsed.Auth.SSOLoginFinal,
		TokenCookieName: tokenName,
		OpaqueXML:       opaque,
	}, nil
}

// xmlReplyResponse is used to unmarshal the auth-reply XML response.
type xmlReplyResponse struct {
	XMLName        xml.Name `xml:"config-auth"`
	SessionToken   string   `xml:"session-token"`
	ServerCertHash string   `xml:"server-cert-hash"`
}

func parseReplyResponse(body []byte) (*CompleteResult, error) {
	var parsed xmlReplyResponse
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("XML decode: %w (body: %s)", err, truncate(body, 500))
	}
	if parsed.SessionToken == "" {
		return nil, fmt.Errorf("session-token not found in response (body: %s)", truncate(body, 500))
	}
	return &CompleteResult{
		SessionToken:   parsed.SessionToken,
		ServerCertHash: parsed.ServerCertHash,
	}, nil
}

// extractOpaqueXML extracts the raw <opaque …>…</opaque> element from an XML
// string. It is preserved verbatim to avoid XML round-trip encoding issues that
// would break the server's opaque blob parsing.
func extractOpaqueXML(body string) string {
	start := strings.Index(body, "<opaque")
	if start == -1 {
		return ""
	}
	end := strings.Index(body[start:], "</opaque>")
	if end == -1 {
		return ""
	}
	return body[start : start+end+len("</opaque>")]
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
