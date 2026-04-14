// push_parking.go implements headless push polling via the SafeNet parking spot API.
//
// When the push challenge page loads, SafeNet has already sent a push notification
// to the user's phone. The page's JavaScript polls a "parking spot" URL on
// SafeNet's cloud (prk.pce.safenetid.com) to detect approval — it does NOT
// re-POST the challenge form (which would trigger a new push each time).
//
// We replicate this by:
//  1. Detecting the parking URL from the form's hidden fields or CSP meta tag
//  2. Polling it with GET until it returns a non-pending response
//  3. Submitting the challenge form once with pushOtpSpsStatus = the result
//
// This approach sends zero requests to the VPN server or Keycloak during the
// wait period — only GET requests to SafeNet's cloud polling endpoint.
package saml

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// pushOtpSpsStatusField is the form field Keycloak expects to contain the
// parking spot response (name = "Push OTP SafeNet Parking Spot Status").
const pushOtpSpsStatusField = "pushOtpSpsStatus"

// detectParkingURL extracts the async push polling URL from either:
//  1. The form's sas_push hidden field (SafeNet-specific, observed in testing)
//  2. The Content-Security-Policy meta tag's connect-src directive (generic)
//
// The parking URL lives on SafeNet's cloud (prk.pce.safenetid.com). Polling it
// does not trigger new push notifications.
func detectParkingURL(body []byte, form *Form) string {
	// 1. Known SafeNet field name — fastest path.
	if u := form.Fields["sas_push"]; u != "" && strings.HasPrefix(u, "http") {
		return u
	}

	// 2. Parse Content-Security-Policy from <meta http-equiv="Content-Security-Policy">.
	// This is vendor-agnostic: any page that does async XHR polling must declare
	// the polling endpoint in connect-src — it can't be obfuscated.
	csp := extractMetaCSP(body)
	if csp != "" {
		if u := parkingURLFromCSP(csp); u != "" {
			return u
		}
	}

	return ""
}

// extractMetaCSP finds <meta http-equiv="Content-Security-Policy" content="...">
// and returns the content attribute value.
func extractMetaCSP(body []byte) string {
	s := string(body)
	lower := strings.ToLower(s)
	// Find <meta ... http-equiv="content-security-policy" ...>
	idx := 0
	for {
		start := strings.Index(lower[idx:], "<meta")
		if start == -1 {
			break
		}
		start += idx
		end := strings.Index(lower[start:], ">")
		if end == -1 {
			break
		}
		tag := lower[start : start+end+1]
		if strings.Contains(tag, "content-security-policy") {
			// Extract content="..." from the original (non-lowercased) tag.
			orig := s[start : start+end+1]
			return extractAttr(orig, "content")
		}
		idx = start + 1
	}
	return ""
}

// extractAttr extracts the value of an HTML attribute from a tag string.
func extractAttr(tag, attr string) string {
	lower := strings.ToLower(tag)
	key := attr + "="
	idx := strings.Index(lower, key)
	if idx == -1 {
		return ""
	}
	rest := tag[idx+len(key):]
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' || rest[0] == '\'' {
		quote := rest[0]
		end := strings.IndexByte(rest[1:], quote)
		if end == -1 {
			return ""
		}
		// Unescape HTML entities in the content value.
		val := rest[1 : end+1]
		val = strings.ReplaceAll(val, "&#39;", "'")
		val = strings.ReplaceAll(val, "&quot;", `"`)
		val = strings.ReplaceAll(val, "&amp;", "&")
		return val
	}
	end := strings.IndexAny(rest, " \t\n\r>")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// parkingURLFromCSP parses a CSP string and returns the first external https://
// URL from the connect-src directive.
func parkingURLFromCSP(csp string) string {
	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		parts := strings.Fields(directive)
		if len(parts) < 2 {
			continue
		}
		if strings.ToLower(parts[0]) != "connect-src" {
			continue
		}
		for _, src := range parts[1:] {
			if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
				return src
			}
		}
	}
	return ""
}

// parkingResult holds the resolved status from a parking spot poll.
type parkingResult struct {
	// authID is the UUID extracted from the parking URL — set as authenticationId.
	authID string
	// status is the plain status string from the JSON response — set as pushOtpSpsStatus.
	// From the SafeNet JS: pushOtpSpsStatus = data.status (not the full JSON body).
	status string
}

// pollParkingSpot waits for push approval by long-polling the SafeNet parking
// spot endpoint. The SafeNet page JS sends a single long-poll POST — the server
// holds the connection open until the push is resolved, then returns the status.
//
// We replicate this exactly: one POST per round, with the remaining deadline as
// the HTTP timeout. If the server returns PENDING immediately (not holding), we
// back off 2s before retrying to avoid hammering. If it holds (true long-poll),
// we retry immediately after it closes.
//
// This approach sends at most a handful of connections over the entire wait
// period, far fewer than 2s short-polling (which would send ~60 over 2 minutes).
//
// The endpoint requires POST (returns 405 for GET). POST with empty JSON body.
func pollParkingSpot(client *http.Client, parkingURL string, log interface {
	Debug(string, ...any)
	Info(string, ...any)
}, timeout time.Duration) (*parkingResult, error) {
	// Extract auth UUID from the last path segment (matches JS: spsurl.lastIndexOf('/'))
	authID := parkingURL[strings.LastIndex(parkingURL, "/")+1:]

	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		remaining := time.Until(deadline)

		// Use the remaining time as the HTTP timeout so a single POST can hold
		// open for the full duration. Build a fresh client per attempt so the
		// timeout adjusts as the deadline approaches.
		longPollClient := &http.Client{
			Jar:     client.Jar,
			Timeout: remaining + 2*time.Second, // small buffer over deadline
		}

		requestStart := time.Now()
		resp, err := longPollClient.Post(parkingURL, "application/json", strings.NewReader("{}"))
		elapsed := time.Since(requestStart)
		if err != nil {
			// Network/timeout error — back off briefly and retry if time remains.
			log.Debug("parking spot POST error — retrying",
				"attempt", attempt,
				"elapsed", elapsed.Round(time.Millisecond),
				"error", err,
			)
			time.Sleep(pushPollInterval)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading parking spot response: %w", err)
		}

		bodyStr := strings.TrimSpace(string(body))
		log.Debug("parking spot poll",
			"attempt", attempt,
			"remaining", remaining.Round(time.Second),
			"elapsed", elapsed.Round(time.Millisecond),
			"status", resp.StatusCode,
			"body", bodyStr,
		)

		// Treat any non-2xx as a transient error — retry with backoff.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			time.Sleep(pushPollInterval)
			continue
		}

		statusStr := extractParkingStatus(bodyStr)
		if isParkingResolved(statusStr) {
			log.Info("push approved — parking spot resolved",
				"attempt", attempt,
				"authID", authID,
				"statusStr", statusStr,
			)
			return &parkingResult{authID: authID, status: statusStr}, nil
		}

		// PENDING: if the server returned quickly it doesn't support long-polling
		// for this state — back off before retrying to avoid hammering.
		// If it held the connection (elapsed > 1s), retry immediately.
		if elapsed < time.Second {
			log.Debug("server returned PENDING quickly — short backoff before retry",
				"backoff", pushPollInterval,
			)
			time.Sleep(pushPollInterval)
		}
		// else: server held the connection (true long-poll) — retry immediately
	}

	return nil, fmt.Errorf("push approval timed out after %s", timeout)
}

// extractParkingStatus returns the status string from a parking spot JSON response.
// The SafeNet JS submits data.status (the string value), not the full JSON body.
// Falls back to the raw body if JSON parsing fails.
func extractParkingStatus(body string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		for k, v := range obj {
			if strings.ToLower(k) == "status" {
				return fmt.Sprintf("%v", v)
			}
		}
	}
	return body
}

// isParkingResolved returns true when the status string from the parking spot
// indicates the push has been resolved — i.e. not pending/waiting.
// Input is already the extracted status string (not raw JSON).
func isParkingResolved(status string) bool {
	if status == "" {
		return false
	}
	upper := strings.ToUpper(status)
	if strings.Contains(upper, "PENDING") || strings.Contains(upper, "WAITING") {
		return false
	}
	return true
}
