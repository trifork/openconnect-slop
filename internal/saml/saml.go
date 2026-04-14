// Package saml handles the SafeNet Trusted Access SAML form flow.
//
// The SafeNet STA flow (confirmed via JMarkstrom/SafeNet-Trusted-Access reference):
//
//  1. GET samlLoginURL → parse id="sas-login-form" (step 1: username only)
//  2. POST sas_user=username + all hidden fields → parse second sas-login-form
//  3. POST sas_response=<totp|empty> + all hidden fields → parse SAMLResponse form
//  4. POST SAMLResponse + RelayState to ASA ACS URL
//  5. ASA sets acSamlv2Token cookie in the redirect chain → we extract it
//     and return it to the caller for the AnyConnect XML auth-reply step.
package saml

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	formID          = "sas-login-form" // SafeNet STA direct form
	kcFormID        = "kc-form-login"  // Keycloak-brokered STA (step 1 only)
	userField       = "sas_user"       // username field in sas-login-form
	kcUserField     = "username"       // username field in kc-form-login
	responseField   = "sas_response"
	samlRespField   = "SAMLResponse"
	relayStateField = "RelayState"

	// pushPollInterval is how often we poll the SafeNet parking spot endpoint.
	pushPollInterval = 2 * time.Second
	// pushTimeout is the maximum time we wait for push approval.
	pushTimeout = 120 * time.Second

	userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Authenticator performs the SafeNet STA SAML form flow.
type Authenticator struct {
	client   *http.Client
	username string
	log      *slog.Logger
}

// New creates an Authenticator. The HTTP client follows redirects and
// maintains a cookie jar across requests — both are required for SAML.
func New(username string, log *slog.Logger) (*Authenticator, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		// CheckRedirect: nil — default: follow up to 10 redirects.
		// The final redirect to localhost:29786 is followed automatically.
	}
	return &Authenticator{
		client:   client,
		username: username,
		log:      log,
	}, nil
}

// AuthenticateTOTP performs the full STA SAML flow using a TOTP code.
// Returns the SSO token (value of tokenCookieName cookie set by the ASA
// after the SAMLResponse redirect chain completes).
func (a *Authenticator) AuthenticateTOTP(samlLoginURL, loginFinalURL, tokenCookieName, totpCode string) (string, error) {
	a.log.Info("starting TOTP auth", "url", samlLoginURL)

	// Step 1: GET the login URL, parse step-1 form (sas-login-form or kc-form-login).
	step1Form, usernameField, err := a.fetchAndParseLoginForm(samlLoginURL)
	if err != nil {
		return "", fmt.Errorf("fetching login page: %w", err)
	}
	a.log.Debug("step 1 form parsed", "action", step1Form.Action, "fields", len(step1Form.Fields), "username_field", usernameField)

	// Step 2: POST username.
	step1Form.Set(usernameField, a.username)
	step2Body, step2URL, err := a.postForm(step1Form)
	if err != nil {
		return "", fmt.Errorf("posting username: %w", err)
	}

	// Step 2 response: parse the OTP challenge form.
	step2Form, err := parseForm(step2Body, step2URL)
	if err != nil {
		return "", fmt.Errorf("parsing OTP challenge form: %w", err)
	}
	a.log.Debug("step 2 form parsed", "action", step2Form.Action, "fields", len(step2Form.Fields))

	// Step 3: POST TOTP code.
	step2Form.Set(responseField, totpCode)
	samlBody, samlURL, err := a.postForm(step2Form)
	if err != nil {
		return "", fmt.Errorf("posting TOTP code: %w", err)
	}

	// Step 4: parse SAMLResponse auto-submit form and POST to ASA ACS.
	return a.submitSAMLResponse(samlBody, samlURL, loginFinalURL, tokenCookieName)
}

// AuthenticatePush performs push authentication by:
//  1. POSTing the username to trigger the push notification (server-side)
//  2. Detecting the parking spot URL from the push page
//  3. Polling the parking spot (SafeNet cloud) until approved
//  4. Submitting the challenge form once with the parking result
//
// Returns ErrPushNeedsChromedp if no parking URL is detected (fallback to browser).
func (a *Authenticator) AuthenticatePush(samlLoginURL, loginFinalURL, tokenCookieName string) (string, error) {
	a.log.Info("starting push auth (parking spot polling)", "url", samlLoginURL)

	step1Form, usernameField, err := a.fetchAndParseLoginForm(samlLoginURL)
	if err != nil {
		return "", fmt.Errorf("fetching login page: %w", err)
	}

	step1Form.Set(usernameField, a.username)
	step2Body, step2URL, err := a.postForm(step1Form)
	if err != nil {
		return "", fmt.Errorf("posting username: %w", err)
	}
	// Push notification has now been triggered server-side.

	step2Form, err := parseForm(step2Body, step2URL)
	if err != nil {
		return "", fmt.Errorf("parsing push challenge form: %w", err)
	}

	// Detect the parking spot URL — this is what we poll, NOT the challenge form.
	parkingURL := detectParkingURL(step2Body, step2Form)
	if parkingURL == "" {
		a.log.Info("no parking URL found — falling back to chromedp")
		return "", ErrPushNeedsChromedp
	}
	a.log.Info("push triggered — approve on your phone",
		"polling", parkingURL,
		"timeout", pushTimeout,
	)

	// Poll SafeNet's cloud endpoint (zero VPN/Keycloak traffic during wait).
	result, err := pollParkingSpot(a.client, parkingURL, a.log, pushTimeout)
	if err != nil {
		return "", err
	}

	// Submit the challenge form once with exactly what the SafeNet JS sends:
	//   authenticationId = UUID from the parking URL (last path segment)
	//   pushOtpSpsStatus = the status STRING (e.g. "RESPONSE_AVAILABLE"), not full JSON
	//   sas_response     = "" (empty — push auth proof is the parking spot result)
	submitForm := step2Form.Clone()
	submitForm.Set("authenticationId", result.authID)
	submitForm.Set(pushOtpSpsStatusField, result.status)

	samlBody, samlURL, err := a.postForm(submitForm)
	if err != nil {
		return "", fmt.Errorf("submitting push result: %w", err)
	}

	return a.submitSAMLResponse(samlBody, samlURL, loginFinalURL, tokenCookieName)
}

// ErrPushNeedsChromedp is returned when the push waiting page uses
// JavaScript XHR polling that cannot be replicated with net/http.
// Caller should fall back to chromedp mode (reveng-234.8).
var ErrPushNeedsChromedp = fmt.Errorf("SafeNet STA push page requires JavaScript — use chromedp mode")

// Form represents a parsed HTML form with its action URL and fields.
type Form struct {
	Action string
	Method string
	Fields map[string]string
}

func (f *Form) Set(name, value string) {
	f.Fields[name] = value
}

func (f *Form) Clone() *Form {
	fields := make(map[string]string, len(f.Fields))
	for k, v := range f.Fields {
		fields[k] = v
	}
	return &Form{Action: f.Action, Method: f.Method, Fields: fields}
}

func (f *Form) values() url.Values {
	v := make(url.Values, len(f.Fields))
	for k, val := range f.Fields {
		v.Set(k, val)
	}
	return v
}

// fetchAndParseLoginForm GETs url and parses the step-1 login form.
// Tries sas-login-form (direct STA) and kc-form-login (Keycloak) in order.
// Returns the form and the name of the username input field.
func (a *Authenticator) fetchAndParseLoginForm(rawURL string) (*Form, string, error) {
	a.log.Debug("GET", "url", rawURL)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response body: %w", err)
	}

	a.log.Debug("GET response",
		"status", resp.StatusCode,
		"final_url", resp.Request.URL.String(),
		"content_type", resp.Header.Get("Content-Type"),
		"body_bytes", len(body),
	)
	a.logBodySample(body)

	return parseLoginForm(body, resp.Request.URL.String())
}

// fetchAndParseForm GETs url and parses the sas-login-form from the response.
func (a *Authenticator) fetchAndParseForm(rawURL string) (*Form, error) {
	a.log.Debug("GET", "url", rawURL)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	a.log.Debug("GET response",
		"status", resp.StatusCode,
		"final_url", resp.Request.URL.String(),
		"content_type", resp.Header.Get("Content-Type"),
		"body_bytes", len(body),
	)
	a.logBodySample(body)

	return parseForm(body, resp.Request.URL.String())
}

// postForm POSTs a form and returns the response body and final URL.
func (a *Authenticator) postForm(f *Form) ([]byte, string, error) {
	encoded := f.values().Encode()
	a.log.Debug("POST",
		"url", f.Action,
		"field_count", len(f.Fields),
		"fields", sanitiseFields(f.Fields),
	)

	req, err := http.NewRequest(http.MethodPost, f.Action, strings.NewReader(encoded))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("POST %s: %w", f.Action, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading POST response: %w", err)
	}

	finalURL := resp.Request.URL.String()
	a.log.Debug("POST response",
		"status", resp.StatusCode,
		"final_url", finalURL,
		"content_type", resp.Header.Get("Content-Type"),
		"body_bytes", len(body),
	)
	a.logBodySample(body)

	return body, finalURL, nil
}

// submitSAMLResponse parses the SAMLResponse form from body and POSTs it to the ASA.
// Returns the SSO token cookie set by the ASA after the redirect chain.
func (a *Authenticator) submitSAMLResponse(body []byte, baseURL, loginFinalURL, tokenCookieName string) (string, error) {
	samlForm, err := parseSAMLResponseForm(body, baseURL)
	if err != nil {
		return "", err
	}
	return a.submitSAMLForm(samlForm, loginFinalURL, tokenCookieName)
}

// submitSAMLForm POSTs the SAMLResponse form to the ASA ACS endpoint and
// extracts the SSO token cookie from the jar after the redirect chain completes.
//
// The Cisco ASA ACS sometimes returns a JS-redirect intermediate form
// (id="samlform") rather than doing a plain HTTP redirect. Browsers auto-submit
// it via onload JavaScript that also sets a CSRF cookie. We replicate that here.
func (a *Authenticator) submitSAMLForm(f *Form, loginFinalURL, tokenCookieName string) (string, error) {
	a.log.Debug("submitting SAMLResponse to ASA ACS", "action", f.Action)
	body, finalURL, err := a.postForm(f)
	if err != nil {
		return "", fmt.Errorf("posting SAMLResponse: %w", err)
	}
	if err := a.followCiscoRedirectForm(body, finalURL); err != nil {
		return "", fmt.Errorf("following Cisco redirect form: %w", err)
	}
	return a.extractSSOToken(loginFinalURL, tokenCookieName)
}

// followCiscoRedirectForm detects and follows the Cisco ASA intermediate form
// (id="samlform") that is sometimes returned by the ACS endpoint instead of
// a plain HTTP redirect. The page's onload JavaScript:
//
//  1. Sets cookie webvpnlogin=1
//  2. Sets cookie CSRFtoken=<value> (same value as the csrf_token form field)
//  3. Auto-submits the form to /+webvpn+/index.html
//
// We replicate steps 1–3 manually since our HTTP client cannot execute JavaScript.
// If no samlform is present this is a no-op.
func (a *Authenticator) followCiscoRedirectForm(body []byte, baseURL string) error {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil // unparseable — not a Cisco redirect page
	}
	node := findFormByID(doc, "samlform")
	if node == nil {
		return nil // no samlform — nothing to do
	}
	form, err := extractForm(node, baseURL)
	if err != nil {
		return fmt.Errorf("extracting samlform: %w", err)
	}
	a.log.Debug("Cisco intermediate redirect form found — following", "action", form.Action)

	// Set cookies the JS would have injected before submission.
	// CSRFtoken must match the csrf_token form field (double-submit CSRF pattern).
	if formURL, parseErr := url.Parse(form.Action); parseErr == nil {
		cookies := []*http.Cookie{
			{Name: "webvpnlogin", Value: "1", Path: "/"},
		}
		if csrfToken := form.Fields["csrf_token"]; csrfToken != "" {
			cookies = append(cookies, &http.Cookie{Name: "CSRFtoken", Value: csrfToken, Path: "/"})
		}
		a.client.Jar.SetCookies(formURL, cookies)
		a.log.Debug("injected Cisco portal cookies before samlform POST")
	}

	if _, _, err := a.postForm(form); err != nil {
		return fmt.Errorf("posting samlform: %w", err)
	}
	return nil
}

// extractSSOToken retrieves the SSO token cookie from the HTTP client's jar.
// The ASA sets the cookie (typically "acSamlv2Token") during the SAMLResponse
// redirect chain that ends at loginFinalURL.
func (a *Authenticator) extractSSOToken(loginFinalURL, cookieName string) (string, error) {
	u, err := url.Parse(loginFinalURL)
	if err != nil {
		return "", fmt.Errorf("parsing loginFinalURL %q: %w", loginFinalURL, err)
	}
	for _, c := range a.client.Jar.Cookies(u) {
		if c.Name == cookieName {
			a.log.Debug("SSO token cookie extracted", "cookie_name", cookieName)
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("SSO token cookie %q not found in jar (domain: %s) — SAML redirect may have failed", cookieName, u.Host)
}

// parseForm parses the sas-login-form from HTML body.
func parseForm(body []byte, baseURL string) (*Form, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parsing HTML: %w", err)
	}

	form := findFormByID(doc, formID)
	if form == nil {
		return nil, fmt.Errorf("form id=%q not found in page", formID)
	}
	return extractForm(form, baseURL)
}

// parseLoginForm finds the step-1 username form. It tries sas-login-form
// (direct SafeNet STA) first, then kc-form-login (Keycloak-brokered STA).
// Returns the form and the name of the username input field.
func parseLoginForm(body []byte, baseURL string) (*Form, string, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, "", fmt.Errorf("parsing HTML: %w", err)
	}
	// Direct SafeNet STA
	if node := findFormByID(doc, formID); node != nil {
		f, err := extractForm(node, baseURL)
		return f, userField, err
	}
	// Keycloak-brokered STA
	if node := findFormByID(doc, kcFormID); node != nil {
		f, err := extractForm(node, baseURL)
		return f, kcUserField, err
	}
	return nil, "", fmt.Errorf("no login form found (tried %q, %q)", formID, kcFormID)
}

// parseSAMLResponseForm finds the auto-submit SAMLResponse form in HTML body.
func parseSAMLResponseForm(body []byte, baseURL string) (*Form, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parsing HTML: %w", err)
	}

	form := findFormWithField(doc, samlRespField)
	if form == nil {
		return nil, fmt.Errorf("SAMLResponse form not found")
	}
	return extractForm(form, baseURL)
}

// findFormByID walks the HTML tree and returns the <form id="id"> node.
func findFormByID(n *html.Node, id string) *html.Node {
	if n.Type == html.ElementNode && n.Data == "form" {
		for _, attr := range n.Attr {
			if attr.Key == "id" && attr.Val == id {
				return n
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findFormByID(c, id); found != nil {
			return found
		}
	}
	return nil
}

// findFormWithField returns the first <form> containing an <input name="field">.
func findFormWithField(n *html.Node, fieldName string) *html.Node {
	if n.Type == html.ElementNode && n.Data == "form" {
		if formContainsField(n, fieldName) {
			return n
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findFormWithField(c, fieldName); found != nil {
			return found
		}
	}
	return nil
}

func formContainsField(form *html.Node, fieldName string) bool {
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == fieldName {
					return true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(form)
}

// extractForm builds a Form from an HTML <form> node, resolving the action
// URL relative to baseURL and collecting all <input> field values.
func extractForm(node *html.Node, baseURL string) (*Form, error) {
	f := &Form{
		Fields: make(map[string]string),
		Method: "POST",
	}

	for _, attr := range node.Attr {
		switch attr.Key {
		case "action":
			f.Action = attr.Val
		case "method":
			f.Method = strings.ToUpper(attr.Val)
		}
	}

	// Resolve relative action URL.
	if f.Action != "" && !strings.HasPrefix(f.Action, "http") {
		base, err := url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("parsing base URL: %w", err)
		}
		ref, err := url.Parse(f.Action)
		if err != nil {
			return nil, fmt.Errorf("parsing form action: %w", err)
		}
		f.Action = base.ResolveReference(ref).String()
	}
	if f.Action == "" {
		f.Action = baseURL
	}

	// Collect all input fields.
	collectInputs(node, f.Fields)

	return f, nil
}

func collectInputs(n *html.Node, fields map[string]string) {
	if n.Type == html.ElementNode && n.Data == "input" {
		var name, value string
		for _, attr := range n.Attr {
			switch attr.Key {
			case "name":
				name = attr.Val
			case "value":
				value = attr.Val
			}
		}
		if name != "" {
			fields[name] = value
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectInputs(c, fields)
	}
}

// looksLikeJSPollingVerbose returns the matched indicator or empty string.
func looksLikeJSPollingVerbose(body []byte) string {
	s := strings.ToLower(string(body))
	indicators := []string{
		"xmlhttprequest",
		"fetch(",
		"setinterval",
		"polling",
	}
	for _, ind := range indicators {
		if strings.Contains(s, ind) {
			return ind
		}
	}
	return ""
}

// logBodySample logs up to 800 bytes of the response body at DEBUG level.
func (a *Authenticator) logBodySample(body []byte) {
	if len(body) == 0 {
		return
	}
	sample := body
	truncated := false
	if len(sample) > 800 {
		sample = sample[:800]
		truncated = true
	}
	a.log.Debug("response body sample",
		"truncated", truncated,
		"sample", string(sample),
	)
}

// sanitiseFields returns a loggable version of form fields with sensitive values masked.
func sanitiseFields(fields map[string]string) map[string]string {
	sensitive := map[string]bool{
		"sas_response":  true,
		"SAMLResponse":  true,
		"samlresponse":  true,
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		if sensitive[k] || sensitive[strings.ToLower(k)] {
			out[k] = "[redacted]"
		} else if len(v) > 60 {
			out[k] = v[:60] + "…"
		} else {
			out[k] = v
		}
	}
	return out
}

// isCallbackCaptured is no longer used — the sso-v2 flow redirects to the ASA,
// not to localhost:29786. Kept as a tombstone comment for historical reference.
// The old --external-browser flow needed this; the sso-v2 flow does not.
