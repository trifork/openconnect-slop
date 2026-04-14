// browser.go implements push authentication via headless Chromium (Strategy B).
//
// Used when Strategy A (HTTP polling) detects that SafeNet STA's push-wait
// page requires JavaScript XHR polling — i.e. when AuthenticatePush returns
// ErrPushNeedsChromedp.
//
// chromedp drives a headless Chromium process via the Chrome DevTools Protocol.
// No display server (X11/Wayland/Xvfb) is required.
//
// Flow:
//  1. Launch headless Chromium
//  2. Navigate to samlLoginURL (SafeNet STA SAML IdP)
//  3. Wait for sas-login-form, fill username, submit
//  4. MobilePASS push fires automatically; user approves on phone
//  5. STA JS polling detects approval, POSTs SAMLResponse to ASA ACS
//  6. ASA sets acSamlv2Token cookie, redirects to loginFinalURL
//  7. chromedp detects the URL landing on the ASA domain
//  8. Cookies are extracted from Chromium via CDP network.GetCookies
package saml

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	// browserTimeout is the outer deadline for the entire browser-based auth.
	// Must be long enough for the user to approve the push on their phone.
	browserTimeout = 150 * time.Second

	// urlPollInterval is how often the browser URL is checked while waiting.
	urlPollInterval = 500 * time.Millisecond
)

// AuthenticatePushChromedp drives headless Chromium to complete the SAML push flow.
// It blocks until the user approves the MobilePASS push notification or the timeout expires.
// Returns the SSO token cookie value extracted from Chromium's cookie store.
func (a *Authenticator) AuthenticatePushChromedp(samlLoginURL, loginFinalURL, tokenCookieName string) (string, error) {
	a.log.Info("starting push auth (strategy B: chromedp headless browser)", "url", samlLoginURL)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(userAgent),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(func(format string, args ...any) {
			a.log.Debug("chromedp", "msg", fmt.Sprintf(format, args...))
		}),
		chromedp.WithErrorf(func(format string, args ...any) {
			a.log.Debug("chromedp error", "msg", fmt.Sprintf(format, args...))
		}),
	)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, browserTimeout)
	defer cancelTimeout()

	a.log.Info("headless Chromium launched — waiting for push approval",
		"timeout", browserTimeout,
		"hint", "approve the MobilePASS notification on your phone")

	a.log.Debug("navigating to SAML login URL", "url", samlLoginURL)

	var ssoToken string
	err := chromedp.Run(ctx,
		chromedp.Navigate(samlLoginURL),

		chromedp.ActionFunc(func(ctx context.Context) error {
			a.log.Debug("waiting for #sas-login-form")
			return nil
		}),
		chromedp.WaitVisible(`#sas-login-form`, chromedp.ByID),

		chromedp.ActionFunc(func(ctx context.Context) error {
			a.log.Debug("form visible — filling username", "username", a.username)
			return nil
		}),
		chromedp.SetValue(`input[name="sas_user"]`, a.username, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			a.log.Debug("submitting username form")
			return nil
		}),
		chromedp.Submit(`#sas-login-form`, chromedp.ByID),

		chromedp.WaitReady(`body`, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var u string
			if err := chromedp.Location(&u).Do(ctx); err == nil {
				a.log.Debug("post-submit page loaded", "url", u)
			}
			return nil
		}),

		// Wait until the browser lands on the ASA login-final URL after the
		// full SAML redirect chain (STA → SAMLResponse POST → ASA ACS → loginFinalURL).
		chromedp.ActionFunc(func(ctx context.Context) error {
			return waitForLoginFinalURL(ctx, loginFinalURL, a.log)
		}),

		// Extract the SSO token cookie from Chromium's cookie store via CDP.
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().Do(ctx)
			if err != nil {
				return fmt.Errorf("GetCookies: %w", err)
			}
			for _, c := range cookies {
				if c.Name == tokenCookieName {
					a.log.Debug("SSO token cookie extracted from browser",
						"cookie_name", tokenCookieName,
					)
					ssoToken = c.Value
					return nil
				}
			}
			return fmt.Errorf("SSO token cookie %q not found in browser jar", tokenCookieName)
		}),
	)

	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			return "", fmt.Errorf("push approval timed out after %s — did you approve on your phone?", browserTimeout)
		}
		return "", fmt.Errorf("browser auth failed: %w", err)
	}

	a.log.Info("SSO token obtained via browser")
	return ssoToken, nil
}

// waitForLoginFinalURL polls the current browser URL every 500ms until it
// matches the loginFinalURL's host (indicating the SAML redirect chain has
// returned to the ASA and the SSO cookie has been set).
func waitForLoginFinalURL(ctx context.Context, loginFinalURL string, log interface {
	Debug(string, ...any)
	Info(string, ...any)
}) error {
	// We consider "success" when the browser URL is on the ASA domain and
	// contains the /+CSCOE+/ path that's unique to the SAML return flow.
	// This avoids false positives during the initial STA navigation.
	var target string
	if idx := strings.Index(loginFinalURL, "://"); idx >= 0 {
		rest := loginFinalURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			target = rest[:slash] // just the host
		} else {
			target = rest
		}
	}

	pollCount := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var current string
		if err := chromedp.Location(&current).Do(ctx); err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		pollCount++
		if pollCount%10 == 0 {
			log.Debug("waiting for ASA redirect", "current_url", current, "polls", pollCount)
		}

		if target != "" && strings.Contains(current, target) && strings.Contains(current, "+CSCOE+") {
			log.Info("browser reached ASA login-final URL", "url", current)
			return nil
		}

		time.Sleep(urlPollInterval)
	}
}
