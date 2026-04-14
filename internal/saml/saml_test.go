package saml_test

import (
	"log/slog"
	"os"
	"testing"

	"openconnect-slop/internal/saml"
)

// Minimal SafeNet STA step-1 page (username form).
const step1HTML = `<!DOCTYPE html><html><body>
<form id="sas-login-form" action="https://idp.eu.safenetid.com/auth/realms/TENANT-STA/login-actions/authenticate" method="POST">
  <input type="text"   name="sas_user"   value="" />
  <input type="hidden" name="execution"  value="abc123" />
  <input type="hidden" name="_eventId"   value="submit" />
</form>
</body></html>`

// SafeNet STA step-2 page (OTP/push challenge form).
const step2HTML = `<!DOCTYPE html><html><body>
<form id="sas-login-form" action="https://idp.eu.safenetid.com/auth/realms/TENANT-STA/login-actions/authenticate" method="POST">
  <input type="text"   name="sas_response" value="" />
  <input type="hidden" name="execution"    value="def456" />
  <input type="hidden" name="_eventId"     value="submit" />
</form>
</body></html>`

// SAML SP auto-submit page returned after successful authentication.
const samlResponseHTML = `<!DOCTYPE html><html><body>
<form method="POST" action="https://vpn.company.com/+CSCOE+/saml/sp/acs?tgname=DefaultWEBVPN">
  <input type="hidden" name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNlIHhtbG5z..." />
  <input type="hidden" name="RelayState"   value="relay-state-token" />
</form>
<script>document.forms[0].submit();</script>
</body></html>`

func newTestAuth(t *testing.T) *saml.Authenticator {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := saml.New("testuser@corp.com", log)
	if err != nil {
		t.Fatalf("saml.New: %v", err)
	}
	return a
}

func TestParseStep1Form(t *testing.T) {
	f, err := saml.ParseFormForTest([]byte(step1HTML), "https://idp.eu.safenetid.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := f.Fields["sas_user"]; !ok {
		t.Error("sas_user field missing")
	}
	if _, ok := f.Fields["execution"]; !ok {
		t.Error("execution hidden field missing")
	}
}

func TestParseStep2Form(t *testing.T) {
	f, err := saml.ParseFormForTest([]byte(step2HTML), "https://idp.eu.safenetid.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := f.Fields["sas_response"]; !ok {
		t.Error("sas_response field missing")
	}
}

func TestParseSAMLResponseForm(t *testing.T) {
	f, err := saml.ParseSAMLResponseFormForTest([]byte(samlResponseHTML), "https://idp.eu.safenetid.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := f.Fields["SAMLResponse"]; v == "" {
		t.Error("SAMLResponse field is empty")
	}
	if v := f.Fields["RelayState"]; v == "" {
		t.Error("RelayState field is empty")
	}
	if f.Action != "https://vpn.company.com/+CSCOE+/saml/sp/acs?tgname=DefaultWEBVPN" {
		t.Errorf("unexpected action URL: %s", f.Action)
	}
}

func TestFormNotFound(t *testing.T) {
	_, err := saml.ParseFormForTest([]byte(`<html><body><p>no form here</p></body></html>`), "https://example.com/")
	if err == nil {
		t.Error("expected error for missing form, got nil")
	}
}

func TestLooksLikeJSPolling(t *testing.T) {
	cases := []struct {
		html string
		want bool
	}{
		{`<html><body><p>Please wait...</p></body></html>`, false},
		{`<html><body><script>setInterval(function(){...}, 2000)</script></body></html>`, true},
		{`<html><body><script>fetch('/status')</script></body></html>`, true},
		{`<html><body><script>new XMLHttpRequest()</script></body></html>`, true},
	}
	for _, tc := range cases {
		got := saml.LooksLikeJSPollingForTest([]byte(tc.html))
		if got != tc.want {
			t.Errorf("looksLikeJSPolling(%q) = %v, want %v", tc.html[:40], got, tc.want)
		}
	}
}

func TestNewAuthenticator(t *testing.T) {
	_ = newTestAuth(t) // just ensure it doesn't panic
}

// --- Parking spot tests ---

const pushChallengeWithSasPush = `<!DOCTYPE html><html>
<head>
<meta http-equiv="Content-Security-Policy"
  content="connect-src 'self' https://prk.pce.safenetid.com/api/parkingspot/AABBCC1122">
</head>
<body>
<form id="sas-login-form" action="https://idp.eu.safenetid.com/auth/realms/T/login-actions/authenticate" method="POST">
  <input type="hidden" name="sas_push"         value="https://prk.pce.safenetid.com/api/parkingspot/AABBCC1122" />
  <input type="hidden" name="pushOtpSpsStatus" value="" />
  <input type="text"   name="sas_response"     value="" />
  <input type="hidden" name="execution"        value="ghi789" />
</form>
</body></html>`

const pushChallengeCSPOnly = `<!DOCTYPE html><html>
<head>
<meta http-equiv="Content-Security-Policy"
  content="default-src 'self'; connect-src 'self' https://prk.pce.safenetid.com/api/parkingspot/XXYYZZ9900; script-src 'self'">
</head>
<body>
<form id="sas-login-form" action="https://idp.eu.safenetid.com/" method="POST">
  <input type="hidden" name="pushOtpSpsStatus" value="" />
  <input type="text"   name="sas_response"     value="" />
</form>
</body></html>`

func TestDetectParkingURL_SasPushField(t *testing.T) {
	body := []byte(pushChallengeWithSasPush)
	form, err := saml.ParseFormForTest(body, "https://idp.eu.safenetid.com/")
	if err != nil {
		t.Fatalf("parse form: %v", err)
	}
	got := saml.DetectParkingURLForTest(body, form)
	want := "https://prk.pce.safenetid.com/api/parkingspot/AABBCC1122"
	if got != want {
		t.Errorf("DetectParkingURL (sas_push) = %q, want %q", got, want)
	}
}

func TestDetectParkingURL_CSPFallback(t *testing.T) {
	body := []byte(pushChallengeCSPOnly)
	form, err := saml.ParseFormForTest(body, "https://idp.eu.safenetid.com/")
	if err != nil {
		t.Fatalf("parse form: %v", err)
	}
	got := saml.DetectParkingURLForTest(body, form)
	want := "https://prk.pce.safenetid.com/api/parkingspot/XXYYZZ9900"
	if got != want {
		t.Errorf("DetectParkingURL (CSP) = %q, want %q", got, want)
	}
}

func TestDetectParkingURL_NotFound(t *testing.T) {
	form, _ := saml.ParseFormForTest([]byte(step2HTML), "https://idp.eu.safenetid.com/")
	got := saml.DetectParkingURLForTest([]byte(step2HTML), form)
	if got != "" {
		t.Errorf("expected empty URL, got %q", got)
	}
}

func TestIsParkingResolved(t *testing.T) {
	// isParkingResolved now takes the extracted status string (not raw JSON).
	// Use IsParkingResolvedForTest which calls isParkingResolved directly.
	cases := []struct {
		status  string
		want    bool
		comment string
	}{
		{"PENDING", false, "PENDING"},
		{"pending", false, "pending lowercase"},
		{"RESPONSE_AVAILABLE", true, "SafeNet approved status"},
		{"APPROVED", true, "approved"},
		{"DENIED", true, "denied"},
		{"SUCCESS", true, "success"},
		{"EXPIRED", true, "expired"},
		{"", false, "empty status"},
		{"WAITING", false, "waiting"},
	}
	for _, tc := range cases {
		got := saml.IsParkingResolvedForTest(tc.status)
		if got != tc.want {
			t.Errorf("IsParkingResolved(%q) [%s] = %v, want %v", tc.status, tc.comment, got, tc.want)
		}
	}
}
