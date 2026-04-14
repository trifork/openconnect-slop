// export_test.go exposes internal functions for white-box testing.
// This file is only compiled during tests.
package saml

// ParseFormForTest exposes parseForm for tests.
func ParseFormForTest(body []byte, baseURL string) (*Form, error) {
	return parseForm(body, baseURL)
}

// ParseSAMLResponseFormForTest exposes parseSAMLResponseForm for tests.
func ParseSAMLResponseFormForTest(body []byte, baseURL string) (*Form, error) {
	return parseSAMLResponseForm(body, baseURL)
}

// LooksLikeJSPollingForTest exposes looksLikeJSPollingVerbose for tests.
func LooksLikeJSPollingForTest(body []byte) bool {
	return looksLikeJSPollingVerbose(body) != ""
}

// DetectParkingURLForTest exposes detectParkingURL for tests.
func DetectParkingURLForTest(body []byte, form *Form) string {
	return detectParkingURL(body, form)
}

// IsParkingResolvedForTest exposes isParkingResolved for tests.
func IsParkingResolvedForTest(status string) bool {
	return isParkingResolved(status)
}

// ExtractParkingStatusForTest exposes extractParkingStatus for tests.
func ExtractParkingStatusForTest(body string) string {
	return extractParkingStatus(body)
}
