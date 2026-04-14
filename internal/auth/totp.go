// Package auth generates TOTP codes from a stored secret.
package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// TOTP generates the current TOTP code from a base32-encoded secret.
func TOTP(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("generating TOTP code: %w", err)
	}
	return code, nil
}
