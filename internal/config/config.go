// Package config loads and validates openconnect-slop configuration.
// Config file location: ~/.config/openconnect-slop/config.toml
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration structure.
type Config struct {
	Username   string `toml:"username"`
	TOTPSecret string `toml:"totp_secret"` // base32-encoded TOTP seed
	AuthMode   string `toml:"auth_mode"`   // "totp" or "push"
	AuthGroup  string `toml:"auth_group"`  // VPN tunnel group name (e.g. "webvpn-vpn01-safenet")
	ACVersion  string `toml:"ac_version"`  // AnyConnect version string, default "4.7.00136"
}

// DefaultACVersion is the AnyConnect client version advertised to the server.
const DefaultACVersion = "4.7.00136"

// AuthModeTOTP, AuthModeTOTPPrompt and AuthModePush are the valid auth_mode values.
const (
	AuthModeTOTP       = "totp"
	AuthModeTOTPPrompt = "totp-prompt"
	AuthModePush       = "push"
)

// Load reads the config file from the standard XDG location with no overrides.
func Load() (*Config, error) {
	return LoadWithOverrides(Config{})
}

// LoadWithOverrides loads config from the file (if it exists) and then applies
// any non-zero values from overrides. CLI flag values should be passed here so
// they take precedence over the config file. Required fields may be satisfied
// entirely by overrides — the config file is optional when overrides supply all
// required values.
func LoadWithOverrides(overrides Config) (*Config, error) {
	cfg := &Config{}

	path, pathErr := configPath()
	if pathErr == nil {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if _, err := toml.Decode(string(data), cfg); err != nil {
				return nil, fmt.Errorf("parsing config: %w", err)
			}
		case errors.Is(err, os.ErrNotExist):
			// Config file is optional when CLI overrides supply required values.
		default:
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	// Apply non-zero CLI overrides on top of file config.
	if overrides.Username != "" {
		cfg.Username = overrides.Username
	}
	if overrides.TOTPSecret != "" {
		cfg.TOTPSecret = overrides.TOTPSecret
	}
	if overrides.AuthMode != "" {
		cfg.AuthMode = overrides.AuthMode
	}
	if overrides.AuthGroup != "" {
		cfg.AuthGroup = overrides.AuthGroup
	}
	if overrides.ACVersion != "" {
		cfg.ACVersion = overrides.ACVersion
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	if c.AuthGroup == "" {
		return errors.New("auth_group is required (e.g. \"webvpn-vpn01-safenet\")")
	}
	if c.AuthMode == "" {
		c.AuthMode = AuthModeTOTP
	}
	if c.AuthMode != AuthModeTOTP && c.AuthMode != AuthModeTOTPPrompt && c.AuthMode != AuthModePush {
		return fmt.Errorf("auth_mode must be %q, %q, or %q, got %q", AuthModeTOTP, AuthModeTOTPPrompt, AuthModePush, c.AuthMode)
	}
	if c.AuthMode == AuthModeTOTP && c.TOTPSecret == "" {
		return errors.New("totp_secret is required when auth_mode = \"totp\"")
	}
	if c.ACVersion == "" {
		c.ACVersion = DefaultACVersion
	}
	return nil
}

func configPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating config dir: %w", err)
	}
	return filepath.Join(cfgDir, "openconnect-slop", "config.toml"), nil
}
