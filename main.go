package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"openconnect-slop/internal/asa"
	"openconnect-slop/internal/auth"
	"openconnect-slop/internal/config"
	"openconnect-slop/internal/saml"
)

// Build-time variables injected via -ldflags -X.
// Default values are used for dev builds without the flags.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func versionString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, buildDate)
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		debug      bool
		username   string
		authGroup  string
		authMode   string
		totpSecret string
		acVersion  string
	)

	cmd := &cobra.Command{
		Use:   "openconnect-slop [flags] <vpn-host>",
		Short: "Headless VPN authentication for Cisco AnyConnect + SafeNet STA",
		Long: `openconnect-slop authenticates to a Cisco AnyConnect VPN via SafeNet STA SAML SSO
and prints eval-able credentials to stdout:

  COOKIE=<session-token>
  HOST=<host>
  FINGERPRINT=pin-sha256:<hash>

Usage with openconnect:

  eval $(openconnect-slop vpn.company.com)
  sudo openconnect --cookie-on-stdin --servercert "$FINGERPRINT" "$HOST" <<< "$COOKIE"`,
		Version:      versionString(),
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if totpSecret != "" {
				fmt.Fprintln(os.Stderr, "WARNING: --totp-secret on command line is visible in process list and shell history")
			}

			level := slog.LevelInfo
			if v := os.Getenv("LOG_LEVEL"); v != "" {
				switch strings.ToLower(v) {
				case "debug":
					level = slog.LevelDebug
				case "warn":
					level = slog.LevelWarn
				case "error":
					level = slog.LevelError
				}
			}
			if debug {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			log.Debug("openconnect-slop starting", "version", versionString())

			overrides := config.Config{
				Username:   username,
				AuthGroup:  authGroup,
				AuthMode:   authMode,
				TOTPSecret: totpSecret,
				ACVersion:  acVersion,
			}
			cfg, err := config.LoadWithOverrides(overrides)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			log.Debug("config loaded",
				"username", cfg.Username,
				"auth_mode", cfg.AuthMode,
				"auth_group", cfg.AuthGroup,
				"ac_version", cfg.ACVersion,
				"totp_secret_set", cfg.TOTPSecret != "",
			)

			return run(log, args[0], cfg)
		},
	}

	cmd.Flags().BoolVarP(&debug, "debug", "v", false, "Enable verbose debug logging")
	cmd.Flags().StringVarP(&username, "username", "u", "", "VPN username (overrides config)")
	cmd.Flags().StringVar(&authGroup, "auth-group", "", "VPN tunnel group (overrides config)")
	cmd.Flags().StringVar(&authMode, "auth-mode", "", "Auth mode: totp | totp-prompt | push (overrides config)")
	cmd.Flags().StringVar(&totpSecret, "totp-secret", "", "TOTP secret base32 (overrides config; WARNING: visible in process list)")
	cmd.Flags().StringVar(&acVersion, "ac-version", "", "AnyConnect version string (overrides config)")

	return cmd
}

func run(log *slog.Logger, host string, cfg *config.Config) error {
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	log.Info("openconnect-slop starting", "version", versionString(), "host", host)

	// Step 1: detect the AnyConnect XML auth endpoint.
	authURL, err := asa.DetectAuthURL(host, log)
	if err != nil {
		return fmt.Errorf("detecting auth URL: %w", err)
	}

	// Step 2: XML auth-init — get SAML login URL, login-final URL, token cookie name.
	initResult, err := asa.AuthInit(authURL, cfg.AuthGroup, cfg.ACVersion, log)
	if err != nil {
		return fmt.Errorf("AnyConnect auth-init: %w", err)
	}

	// Step 3: SAML authentication → SSO token.
	authenticator, err := saml.New(cfg.Username, log)
	if err != nil {
		return fmt.Errorf("creating SAML authenticator: %w", err)
	}

	ssoToken, err := authenticate(authenticator, cfg, initResult, log)
	if err != nil {
		return fmt.Errorf("SAML authentication: %w", err)
	}

	// Step 4: XML auth-reply — exchange SSO token for session credentials.
	result, err := asa.AuthReply(initResult, ssoToken, cfg.ACVersion, log)
	if err != nil {
		return fmt.Errorf("AnyConnect auth-reply: %w", err)
	}

	// Step 5: print eval-able output for the calling shell / openconnect.
	bareHost := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	fingerprint := result.ServerCertHash
	if fingerprint == "" {
		fingerprint = asa.GetServerCertHash(host, log)
	}
	fmt.Printf("COOKIE=%s\n", result.SessionToken)
	fmt.Printf("HOST=%s\n", bareHost)
	fmt.Printf("FINGERPRINT=%s\n", fingerprint)

	log.Info("authentication complete — credentials printed to stdout")
	return nil
}

// authenticate performs the SAML flow (TOTP or push) and returns the SSO token.
func authenticate(a *saml.Authenticator, cfg *config.Config, init *asa.InitResult, log *slog.Logger) (string, error) {
	switch cfg.AuthMode {
	case config.AuthModeTOTP:
		return runTOTP(a, cfg, init, log)
	case config.AuthModeTOTPPrompt:
		return runTOTPPrompt(a, init, log)
	case config.AuthModePush:
		return runPush(a, init, log)
	default:
		return "", fmt.Errorf("unknown auth_mode %q", cfg.AuthMode)
	}
}

func runTOTP(a *saml.Authenticator, cfg *config.Config, init *asa.InitResult, log *slog.Logger) (string, error) {
	log.Debug("generating TOTP code")
	code, err := auth.TOTP(cfg.TOTPSecret)
	if err != nil {
		return "", err
	}
	log.Debug("TOTP code generated (not logged for security)")
	return a.AuthenticateTOTP(init.SSOLoginURL, init.LoginFinalURL, init.TokenCookieName, code)
}

func runTOTPPrompt(a *saml.Authenticator, init *asa.InitResult, log *slog.Logger) (string, error) {
	// Open /dev/tty directly so the prompt reaches the terminal even when
	// stderr is redirected (e.g. 2>debug.txt). Same pattern as ssh/gpg.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Fallback: stderr (works when not redirected)
		tty = os.Stderr
	} else {
		defer tty.Close()
	}
	fmt.Fprint(tty, "Enter TOTP code: ")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			codeCh <- strings.TrimSpace(scanner.Text())
		} else if err := scanner.Err(); err != nil {
			errCh <- err
		} else {
			errCh <- fmt.Errorf("stdin closed without input")
		}
	}()

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return "", fmt.Errorf("reading TOTP code: %w", err)
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for TOTP code (60s)")
	}

	log.Debug("TOTP code read from stdin (not logged for security)")
	return a.AuthenticateTOTP(init.SSOLoginURL, init.LoginFinalURL, init.TokenCookieName, code)
}

func runPush(a *saml.Authenticator, init *asa.InitResult, log *slog.Logger) (string, error) {
	// Strategy A: pure HTTP polling — no browser needed if STA serves
	// plain HTML responses while waiting for push approval.
	log.Debug("attempting push strategy A (HTTP polling)")
	token, err := a.AuthenticatePush(init.SSOLoginURL, init.LoginFinalURL, init.TokenCookieName)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, saml.ErrPushNeedsChromedp) {
		return "", err
	}

	// Strategy B: headless Chromium via chromedp.
	// Handles JS-driven push polling. Requires Chromium installed;
	// does NOT require a display server.
	log.Info("strategy A requires JavaScript — falling back to chromedp (headless Chromium)")
	return a.AuthenticatePushChromedp(init.SSOLoginURL, init.LoginFinalURL, init.TokenCookieName)
}
