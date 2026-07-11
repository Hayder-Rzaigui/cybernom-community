package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/hayderrzaigui/cybernom/internal/auth"
	"github.com/hayderrzaigui/cybernom/internal/config"
	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// runInitAdmin implements `cybernom -init-admin`: an interactive, safe
// replacement for the old README instructions that had operators hand-hash
// a password with htpasswd and hand-write an INSERT statement. That path
// invited exactly the mistakes you'd expect — weak passwords with no
// length check, copy-paste hash corruption, and a bootstrap step with zero
// relationship to the app's own validation rules (min password length,
// configured bcrypt cost, username uniqueness).
//
// This command reuses the exact same store.CreateUser / auth.HashPassword
// path the authenticated POST /api/v1/users endpoint uses, so "the first
// admin" and "every admin after that" go through identical validation.
func runInitAdmin(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// This timeout covers only the initial connectivity check — it must
	// NOT span the interactive prompts below. A human can easily take
	// longer than 15s to type a username and a password twice, and this
	// same ctx used to be reused for the later DB calls too, so a normal
	// amount of typing time could make GetUserByUsername/CreateUser fail
	// with "context deadline exceeded" even though the database was fine.
	openCtx, openCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer openCancel()

	store, err := storage.Open(openCtx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer store.Close()

	fmt.Println("CyberNom — create initial admin account")
	fmt.Println("(this can also be used later to create additional admins offline)")
	fmt.Println()

	username, err := promptUsername()
	if err != nil {
		return err
	}

	// Fresh, short-lived contexts for each DB call, started only after the
	// relevant prompt has already completed — so time spent waiting on
	// human input is never counted against them.
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer lookupCancel()
	if _, err := store.GetUserByUsername(lookupCtx, username); err == nil {
		return fmt.Errorf("a user named %q already exists", username)
	}

	password, err := promptPassword()
	if err != nil {
		return err
	}

	hash, err := auth.HashPassword(password, cfg.Auth.BcryptCost)
	if err != nil {
		// Same validation the API endpoint enforces (e.g. minimum length) —
		// surfaced here instead of silently accepting a weak password.
		return fmt.Errorf("password rejected: %w", err)
	}

	createCtx, createCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer createCancel()
	user, err := store.CreateUser(createCtx, username, hash, "admin")
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}

	fmt.Printf("\nCreated admin user %q (id: %s). You can now sign in at /dashboard.\n", user.Username, user.ID)
	return nil
}

func promptUsername() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Username: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading username: %w", err)
		}
		username := strings.TrimSpace(line)
		if username == "" {
			fmt.Println("Username cannot be empty.")
			continue
		}
		return username, nil
	}
}

// promptPassword reads a password twice with terminal echo disabled (via
// golang.org/x/term) so it never appears on-screen, in shell history, or in
// process listings the way `htpasswd -bnBC 12 "" 'password'` would.
func promptPassword() (string, error) {
	for {
		fmt.Print("Password (min 12 characters, input hidden): ")
		pw1, err := readHiddenLine()
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		fmt.Print("Confirm password: ")
		pw2, err := readHiddenLine()
		if err != nil {
			return "", fmt.Errorf("reading password confirmation: %w", err)
		}

		if pw1 != pw2 {
			fmt.Println("Passwords did not match, try again.")
			continue
		}
		if len(pw1) < 12 {
			fmt.Println("Password must be at least 12 characters, try again.")
			continue
		}
		return pw1, nil
	}
}

func readHiddenLine() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Non-interactive stdin (e.g. piped input in a test/CI context) —
		// fall back to a plain line read rather than hanging on a
		// terminal-only syscall.
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, os.ErrClosed) {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	bytePw, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePw)), nil
}
