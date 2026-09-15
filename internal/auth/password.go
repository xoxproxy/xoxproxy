// Package auth implements admin authentication: argon2id password hashing,
// server-side sessions, login with account lockout and per-IP throttling,
// and credential generation. It is deliberately provider-shaped: the
// password and session primitives are independent so TOTP/passkeys can be
// layered without touching session storage.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP-recommended class for server-side hashing,
// sized for a 1 GB VPS: ~64 MiB per hash, acceptable for the low frequency
// of admin logins).
const (
	argon2MemoryKiB = 64 * 1024
	argon2Time      = 3
	argon2Threads   = 2
	argon2KeyLen    = 32
	argon2SaltLen   = 16
)

// HashPassword derives an argon2id hash in PHC string format:
// $argon2id$v=19$m=65536,t=3,p=2$<salt b64>$<key b64>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2MemoryKiB, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches a PHC-format hash
// produced by HashPassword (or any argon2id hash with embedded parameters).
// It returns false, not an error, for malformed hashes: a corrupt hash must
// never become a login outage or a 500.
func VerifyPassword(password, encoded string) (bool, error) {
	params, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return false, nil
	}
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeArgon2id(encoded string) (argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argon2Params{}, nil, nil, errors.New("auth: not an argon2id PHC hash")
	}
	var p argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: bad argon2 params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: bad salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: bad key: %w", err)
	}
	return p, salt, key, nil
}

// Password policy. Length-first (NIST SP 800-63B guidance): no composition
// rules, but reject username echoes and trivially guessable values.
const (
	MinPasswordLength = 12
	// GeneratedPasswordLength exceeds policy with margin; 20 chars from a
	// 54-char alphabet ≈ 115 bits of entropy.
	GeneratedPasswordLength = 20
)

// ErrWeakPassword explains why a candidate password was rejected.
var ErrWeakPassword = errors.New("password does not meet policy")

// commonPasswords are the values that must never be admin passwords no
// matter the length rules.
var commonPasswords = map[string]struct{}{
	"password": {}, "passphrase": {}, "qwertyuiop": {}, "asdfghjkl": {},
	"zxcvbnm": {}, "123456789012": {}, "letmein": {}, "administrator": {},
	"changeme": {}, "xoxproxy": {}, "proxyadmin": {}, "secret": {},
}

// ValidatePasswordPolicy checks a candidate admin password. username is
// used for similarity rejection and may be empty for generated values
// (which pass by construction but are checked anyway for defense in depth).
func ValidatePasswordPolicy(password, username string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, MinPasswordLength)
	}
	lower := strings.ToLower(password)
	// Substring match, not exact: "passwordpassword" and "my-secret-secret"
	// are exactly as guessable as the base words.
	for common := range commonPasswords {
		if strings.Contains(lower, common) {
			return fmt.Errorf("%w: this password contains a commonly guessed word", ErrWeakPassword)
		}
	}
	if username != "" {
		u := strings.ToLower(username)
		if len(u) >= 3 && strings.Contains(lower, u) {
			return fmt.Errorf("%w: must not contain the username", ErrWeakPassword)
		}
	}
	return nil
}

// passwordAlphabet excludes visually ambiguous characters (0/O, 1/l/I) so
// generated credentials can be transcribed from a terminal without error.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns a cryptographically random password. It is the
// only approved source of proxy-user and initial admin credentials.
func GeneratePassword() string {
	b := make([]byte, GeneratedPasswordLength)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is fatal for credential generation: returning
		// a fallback would be a vulnerability, so panic and fail closed.
		panic("auth: entropy source unavailable: " + err.Error())
	}
	out := make([]byte, GeneratedPasswordLength)
	for i, v := range b {
		out[i] = passwordAlphabet[int(v)%len(passwordAlphabet)]
	}
	return string(out)
}
