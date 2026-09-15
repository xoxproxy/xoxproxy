// Package threeproxy implements the engine provider for 3proxy:
// configuration rendering, atomic deploy with SIGUSR1 reload, and
// traffic-log parsing. Behavior verified against the 3proxy 0.9 source
// and utilities — see docs/SPIKE-3PROXY.md.
package threeproxy

import (
	"crypto/rand"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// CRHash renders password and salt into 3proxy's BLAKE2b-crypt verifier
// format ("CR" password type): $3$<salt>$<22 chars>.
//
// Algorithm (verified against upstream src/3proxy_crypt.c and the
// vectors in crypt_test.go): a 16-byte unkeyed BLAKE2b digest over the
// password bytes INCLUDING the terminating NUL, followed by the salt
// bytes with no terminator, then the traditional crypt base64 alphabet
// in the MD5-crypt arrangement.
//
// The engine config therefore never contains a plaintext (or
// derivably-reversible) password; the control plane keeps its own
// argon2id hash separately.
func CRHash(password, salt string) string {
	h, err := blake2b.New(16, nil) // unkeyed BLAKE2b-128; never fails for size 16
	if err != nil {
		panic("threeproxy: blake2b init: " + err.Error())
	}
	h.Write([]byte(password))
	h.Write([]byte{0}) // the C code hashes strlen(pw)+1 bytes
	h.Write([]byte(salt))
	return "$3$" + salt + "$" + cryptB64(h.Sum(nil))
}

// cryptB64 encodes the 16 digest bytes exactly as 3proxy's mycrypt does
// (src/3proxy_crypt.c): three-byte big-endian groups in the order
// [0,6,12] [1,7,13] [2,8,14] [3,9,15] [4,10,5] plus a final two-char
// group from byte 11.
func cryptB64(f []byte) string {
	const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	put := func(v uint32, n int) {
		for i := 0; i < n; i++ {
			b.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	put(uint32(f[0])<<16|uint32(f[6])<<8|uint32(f[12]), 4)
	put(uint32(f[1])<<16|uint32(f[7])<<8|uint32(f[13]), 4)
	put(uint32(f[2])<<16|uint32(f[8])<<8|uint32(f[14]), 4)
	put(uint32(f[3])<<16|uint32(f[9])<<8|uint32(f[15]), 4)
	put(uint32(f[4])<<16|uint32(f[10])<<8|uint32(f[5]), 4)
	put(uint32(f[11]), 2)
	return b.String()
}

// saltAlphabet is restricted to bytes with no meaning in 3proxy config
// syntax (no '$', ':', '"', whitespace, '#').
const saltAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// saltMaxLen matches 3proxy_crypt's 64-character salt limit.
const saltMaxLen = 64

// NewSalt returns a random salt safe for embedding in a config file.
func NewSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("threeproxy: salt: %w", err)
	}
	for i, b := range buf {
		buf[i] = saltAlphabet[int(b)%len(saltAlphabet)]
	}
	return string(buf), nil
}

// NewEngineHash derives a fresh engine verifier for a password: a new
// random salt plus the CR hash. This is the value stored alongside the
// user and rendered into the engine config.
func NewEngineHash(password string) (string, error) {
	salt, err := NewSalt()
	if err != nil {
		return "", err
	}
	return CRHash(password, salt), nil
}
