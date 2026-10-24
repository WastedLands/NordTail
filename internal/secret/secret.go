// Package secret holds secret values so they cannot leak through formatting,
// logging, or serialization, and seals them at rest with the operator's
// master key.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const redacted = "[redacted]"

// String is a secret string. Every formatting, logging, and marshaling path
// prints a placeholder; only Reveal returns the value.
type String struct{ v string }

// New wraps s.
func New(s string) String { return String{v: s} }

// Reveal returns the secret value. Call it only at the point of use.
func (s String) Reveal() string { return s.v }

// IsZero reports whether no secret is set.
func (s String) IsZero() bool { return s.v == "" }

func (String) String() string               { return redacted }
func (String) GoString() string             { return redacted }
func (String) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (String) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (String) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (String) LogValue() slog.Value         { return slog.StringValue(redacted) }

// Placeholder reports whether the value is empty or an obvious placeholder.
func (s String) Placeholder() bool {
	switch strings.ToUpper(strings.TrimSpace(s.v)) {
	case "", "REPLACE_ME", "CHANGEME", "CHANGE_ME", "XXX", "TODO":
		return true
	}
	return false
}

// MasterKey seals and opens secrets with AES-256-GCM.
type MasterKey struct{ aead cipher.AEAD }

// ParseMasterKey decodes a base64 32-byte key. Missing, placeholder, wrong
// length, or all-zero keys are rejected: NordTail must not start without a
// real key (hard rule: no master key, no start).
func ParseMasterKey(encoded String) (*MasterKey, error) {
	if encoded.Placeholder() {
		return nil, errors.New("master key is missing or a placeholder")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded.Reveal()))
	if err != nil {
		return nil, errors.New("master key is not valid base64")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(raw))
	}
	zero := true
	for _, b := range raw {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, errors.New("master key is all zeros")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MasterKey{aead: aead}, nil
}

// Seal encrypts s; aad binds the ciphertext to its context (e.g. a row ID),
// so sealed values can't be swapped between records.
func (k *MasterKey) Seal(s String, aad string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, []byte(s.v), []byte(aad)), nil
}

// Open decrypts a value produced by Seal with the same aad.
func (k *MasterKey) Open(sealed []byte, aad string) (String, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n {
		return String{}, errors.New("sealed value too short")
	}
	pt, err := k.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
	if err != nil {
		return String{}, errors.New("cannot open sealed value (wrong master key or tampered data)")
	}
	return String{v: string(pt)}, nil
}
