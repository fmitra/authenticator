// Package crypto provides cryptographic utility functions.
package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Bytes returns securely generated random bytes.
func Bytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BytesFromSample returns securely generated random bytes from a string
// sample.
func BytesFromSample(length int, samples ...string) ([]byte, error) {
	sample := strings.Join(samples, "")
	if sample == "" {
		sample = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
			"[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	}

	bytes, err := Bytes(length)
	if err != nil {
		return nil, err
	}
	for i, b := range bytes {
		bytes[i] = sample[b%byte(len(sample))]
	}

	return bytes, nil
}

// String returns a securely generated random string from an optional
// sample.
func String(length int, samples ...string) (string, error) {
	b, err := BytesFromSample(length, samples...)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// StringB64 returns a securely generated random string from an optional
// sample, encoded in base64.
func StringB64(length int, samples ...string) (string, error) {
	b, err := BytesFromSample(length, samples...)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Hash returns a sha512 hash of a string.
func Hash(s string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(s))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
