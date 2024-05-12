package hkdf

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// HashFunction represents the type of hash function to use.
type HashFunction int

const (
	SHA1 HashFunction = iota
	SHA256
	SHA512
)

// HKDF represents the HKDF instance with the selected hash function.
type HKDF struct {
	hash     func() hash.Hash
	hashSize int
}

// New creates a new HKDF instance with the specified hash function.
func New(hashFunc HashFunction) (*HKDF, error) {
	var h func() hash.Hash
	var size int

	switch hashFunc {
	case SHA1:
		h = sha1.New
		size = sha1.Size
	case SHA256:
		h = sha256.New
		size = sha256.Size
	case SHA512:
		h = sha512.New
		size = sha512.Size
	default:
		return nil, errors.New("hkdf: unsupported hash function")
	}

	return &HKDF{
		hash:     h,
		hashSize: size,
	}, nil
}

// Extract performs the Extract step of HKDF, returning a pseudorandom key (PRK).
func (hkdf *HKDF) Extract(salt, ikm []byte) []byte {
	if salt == nil || len(salt) == 0 {
		// If salt is not provided, use a string of HashLen zeros.
		salt = make([]byte, hkdf.hashSize)
	}
	mac := hmac.New(hkdf.hash, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// ErrInvalidLength is returned when the desired key length is too long.
var ErrInvalidLength = errors.New("hkdf: desired key length too long")

// Expand performs the Expand step of HKDF, generating the output keying material (OKM).
func (hkdf *HKDF) Expand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("hkdf: invalid desired length")
	}

	maxLength := 255 * hkdf.hashSize
	if length > maxLength {
		return nil, ErrInvalidLength
	}

	t := []byte{}
	okm := []byte{}
	counter := byte(1)

	for len(okm) < length {
		mac := hmac.New(hkdf.hash, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
		counter++
	}

	return okm[:length], nil
}
