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