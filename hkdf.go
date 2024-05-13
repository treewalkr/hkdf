package hkdf

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
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

// ExtractAndExpand is a convenience function that performs both Extract and Expand steps.
func (hkdf *HKDF) ExtractAndExpand(salt, ikm, info []byte, length int) ([]byte, error) {
	prk := hkdf.Extract(salt, ikm)
	return hkdf.Expand(prk, info, length)
}

// Reader is an io.Reader that implements the HKDF expand operation.
// It allows streaming the derived key material.
type Reader struct {
	hkdf      *HKDF
	prk       []byte
	info      []byte
	length    int
	remaining int
	t         []byte
	counter   byte
	buffer    []byte
}

// NewReader creates a new HKDF Reader.
func (hkdf *HKDF) NewReader(prk, info []byte, length int) *Reader {
	return &Reader{
		hkdf:      hkdf,
		prk:       prk,
		info:      info,
		length:    length,
		remaining: length,
		counter:   1,
	}
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}

	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}

	result := p[:n]
	for i := 0; i < n; i++ {
		if len(r.buffer) == 0 {
			mac := hmac.New(r.hkdf.hash, r.prk)
			mac.Write(r.t)
			mac.Write(r.info)
			mac.Write([]byte{r.counter})
			r.t = mac.Sum(nil)
			r.counter++
			r.buffer = r.t
		}
		result[i] = r.buffer[0]
		r.buffer = r.buffer[1:]
		r.remaining--
	}

	return n, nil
}
