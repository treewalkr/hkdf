# HKDF Library for Go

This library provides an implementation of the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in [RFC 5869](https://tools.ietf.org/html/rfc5869). HKDF is a simple and secure key derivation function built on HMAC (Hash-based Message Authentication Code), allowing you to derive cryptographically secure keys from initial keying material (IKM).

## Features

- **Hash Support**: Includes support for `SHA1`, `SHA256`, and `SHA512`.
- **Flexible Interface**: Provides methods to perform the `Extract` and `Expand` steps independently, as well as a combined `ExtractAndExpand` method.
- **Streamed Output**: Supports streaming output with an `io.Reader`-compatible `HKDF.Reader` for applications needing progressive key material generation.

## Installation

```bash
go get github.com/treewalkr/hkdf
```

## Getting Started
### Import the Library

```go
import "github.com/treewalkr/hkdf"
```

### Basic Usage Example
```go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/treewalkr/hkdf"
)

func main() {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	length := 42

	hkdfInstance, err := hkdf.New(hkdf.SHA256)
	if err != nil {
		log.Fatalf("Failed to create HKDF instance: %v", err)
	}

	okm, err := hkdfInstance.ExtractAndExpand(salt, ikm, info, length)
	if err != nil {
		log.Fatalf("HKDF failed: %v", err)
	}

	fmt.Printf("Derived Key (OKM): %x\n", okm)
}
```

Output:

```
Derived Key (OKM): 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
```

### Streaming Output Using `Reader`
```go
reader := hkdfInstance.NewReader(prk, info, length)
derived := make([]byte, length)
_, err := reader.Read(derived)
if err != nil {
	log.Fatalf("Failed to read derived key: %v", err)
}
fmt.Printf("Derived Key (OKM): %x\n", derived)
```

## API Reference
### `NEW`
```go
func New(hashFunc HashFunction) (*HKDF, error)
```
Creates a new HKDF instance with the specified hash function. Supported hash functions are `SHA1`, `SHA256`, and `SHA512`.

### `Extract`
```go
func (hkdf *HKDF) Extract(salt, ikm []byte) []byte
```
Extracts a pseudorandom key (PRK) from the input keying material (IKM) and `salt`. If salt is empty or `nil`, a zeroed string of length equal to the hash output is used as salt.

### `Expand`
```go
func (hkdf *HKDF) Expand(prk, info []byte, length int) ([]byte, error)
```
Expands the PRK to the desired output length using optional context information (`info`). Returns an error if `length` is greater than the maximum allowed length (255 * hash output size).

### `ExtractAndExpand`
```go
func (hkdf *HKDF) ExtractAndExpand(salt, ikm, info []byte, length int) ([]byte, error)
```
Convenience function that combines `Extract` and `Expand` steps to produce the output keying material (OKM).

### `Reader`
```go
func (hkdf *HKDF) NewReader(prk, info []byte, length int) *Reader
```
Creates a new `Reader` that can be used to stream output keying material.
