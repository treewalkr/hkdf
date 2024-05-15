package hkdf

import (
	"testing"
)

func TestHKDF_Extract(t *testing.T) {
	hkdf, err := New(SHA256)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm := []byte("input key material")
	salt := []byte("salt value")
	prk := hkdf.Extract(salt, ikm)

	if len(prk) != hkdf.hashSize {
		t.Errorf("PRK length incorrect. Expected %d, got %d", hkdf.hashSize, len(prk))
	}
}

func TestHKDF_Expand(t *testing.T) {
	hkdf, err := New(SHA256)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	prk := make([]byte, hkdf.hashSize)
	info := []byte("info")
	length := 32
	okm, err := hkdf.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if len(okm) != length {
		t.Errorf("OKM length incorrect. Expected %d, got %d", length, len(okm))
	}
}
