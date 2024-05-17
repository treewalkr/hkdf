package hkdf

import (
	"bytes"
	"encoding/hex"
	"io"
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

func TestHKDF_SHA256(t *testing.T) {
	// Test vectors from RFC 5869

	// Test Case 1
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	length := 42
	expectedOKM, _ := hex.DecodeString(
		"3cb25f25faacd57a90434f64d0362f2a" +
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
			"34007208d5b887185865")

	hkdf, err := New(SHA256)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	okm, err := hkdf.ExtractAndExpand(salt, ikm, info, length)
	if err != nil {
		t.Fatalf("ExtractAndExpand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot: %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_SHA1(t *testing.T) {
	// Test vectors from RFC 5869

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	length := 42
	expectedOKM, _ := hex.DecodeString(
		"085a01ea1b10f36933068b56efa5ad81" +
			"a4f14b822f5b091568a9cdd4f155fda2" +
			"c22e422478d305f3f896")

	hkdfInstance, err := New(SHA1)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	okm, err := hkdfInstance.ExtractAndExpand(salt, ikm, info, length)
	if err != nil {
		t.Fatalf("ExtractAndExpand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_ExpandError(t *testing.T) {
	hkdf, _ := New(SHA256)
	prk := make([]byte, hkdf.hashSize)
	info := []byte("info")
	length := 255*hkdf.hashSize + 1

	_, err := hkdf.Expand(prk, info, length)
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestHKDF_Reader(t *testing.T) {
	hkdf, _ := New(SHA256)
	prk := hkdf.Extract([]byte{0x00}, []byte("input key material"))
	info := []byte("info")
	length := 64

	reader := hkdf.NewReader(prk, info, length)
	derived := make([]byte, length)
	n, err := reader.Read(derived)
	if err != nil && err != io.EOF {
		t.Fatalf("Reader failed: %v", err)
	}
	if n != length {
		t.Fatalf("Expected to read %d bytes, got %d", length, n)
	}

	// Ensure deterministic output by re-computing
	okm, err := hkdf.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !bytes.Equal(derived, okm) {
		t.Errorf("Derived key does not match expected OKM.")
	}
}
