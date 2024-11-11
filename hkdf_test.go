package hkdf

import (
	"bytes"
	"crypto/md5"
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
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_SHA256_LongInputs(t *testing.T) {
	hkdfInstance, err := New(SHA256)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f" +
		"404142434445464748494a4b4c4d4e4f")

	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f" +
		"808182838485868788898a8b8c8d8e8f" +
		"909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	length := 82
	expectedOKM, _ := hex.DecodeString("b11e398dc80327a1c8e7f78c596a4934" +
		"4f012eda2d4efad8a050cc4c19afa97c" +
		"59045a99cac7827271cb41c65e590e09" +
		"da3275600c2f09b8367793a9aca3db71" +
		"cc30c58179ec3e87c14c01d5c1f3434f" +
		"1d87")

	okm, err := hkdfInstance.ExtractAndExpand(salt, ikm, info, length)
	if err != nil {
		t.Fatalf("ExtractAndExpand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_SHA256_EmptySaltInfo(t *testing.T) {
	hkdfInstance, err := New(SHA256)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := []byte{} // Empty salt
	info := []byte{} // Empty info
	length := 42

	expectedPRK, _ := hex.DecodeString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
	expectedOKM, _ := hex.DecodeString("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

	// Extract and verify PRK
	prk := hkdfInstance.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK does not match expected value.\nGot:      %x\nExpected: %x", prk, expectedPRK)
	}

	// Expand and verify OKM
	okm, err := hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
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

func TestHKDF_SHA1_LongInputs(t *testing.T) {
	hkdfInstance, err := New(SHA1)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f" +
		"404142434445464748494a4b4c4d4e4f")

	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f" +
		"808182838485868788898a8b8c8d8e8f" +
		"909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	length := 82
	expectedPRK, _ := hex.DecodeString("8adae09a2a307059478d309b26c4115a224cfaf6")
	expectedOKM, _ := hex.DecodeString("0bd770a74d1160f7c9f12cd5912a06eb" +
		"ff6adcae899d92191fe4305673ba2ffe" +
		"8fa3f1a4e5ad79f3f334b3b202b2173c" +
		"486ea37ce3d397ed034c7f9dfeb15c5e" +
		"927336d0441f4c4300e2cff0d0900b52" +
		"d3b4")

	// Extract and verify PRK
	prk := hkdfInstance.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK does not match expected value.\nGot:      %x\nExpected: %x", prk, expectedPRK)
	}

	// Expand and verify OKM
	okm, err := hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_SHA1_EmptySaltInfo(t *testing.T) {
	hkdfInstance, err := New(SHA1)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := []byte{} // Empty salt
	info := []byte{} // Empty info
	length := 42

	expectedPRK, _ := hex.DecodeString("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01")
	expectedOKM, _ := hex.DecodeString("0ac1af7002b3d761d1e55298da9d0506" +
		"b9ae52057220a306e07b6b87e8df21d0" +
		"ea00033de03984d34918")

	// Extract and verify PRK
	prk := hkdfInstance.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK does not match expected value.\nGot:      %x\nExpected: %x", prk, expectedPRK)
	}

	// Expand and verify OKM
	okm, err := hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_SHA1_NoSaltEmptyInfo(t *testing.T) {
	hkdfInstance, err := New(SHA1)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	ikm, _ := hex.DecodeString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
	info := []byte{} // Empty info
	length := 42

	expectedPRK, _ := hex.DecodeString("2adccada18779e7c2077ad2eb19d3f3e731385dd")
	expectedOKM, _ := hex.DecodeString("2c91117204d745f3500d636a62f64f0a" +
		"b3bae548aa53d423b0d1f27ebba6f5e5" +
		"673a081d70cce7acfc48")

	// Extract and verify PRK
	prk := hkdfInstance.Extract(nil, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK does not match expected value.\nGot:      %x\nExpected: %x", prk, expectedPRK)
	}

	// Expand and verify OKM
	okm, err := hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM)
	}
}

func TestHKDF_MD5(t *testing.T) {
	hkdfInstance, err := NewWithHash(md5.New)
	if err != nil {
		t.Fatalf("Failed to create HKDF instance: %v", err)
	}

	// Input data
	ikm, _ := hex.DecodeString("7f5f1374")
	salt, _ := hex.DecodeString("8e94ef805b93e683ff18")
	info, _ := hex.DecodeString("32c92d6798ba9570e29d1a6025c14f59")
	length := 32

	// Expected values
	expectedPRK1, _ := hex.DecodeString("080ed874276c97013ae1154f2a74d573")
	expectedOKM1, _ := hex.DecodeString("4d832f0fa8771759545670776915ead024f365a5e75ec246e767d09ad02ea2ec")

	expectedPRK2, _ := hex.DecodeString("1a7d0678493533a8f091d9914765e51d")
	expectedOKM2, _ := hex.DecodeString("623c9d06e24bd411c1d066d9b6f9297350a3084eec2c5189fccef2caad0b05e2")

	// First set of PRK and OKM checks
	prk := hkdfInstance.Extract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK1) {
		t.Errorf("PRK1 does not match expected value.\nGot:      %x\nExpected: %x", prk, expectedPRK1)
	}

	okm, err := hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed for OKM1: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM1) {
		t.Errorf("OKM1 does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM1)
	}

	// Second set of PRK and OKM checks with modified PRK
	prk = expectedPRK2 // Manually setting PRK to second expected PRK value for the test
	okm, err = hkdfInstance.Expand(prk, info, length)
	if err != nil {
		t.Fatalf("Expand failed for OKM2: %v", err)
	}

	if !bytes.Equal(okm, expectedOKM2) {
		t.Errorf("OKM2 does not match expected value.\nGot:      %x\nExpected: %x", okm, expectedOKM2)
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
