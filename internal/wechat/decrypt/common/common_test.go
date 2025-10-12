package common

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func TestEncryptDecryptPageRoundTrip(t *testing.T) {
	const (
		pageSize = 4096
		hmacSize = 20
		pageNum  = int64(1)
	)

	reserve := IVSize + hmacSize
	if reserve%AESBlockSize != 0 {
		reserve = ((reserve / AESBlockSize) + 1) * AESBlockSize
	}

	dataLen := pageSize - reserve
	if dataLen%AESBlockSize != 0 {
		t.Fatalf("data length %d must be aligned to AES block size", dataLen)
	}

	message := []byte("round-trip message for encrypt/decrypt test")

	plainPage := make([]byte, pageSize)
	copy(plainPage, message)

	iv := bytes.Repeat([]byte{0x11}, IVSize)
	copy(plainPage[pageSize-reserve:], iv)

	encKey := bytes.Repeat([]byte{0x42}, KeySize)
	macKey := bytes.Repeat([]byte{0x24}, KeySize)

	encryptedPage, err := EncryptPage(plainPage, encKey, macKey, pageNum, sha1.New, hmacSize, reserve, pageSize)
	if err != nil {
		t.Fatalf("EncryptPage failed: %v", err)
	}

	decryptedPage, err := DecryptPage(encryptedPage, encKey, macKey, pageNum, sha1.New, hmacSize, reserve, pageSize)
	if err != nil {
		t.Fatalf("DecryptPage failed: %v", err)
	}

	if !bytes.Equal(decryptedPage[:dataLen], plainPage[:dataLen]) {
		t.Fatalf("decrypted data mismatch: got %x, want %x", decryptedPage[:dataLen], plainPage[:dataLen])
	}

	if !bytes.Equal(decryptedPage[pageSize-reserve:pageSize-reserve+IVSize], iv) {
		t.Fatalf("iv mismatch: got %x, want %x", decryptedPage[pageSize-reserve:pageSize-reserve+IVSize], iv)
	}
}
