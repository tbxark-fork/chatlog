package windows

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
)

func TestV4EncryptorRoundTrip(t *testing.T) {
	encryptor := NewV4Encryptor()
	decryptor := NewV4Decryptor()

	keyBytes := bytes.Repeat([]byte{0x11}, common.KeySize)
	hexKey := hex.EncodeToString(keyBytes)

	pageSize := encryptor.GetPageSize()
	reserve := encryptor.GetReserve()

	totalPages := 3
	plainBytes := make([]byte, pageSize*totalPages)

	copy(plainBytes[:len(common.SQLiteHeader)], []byte(common.SQLiteHeader))

	for i := len(common.SQLiteHeader); i < pageSize; i++ {
		plainBytes[i] = byte((i + 37) % 251)
	}

	for i := 0; i < pageSize; i++ {
		plainBytes[pageSize+i] = byte((i + 91) % 251)
	}

	plainFile, err := os.CreateTemp(t.TempDir(), "plain-*.db")
	if err != nil {
		t.Fatalf("failed to create temp plain db: %v", err)
	}
	if _, err := plainFile.Write(plainBytes); err != nil {
		t.Fatalf("failed to write plain db: %v", err)
	}
	if err := plainFile.Close(); err != nil {
		t.Fatalf("failed to close plain db: %v", err)
	}

	var encBuf bytes.Buffer
	if err := encryptor.Encrypt(context.Background(), plainFile.Name(), hexKey, &encBuf); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	encFile, err := os.CreateTemp(t.TempDir(), "enc-*.db")
	if err != nil {
		t.Fatalf("failed to create temp encrypted db: %v", err)
	}
	if _, err := encFile.Write(encBuf.Bytes()); err != nil {
		t.Fatalf("failed to write encrypted db: %v", err)
	}
	if err := encFile.Close(); err != nil {
		t.Fatalf("failed to close encrypted db: %v", err)
	}

	var decBuf bytes.Buffer
	if err := decryptor.Decrypt(context.Background(), encFile.Name(), hexKey, &decBuf); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted := decBuf.Bytes()
	if len(decrypted) != len(plainBytes) {
		t.Fatalf("unexpected decrypted length: got %d, want %d", len(decrypted), len(plainBytes))
	}

	if !bytes.Equal(decrypted[:len(common.SQLiteHeader)], plainBytes[:len(common.SQLiteHeader)]) {
		t.Fatalf("sqlite header mismatch")
	}

	page0DataLen := pageSize - len(common.SQLiteHeader) - reserve
	if !bytes.Equal(decrypted[len(common.SQLiteHeader):len(common.SQLiteHeader)+page0DataLen], plainBytes[len(common.SQLiteHeader):len(common.SQLiteHeader)+page0DataLen]) {
		t.Fatalf("page 0 data mismatch")
	}

	for page := 1; page < totalPages; page++ {
		start := page * pageSize
		if !bytes.Equal(decrypted[start:start+pageSize-reserve], plainBytes[start:start+pageSize-reserve]) {
			t.Fatalf("page %d data mismatch", page)
		}
	}
}
