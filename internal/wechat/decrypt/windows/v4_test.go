package windows

import (
	"context"
	"os"
	"testing"
)

func TestV4Decryptor_Decrypt(t *testing.T) {
	hexKey := ""
	db := `C:\Users\Docker\Documents\xwechat_files\XXX\db_storage\message\message_0.db`
	dbDec := `message_0_dec.db`
	decryptor := NewV4Decryptor()
	file, err := os.Create(dbDec)
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()
	err = decryptor.Decrypt(context.Background(), db, hexKey, file)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	_ = file.Sync()

}

func TestV4V4Encryptor_Encrypt(t *testing.T) {
	hexKey := ""
	dbDec := `message_0_dec.db`
	reEnc := `message_0.db`
	encryptor := NewV4Encryptor()
	file, err := os.Create(reEnc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = file.Close()
	}()
	err = encryptor.Encrypt(context.Background(), dbDec, hexKey, file)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Sync()
}
