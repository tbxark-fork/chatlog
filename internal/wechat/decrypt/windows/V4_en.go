package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"

	"golang.org/x/crypto/pbkdf2"
)

type V4Encryptor struct {
	iterCount int
	hmacSize  int
	hashFunc  func() hash.Hash
	reserve   int
	pageSize  int
	version   string
}

func NewV4Encryptor() *V4Encryptor {
	hashFunc := sha512.New
	hmacSize := HmacSHA512Size
	reserve := common.IVSize + hmacSize
	if reserve%common.AESBlockSize != 0 {
		reserve = ((reserve / common.AESBlockSize) + 1) * common.AESBlockSize
	}

	return &V4Encryptor{
		iterCount: V4IterCount,
		hmacSize:  hmacSize,
		hashFunc:  hashFunc,
		reserve:   reserve,
		pageSize:  PageSize,
		version:   "Windows v4",
	}
}

func (e *V4Encryptor) deriveKeys(key []byte, salt []byte) ([]byte, []byte) {
	encKey := pbkdf2.Key(key, salt, e.iterCount, common.KeySize, e.hashFunc)

	macSalt := common.XorBytes(salt, 0x3a)
	macKey := pbkdf2.Key(encKey, macSalt, 2, common.KeySize, e.hashFunc)

	return encKey, macKey
}

func (e *V4Encryptor) Encrypt(ctx context.Context, plainDB string, hexKey string, output io.Writer) error {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return errors.DecodeKeyFailed(err)
	}
	if len(key) != common.KeySize {
		return fmt.Errorf("invalid key length: expected %d, got %d", common.KeySize, len(key))
	}

	plainFile, err := os.Open(plainDB)
	if err != nil {
		return errors.OpenFileFailed(plainDB, err)
	}
	defer plainFile.Close()

	if _, err := plainFile.Stat(); err != nil {
		return errors.StatFileFailed(plainDB, err)
	}

	header := make([]byte, len(common.SQLiteHeader))
	if _, err := io.ReadFull(plainFile, header); err != nil {
		return errors.ReadFileFailed(plainDB, err)
	}
	if !bytes.Equal(header, []byte(common.SQLiteHeader)) {
		return fmt.Errorf("invalid sqlite header")
	}

	firstPayload := make([]byte, e.pageSize-len(common.SQLiteHeader))
	n, err := io.ReadFull(plainFile, firstPayload)
	if err != nil {
		if err != io.ErrUnexpectedEOF && err != io.EOF {
			return errors.ReadFileFailed(plainDB, err)
		}
	}
	if n < len(firstPayload) {
		for i := n; i < len(firstPayload); i++ {
			firstPayload[i] = 0
		}
	}

	salt := make([]byte, common.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encKey, macKey := e.deriveKeys(key, salt)

	firstPlain := make([]byte, common.SaltSize+len(firstPayload))
	copy(firstPlain[:common.SaltSize], salt)
	copy(firstPlain[common.SaltSize:], firstPayload)

	firstTail := firstPlain[len(firstPlain)-e.reserve:]
	if _, err := rand.Read(firstTail[:common.IVSize]); err != nil {
		return fmt.Errorf("failed to generate IV for page 0: %w", err)
	}
	for i := common.IVSize; i < len(firstTail); i++ {
		firstTail[i] = 0
	}

	encryptedPage, err := common.EncryptPage(firstPlain, encKey, macKey, 0, e.hashFunc, e.hmacSize, e.reserve, e.pageSize)
	if err != nil {
		return err
	}

	if _, err := output.Write(encryptedPage); err != nil {
		return errors.WriteOutputFailed(err)
	}

	pageBuf := make([]byte, e.pageSize)
	for curPage := int64(1); ; curPage++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, readErr := io.ReadFull(plainFile, pageBuf)
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if readErr != io.ErrUnexpectedEOF {
				return errors.ReadFileFailed(plainDB, readErr)
			}
		}

		if n == 0 && readErr == io.ErrUnexpectedEOF {
			break
		}

		if n < e.pageSize {
			for i := n; i < e.pageSize; i++ {
				pageBuf[i] = 0
			}
		}

		allZeros := true
		for _, b := range pageBuf {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			if _, err := output.Write(pageBuf); err != nil {
				return errors.WriteOutputFailed(err)
			}
			if readErr == io.ErrUnexpectedEOF {
				break
			}
			continue
		}

		tail := pageBuf[e.pageSize-e.reserve:]
		if _, err := rand.Read(tail[:common.IVSize]); err != nil {
			return fmt.Errorf("failed to generate IV for page %d: %w", curPage, err)
		}
		for i := common.IVSize; i < len(tail); i++ {
			tail[i] = 0
		}

		encryptedPage, err := common.EncryptPage(pageBuf, encKey, macKey, curPage, e.hashFunc, e.hmacSize, e.reserve, e.pageSize)
		if err != nil {
			return err
		}

		if _, err := output.Write(encryptedPage); err != nil {
			return errors.WriteOutputFailed(err)
		}

		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

func (e *V4Encryptor) GetPageSize() int {
	return e.pageSize
}

func (e *V4Encryptor) GetReserve() int {
	return e.reserve
}

func (e *V4Encryptor) GetHMACSize() int {
	return e.hmacSize
}

func (e *V4Encryptor) GetVersion() string {
	return e.version
}

func (e *V4Encryptor) GetIterCount() int {
	return e.iterCount
}
