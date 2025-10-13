package decrypt

import (
	"context"
	"io"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/windows"
)

// Encryptor 定义数据库加密的接口
type Encryptor interface {
	// Encrypt 解密数据库
	Encrypt(ctx context.Context, plainDB string, hexKey string, output io.Writer) error

	// GetPageSize 返回页面大小
	GetPageSize() int

	// GetReserve 返回保留字节数
	GetReserve() int

	// GetHMACSize 返回HMAC大小
	GetHMACSize() int

	// GetVersion 返回解密器版本
	GetVersion() string
}

// NewEncryptor 创建一个新的加密器
func NewEncryptor(platform string, version int) (Encryptor, error) {
	// 根据平台返回对应的实现
	switch {
	case platform == "windows" && version == 4:
		return windows.NewV4Encryptor(), nil
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}
