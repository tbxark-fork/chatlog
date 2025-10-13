package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key"
)

type Wechat struct {
	platform  string
	version   int
	extractor key.Extractor
	encryptor decrypt.Encryptor
	decryptor decrypt.Decryptor
}

func NewWechat() (*Wechat, error) {
	platform := "windows"
	version := 4
	extractor, err := key.NewExtractor(platform, version)
	if err != nil {
		return nil, err
	}
	encryptor, err := decrypt.NewEncryptor(platform, version)
	if err != nil {
		return nil, err
	}
	decryptor, err := decrypt.NewDecryptor(platform, version)
	if err != nil {
		return nil, err
	}
	return &Wechat{
		platform:  platform,
		version:   version,
		extractor: extractor,
		encryptor: encryptor,
		decryptor: decryptor,
	}, nil
}

func (w *Wechat) EncryptFile(ctx context.Context, inputPath, outputDir, hexKey string) (string, error) {
	if inputPath == "" {
		return "", fmt.Errorf("未选择需要加密的文件")
	}
	if outputDir == "" {
		outputDir = filepath.Dir(inputPath)
	}

	base := filepath.Base(inputPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	ext := filepath.Ext(base)
	outputName := name + "_encrypted"
	if ext != "" {
		outputName += ext
	} else {
		outputName += ".enc"
	}
	outputPath := filepath.Join(outputDir, outputName)

	file, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	err = w.encryptor.Encrypt(ctx, inputPath, hexKey, file)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

func (w *Wechat) DecryptFile(ctx context.Context, inputPath, outputDir, hexKey string) (string, error) {
	if inputPath == "" {
		return "", fmt.Errorf("未选择需要解密的文件")
	}
	if outputDir == "" {
		outputDir = filepath.Dir(inputPath)
	}
	base := filepath.Base(inputPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	ext := filepath.Ext(base)
	outputName := name + "_decrypted"
	if ext != "" {
		outputName += ext
	} else {
		outputName += ".dec"
	}
	outputPath := filepath.Join(outputDir, outputName)

	file, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	err = w.decryptor.Decrypt(ctx, inputPath, hexKey, file)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

func run() error {
	wechat, err := NewWechat()
	if err != nil {
		return err
	}

	a := app.New()
	w := a.NewWindow("WX")

	keyValue := binding.NewString()
	fileValue := binding.NewString()
	outputValue := binding.NewString()
	statusValue := binding.NewString()
	_ = statusValue.Set("等待操作...")

	keyEntry := widget.NewEntryWithData(keyValue)
	keyEntry.SetPlaceHolder("输入密钥 (Hex)")

	fileEntry := widget.NewEntryWithData(fileValue)
	fileEntry.Disable()

	fileButton := widget.NewButton("选择文件", func() {
		open := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				_ = statusValue.Set(fmt.Sprintf("选择文件失败: %v", err))
				return
			}
			if reader == nil {
				return
			}
			path := reader.URI().Path()
			_ = reader.Close()
			_ = fileValue.Set(path)
			if currentDir, _ := outputValue.Get(); currentDir == "" {
				_ = outputValue.Set(filepath.Dir(path))
			}
		}, w)
		open.Show()
	})

	fileRow := container.NewBorder(nil, nil, nil, fileButton, fileEntry)

	outputEntry := widget.NewEntryWithData(outputValue)
	outputEntry.SetPlaceHolder("输出目录，默认与源文件一致")

	outputButton := widget.NewButton("选择目录", func() {
		open := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				_ = statusValue.Set(fmt.Sprintf("选择目录失败: %v", err))
				return
			}
			if uri == nil {
				return
			}
			_ = outputValue.Set(uri.Path())
		}, w)
		open.Show()
	})

	outputRow := container.NewBorder(nil, nil, nil, outputButton, outputEntry)

	statusLabel := widget.NewLabelWithData(statusValue)

	buttons := container.NewHBox(
		widget.NewButton("加密", func() {
			go func() {
				hexKey, _ := keyValue.Get()
				if hexKey == "" {
					_ = statusValue.Set("请输入有效的密钥")
					return
				}
				inputPath, _ := fileValue.Get()
				outputDir, _ := outputValue.Get()

				_ = statusValue.Set("正在加密...")
				outputPath, err := wechat.EncryptFile(context.Background(), inputPath, outputDir, hexKey)
				if err != nil {
					_ = statusValue.Set(fmt.Sprintf("加密失败: %v", err))
					return
				}
				_ = statusValue.Set(fmt.Sprintf("加密成功: %s", outputPath))
			}()
		}),
		widget.NewButton("解密", func() {
			go func() {
				hexKey, _ := keyValue.Get()
				if hexKey == "" {
					_ = statusValue.Set("请输入有效的密钥")
					return
				}
				inputPath, _ := fileValue.Get()
				outputDir, _ := outputValue.Get()

				_ = statusValue.Set("正在解密...")
				outputPath, err := wechat.DecryptFile(context.Background(), inputPath, outputDir, hexKey)
				if err != nil {
					_ = statusValue.Set(fmt.Sprintf("解密失败: %v", err))
					return
				}
				_ = statusValue.Set(fmt.Sprintf("解密成功: %s", outputPath))
			}()
		}),
	)

	content := container.NewVBox(
		widget.NewLabel("密钥"),
		keyEntry,
		widget.NewLabel("文件"),
		fileRow,
		widget.NewLabel("输出目录"),
		outputRow,
		buttons,
		statusLabel,
	)

	w.SetContent(container.NewPadded(content))
	w.Resize(fyne.NewSize(800, 600))
	w.ShowAndRun()
	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Panicf("error: %v", err)
	}
}
