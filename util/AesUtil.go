package p1Util

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
)

// AES-ECB加密
func ECBEncrypt(SPlainText, SKey string) (string, error) {
	plainText := []byte(SPlainText)
	key := []byte(SKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bs := aes.BlockSize
	paddingPlainText := pkcs7Padding(plainText, bs)
	cipherText := make([]byte, len(paddingPlainText))
	for i := 0; i < len(paddingPlainText); i += bs {
		block.Encrypt(cipherText[i:i+bs], paddingPlainText[i:i+bs])
	}
	return hex.EncodeToString(cipherText), nil
}

// AES-ECB解密
func ECBDecrypt(ScipherText, SKey string) (string, error) {
	cipherText, _ := hex.DecodeString(ScipherText)
	key := []byte(SKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bs := aes.BlockSize
	plainText := make([]byte, len(cipherText))

	for i := 0; i < len(cipherText); i += bs {
		block.Decrypt(plainText[i:i+bs], cipherText[i:i+bs])
	}

	unpaddingPaninText := pkcs7Unpadding(plainText)
	return string(unpaddingPaninText), nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:length-unpadding]
}
