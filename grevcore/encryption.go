package grevcore 

import (
	"log/slog"
	"fmt"
	"net"
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/zenazn/pkcs7pad"
)

var HARDCODED_SEED = []byte("thisisa16bytekey")

func DeriveKey(c net.Conn) ([]byte, error) {
	seed_1 := make([]byte, 16)
	seed_2 := make([]byte, 16)
	key := make([]byte, 16)

	rand.Read(seed_1)
	c.Write(seed_1)

	_, err := io.ReadFull(c, seed_2)
	if err != nil {
		return nil, fmt.Errorf("Failed to read 16 bytes from connection. Error: %w.", err)
	}

	for i := range key {
		key[i] = seed_1[i] ^ seed_2[i] ^ HARDCODED_SEED[i]
	}

	return key, nil
}

func AesEncrypt(dataPtr, keyPtr *[]byte) []byte {
	data := *dataPtr
	key := *keyPtr
	block, err := aes.NewCipher(key)
	data = pkcs7pad.Pad(data, 16)

	if err != nil {
		slog.Error("An error occured while establishing block cipher.", slog.Any("ERROR", err))
		return nil
	}

	ciphertext := make([]byte, aes.BlockSize + len(data))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func AesDecrypt(dataPtr, keyPtr *[]byte) []byte {
	data := *dataPtr
	key := *keyPtr
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]


	block, err := aes.NewCipher(key)

	if err != nil {
		slog.Error("An error occured while establishing block cipher in decryption.", slog.Any("ERROR", err))
		return nil
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	data, _ = pkcs7pad.Unpad(data)

	return ciphertext
}


