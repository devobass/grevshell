package grevcore 

import (
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
	seed_1	:= make([]byte, 16)
	seed_2	:= make([]byte, 16)
	key	:= make([]byte, 16)

	rand.Read(seed_1)
	_, err := c.Write(seed_1)

	if err != nil {
		return nil, fmt.Errorf("Failed to send 16 bytes to connection. Error: %w.", err)
	}

	_, err = io.ReadFull(c, seed_2)

	if err != nil {
		return nil, fmt.Errorf("Failed to read 16 bytes from connection. Error: %w.", err)
	}

	for i := range key {
		key[i] = seed_1[i] ^ seed_2[i] ^ HARDCODED_SEED[i]
	}

	return key, nil
}

func AesEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	data = pkcs7pad.Pad(data, aes.BlockSize)

	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize + len(data))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func AesDecrypt(data, key []byte) ([]byte, error) {
	if len(data) == 0 || len(data) % aes.BlockSize != 0 {
		return nil, fmt.Errorf("Invalid data size of %d.", len(data))
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, err = pkcs7pad.Unpad(ciphertext)

	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
