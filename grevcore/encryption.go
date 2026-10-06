package grevcore 

import (
	"fmt"
	"net"
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	
	"golang.org/x/crypto/argon2"
	"github.com/zenazn/pkcs7pad"
)

func DeriveKey(c net.Conn, psk []byte) ([]byte, error) {
	seed_1	:= make([]byte, 16)
	seed_2	:= make([]byte, 16)
	salt	:= make([]byte, 16)

	rand.Read(seed_1)
	_, err := c.Write(seed_1)

	if err != nil {
		return nil, fmt.Errorf("Failed to send 16 bytes to connection. Error: %w.", err)
	}

	_, err = io.ReadFull(c, seed_2)

	if err != nil {
		return nil, fmt.Errorf("Failed to read 16 bytes from connection. Error: %w.", err)
	}

	for i := range salt {
		salt[i] = seed_1[i] ^ seed_2[i]
	}

	// I might be a genius
	key := argon2.IDKey(psk, salt, 1, 2*1024*1024, 4, 16)

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
