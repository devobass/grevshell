package grevcore 

import (
	"fmt"
	"net"
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/pbkdf2"
	"crypto/sha512"
)

func DeriveKey(c net.Conn, psk string) ([]byte, error) {
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

	key, err := pbkdf2.Key(sha512.New, psk, salt, 250000, 16)

	if err != nil {
		return nil, err
	}

	return key, nil
}

func AesEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())

	_, err = rand.Read(iv)

	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, iv, data, nil)

	encrypted := make([]byte, gcm.NonceSize() + len(ciphertext))

	copy(encrypted[:gcm.NonceSize()], iv)
	copy(encrypted[gcm.NonceSize():], ciphertext)

	return encrypted, nil
}

func AesDecrypt(data, key []byte) ([]byte, error) {
	if len(data) == 0 || len(data) < 28 {
		return nil, fmt.Errorf("Invalid AES encrypted block size of %d.", len(data))
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	iv := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
