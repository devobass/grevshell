package grevcore 

import (
	"fmt"
	"net"
	"io"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/hkdf"
	"crypto/ecdh"
)

func ExchangeKey(c net.Conn, psk string) ([]byte, error) {
	curve := ecdh.X25519()

	private, err := curve.GenerateKey(rand.Reader)

	if err != nil {
		return nil, err
	}

	public := private.PublicKey()
	_, err = c.Write(public.Bytes())

	if err != nil {
		return nil, err
	}

	remote := make([]byte, 32)

	_, err = io.ReadFull(c, remote)

	if err != nil {
		return nil, err
	}

	remotePublicKey, err := curve.NewPublicKey(remote)

	if err != nil {
		return nil, err
	}

	shared, err := private.ECDH(remotePublicKey)

	if err != nil {
		return nil, err
	}

	key, err := hkdf.Key(sha512.New, shared, []byte(psk), "", 16)

	if err != nil {
		return nil, err
	}

	if ! KeysMatch(c, key) {
		return nil, fmt.Errorf("Keys do not match.")
	}

	return key, nil
}

func KeysMatch(c net.Conn, key []byte) bool {
	recvHash := make([]byte, sha512.Size)

	hash := sha512.Sum512(key)
	derivedHash := hash[:]

	_, err := c.Write(derivedHash)

	if err != nil {
		return false
	}

	_, err = io.ReadFull(c, recvHash)

	if err != nil {
		return false
	}

	return bytes.Equal(recvHash, derivedHash)
}

func AesEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

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
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	if len(data) == 0 || len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("Invalid AES encrypted block size of %d.", len(data))
	}

	iv := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
