package grevcore 

import (
	"fmt"
	"net"
	"io"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/hmac"
	"crypto/hkdf"
	"crypto/ecdh"
)

func ExchangeKey(c net.Conn, psk string) ([]byte, error) {
	curve := ecdh.X25519()

	private, err := curve.GenerateKey(rand.Reader)

	if err != nil {
		return nil, fmt.Errorf("an error occured while generating the private key, err=%w", err)
	}

	public := private.PublicKey()
	_, err = c.Write(public.Bytes())

	if err != nil {
		return nil, fmt.Errorf("an error occured while sending the public key over, err=%w", err)
	}

	remote := make([]byte, 32)

	_, err = io.ReadFull(c, remote)

	if err != nil {
		return nil, fmt.Errorf("an error occured while receiving the recepient's public key, err=%w", err)
	}

	remotePublicKey, err := curve.NewPublicKey(remote)

	if err != nil {
		return nil, fmt.Errorf("an error occured while converting the public key bytes, err=%w", err)
	}

	shared, err := private.ECDH(remotePublicKey)

	if err != nil {
		return nil, fmt.Errorf("an error occured while deriving the shared ecdh secret, err=%w", err)
	}

	key, err := hkdf.Key(sha512.New, shared, []byte(psk), "", 32)

	if err != nil {
		return nil, fmt.Errorf("an error occured while performing HKDF key expansion, err=%w", err)
	}

	valid, err := KeysMatch(c, key, public.Bytes(), remote)
	if err != nil || ! valid {
		return nil, fmt.Errorf("shared secret keys do not match, err=%w", err)
	}

	return key, nil
}

func KeysMatch(c net.Conn, key, pub, peerPub []byte) (bool, error) {
	mac := hmac.New(sha512.New, key)
	receivedChallenge := make([]byte, mac.Size())

	mac.Write(peerPub)
	challenge := mac.Sum(nil)
	mac.Reset()

	mac.Write(pub)
	expected := mac.Sum(nil)

	_, err := c.Write(challenge)

	if err != nil {
		return false, fmt.Errorf("an error occured while sending the peer a challenge, err=%w", err)
	}

	_, err = io.ReadFull(c, receivedChallenge)

	if err != nil {
		return false, fmt.Errorf("an error occured while receiving the peer's challenge, err=%w", err)
	}

	return hmac.Equal(expected, receivedChallenge), nil
}

func AesEncrypt(data, key []byte) ([]byte, error) {
	ciph, err := aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("an error occured while initializing the cipher, err=%w", err)
	}

	gcm, err := cipher.NewGCM(ciph)

	if err != nil {
		return nil, fmt.Errorf("an error occured while initializing AES-GCM, err=%w", err)
	}

	iv := make([]byte, gcm.NonceSize())

	_, err = rand.Read(iv)

	if err != nil {
		return nil, fmt.Errorf("an error occured while generating random nonce, err=%w", err)
	}

	ciphertext := gcm.Seal(nil, iv, data, nil)

	encrypted := make([]byte, gcm.NonceSize() + len(ciphertext))

	copy(encrypted[:gcm.NonceSize()], iv)
	copy(encrypted[gcm.NonceSize():], ciphertext)

	return encrypted, nil
}

func AesDecrypt(data, key []byte) ([]byte, error) {
	ciph, err := aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("an error occured while initializing the cipher, err=%w", err)
	}

	gcm, err := cipher.NewGCM(ciph)

	if err != nil {
		return nil, fmt.Errorf("an error occured while initializing AES-GCM, err=%w", err)
	}

	if len(data) == 0 || len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid AES encrypted cipher size of %d.", len(data))
	}

	iv := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)

	if err != nil {
		return nil, fmt.Errorf("an error occured while decrypting the data, err=%w", err)
	}

	return plaintext, nil
}
