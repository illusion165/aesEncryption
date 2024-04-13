package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AesGcmEncrypt AES-GCM
func AesGcmEncrypt(plaintext string, secretKey string) (string, error) {
	// key length must be [16, 24, 32]
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}
	encrypted := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return Encode(encrypted), nil
}

// AesGcmDecrypt AES-GCM
func AesGcmDecrypt(cryptoText string, secretKey string) (string, error) {
	ciphertext, err := Decode(cryptoText)
	if err != nil {
		return "", err
	}

	// key length must be [16, 24, 32]
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce := ciphertext[:nonceSize]

	plaintext, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// AesCFBEncrypt AES-CFB
func AesCFBEncrypt(text string, secretKey string) (string, error) {
	// key length must be [16, 24, 32]
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return Encode(ciphertext), nil
}

// AesCFBDecrypt AES-CFB
func AesCFBDecrypt(cryptoText string, secretKey string) (string, error) {
	ciphertext, err := Decode(cryptoText)
	if err != nil {
		return "", err
	}
	// key length must be [16, 24, 32]
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}
