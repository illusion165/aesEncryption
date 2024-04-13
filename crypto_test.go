package main

import (
	"crypto/aes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GCMCrypto(t *testing.T) {
	var (
		keylen16 = RandStringBytes(16)
		keylen24 = RandStringBytes(24)
		keylen32 = RandStringBytes(32)
	)

	testCases := []struct {
		name             string
		secretKeyEnCrypt string
		secretKeyDeCrypt string
		plaintext        string
		expected         bool
	}{
		{
			name:             "encrypt/decrypt with secret key is invalid",
			secretKeyEnCrypt: RandStringBytes(32),
			secretKeyDeCrypt: RandStringBytes(32),
			plaintext:        "hello world!!!",
			expected:         false,
		},
		{
			name:             "secret key length is 16",
			secretKeyEnCrypt: keylen16,
			secretKeyDeCrypt: keylen16,
			plaintext:        "hello world!!!",
			expected:         true,
		},
		{
			name:             "secret key length is 24",
			secretKeyEnCrypt: keylen24,
			secretKeyDeCrypt: keylen24,
			plaintext:        "hello world!!!",
			expected:         true,
		},
		{
			name:             "secret key length is 32",
			secretKeyEnCrypt: keylen32,
			secretKeyDeCrypt: keylen32,
			plaintext:        "hello world!!!",
			expected:         true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			cipherText, err := AesGcmEncrypt(tc.plaintext, tc.secretKeyEnCrypt)
			require.NoError(t, err)
			require.NotEmpty(t, cipherText)
			decryptText, err := AesGcmDecrypt(cipherText, tc.secretKeyDeCrypt)
			if !tc.expected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, tc.plaintext == decryptText)
			}
		})
	}
}

func Test_CFBEncrypt(t *testing.T) {
	testCases := []struct {
		name      string
		secretKey string
		plaintext string
		error     func(string) error
	}{
		{
			name:      "secret key length not in 16, 24, 32",
			secretKey: "1234",
			plaintext: "plain text",
			error: func(key string) error {
				return aes.KeySizeError(len(key))
			},
		},
		{
			name:      "secret key length is 16",
			secretKey: RandStringBytes(16),
			plaintext: "plain text",
			error: func(key string) error {
				return nil
			},
		},
		{
			name:      "secret key length is 24",
			secretKey: RandStringBytes(24),
			plaintext: "plain text",
			error: func(key string) error {
				return nil
			},
		},
		{
			name:      "secret key length is 32",
			secretKey: RandStringBytes(32),
			plaintext: "plain text",
			error: func(key string) error {
				return nil
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			_, err := AesCFBEncrypt(tc.plaintext, tc.secretKey)
			require.Equal(t, tc.error(tc.secretKey), err)
		})
	}
}
func Test_SameTextEncryptGCM(t *testing.T) {
	t.Run("the same text must differ between each encryption", func(t *testing.T) {
		var (
			secretKey = RandStringBytes(32)
			plainText = RandStringBytes(20)
		)
		cipherText1, err := AesGcmEncrypt(plainText, secretKey)
		require.NoError(t, err)
		require.NotEmpty(t, cipherText1)

		cipherText2, err := AesGcmEncrypt(plainText, secretKey)
		require.NoError(t, err)
		require.NotEmpty(t, cipherText2)

		require.NotEqual(t, cipherText1, cipherText2)

		decryptText1, err := AesGcmDecrypt(cipherText1, secretKey)
		require.NoError(t, err)
		require.Equal(t, decryptText1, plainText)

		decryptText2, err := AesGcmDecrypt(cipherText2, secretKey)
		require.NoError(t, err)
		require.Equal(t, decryptText2, plainText)

	})
}

func Test_SameTextEncryptCFB(t *testing.T) {
	t.Run("the same text must differ between each encryption", func(t *testing.T) {
		var (
			secretKey = RandStringBytes(32)
			plainText = RandStringBytes(20)
		)
		cipherText1, err := AesCFBEncrypt(plainText, secretKey)
		require.NoError(t, err)
		require.NotEmpty(t, cipherText1)

		cipherText2, err := AesCFBEncrypt(plainText, secretKey)
		require.NoError(t, err)
		require.NotEmpty(t, cipherText2)

		require.NotEqual(t, cipherText1, cipherText2)

		decryptText1, err := AesCFBDecrypt(cipherText1, secretKey)
		require.NoError(t, err)
		require.Equal(t, decryptText1, plainText)

		decryptText2, err := AesCFBDecrypt(cipherText2, secretKey)
		require.NoError(t, err)
		require.Equal(t, decryptText2, plainText)

	})
}

func Test_CFBCrypto(t *testing.T) {
	var (
		keylen16 = RandStringBytes(16)
		keylen24 = RandStringBytes(24)
		keylen32 = RandStringBytes(32)
	)
	testCases := []struct {
		name             string
		secretKeyEnCrypt string
		secretKeyDeCrypt string
		plaintext        string
		expected         bool
	}{
		{
			name:             "encrypt/decrypt with secret key is invalid",
			secretKeyEnCrypt: RandStringBytes(32),
			secretKeyDeCrypt: RandStringBytes(32),
			plaintext:        "hello world!!!",
			expected:         false,
		},
		{
			name:             "secret key length is 16",
			secretKeyEnCrypt: keylen16,
			secretKeyDeCrypt: keylen16,
			plaintext:        "hello world!!!",
			expected:         true,
		},
		{
			name:             "secret key length is 24",
			secretKeyEnCrypt: keylen24,
			secretKeyDeCrypt: keylen24,
			plaintext:        "hello world!!!",
			expected:         true,
		},
		{
			name:             "secret key length is 32",
			secretKeyEnCrypt: keylen32,
			secretKeyDeCrypt: keylen32,
			plaintext:        "hello world!!!",
			expected:         true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			cipherText, err := AesCFBEncrypt(tc.plaintext, tc.secretKeyEnCrypt)
			require.NoError(t, err)
			require.NotEmpty(t, cipherText)
			decryptText, err := AesCFBDecrypt(cipherText, tc.secretKeyDeCrypt)
			require.NoError(t, err)
			require.Equal(t, tc.expected, tc.plaintext == decryptText)
		})
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+=0123456789"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
