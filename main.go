package main

import (
	"fmt"
)

func main() {
	secrectKey := "%2HY(k!Qy#+xbea7g8W5+zHTJ@3GnXLv"
	plainText := "test encryption"

	cipherText, _ := AesGcmEncrypt(plainText, secrectKey)
	fmt.Println("cipherText:", cipherText)

	plaintext, _ := AesGcmDecrypt(cipherText, secrectKey)
	fmt.Println("plaintext:", plaintext)

	cipherText1, _ := AesCFBEncrypt(plainText, secrectKey)
	fmt.Println("cipherText1:", cipherText1)

	plaintext1, _ := AesCFBDecrypt(cipherText1, secrectKey)
	fmt.Println("plaintext1:", plaintext1)

}
