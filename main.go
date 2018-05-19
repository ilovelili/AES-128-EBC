package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"flag"
	"fmt"
)

var (
	key = []byte("testtesttesttest") // aes 128 requires 24 characters in base64.
	src = []byte("ade")
)

func main() {
	var hasError = false
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error")
		hasError = true
	}

	if hasError {
		flag.Usage()
		return
	}

	ecb := NewECBEncrypter(block)
	content := PKCS5Padding(src, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	fmt.Println("result:", base64.StdEncoding.EncodeToString(crypted))
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
