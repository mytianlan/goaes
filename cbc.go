package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"
)

const (
	cbcIvString  = "0A8A76C0C10AE1DA"
	cbcKeyString = "0A8A76C0C10AE1DA"
)

func CBCEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	if len(iv) == 0 {
		iv = []byte(cbcIvString)
	}
	if len(key) == 0 {
		key = []byte(cbcKeyString)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("nvalid decrypt key:%x \n", key)
		return nil, errors.New("invalid decrypt key")
	}
	blockSize := block.BlockSize()
	plaintext = PKCS5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func CBCDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	if len(iv) == 0 {
		iv = []byte(cbcIvString)
	}
	if len(key) == 0 {
		key = []byte(cbcKeyString)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("nvalid decrypt key:%x \n", key)
		return nil, errors.New("invalid decrypt key")
	}

	blockSize := block.BlockSize()

	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	//iv := []byte(ivDefValue)
	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	blockModel := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plaintext, ciphertext)
	plaintext = PKCS5UnPadding(plaintext)

	return plaintext, nil
}
