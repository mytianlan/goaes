package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"log"
)

const (
	//ecbKeyString = "1234567812345678"
	ecbKeyString = "0A8A76C0C10AE1DA"
)

func Encrypt(content string, aeskey string) string {
	plaintext := []byte(content)
	key := []byte(aeskey)
	if len(key) == 0 {
		key = []byte(ecbKeyString)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("nvalid decrypt key:%x \n", key)
		return ""
	}
	blockSize := block.BlockSize()
	blockMode := NewECBEncrypter(block)

	//plaintext = PKCS5Padding(plaintext, blockSize)
	plaintext = ZeroPadding(plaintext, blockSize)
	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)

	return hex.EncodeToString(ciphertext)
}

// ECB加密算法，使用zeropadding填充
func ECBEncrypt(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(r.(string))
		}
	}()
	if len(key) == 0 {
		key = []byte(ecbKeyString)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("nvalid decrypt key:%x \n", key)
		return nil, errors.New("invalid decrypt key")
	}
	blockSize := block.BlockSize()
	blockMode := NewECBEncrypter(block)

	//plaintext = PKCS5Padding(plaintext, blockSize)
	plaintext = ZeroPadding(plaintext, blockSize)
	ciphertext = make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// ECB解密算法，使用zeropadding填充
func ECBDecrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(r.(string))
		}
	}()
	if len(key) == 0 {
		key = []byte(ecbKeyString)
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
	blockMode := NewECBDecrypter(block)

	plaintext = make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plaintext, ciphertext)

	//plaintext = PKCS5UnPadding(plaintext)
	plaintext = ZeroUnPadding(plaintext)
	return plaintext, nil
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
