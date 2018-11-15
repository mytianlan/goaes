# AES tools

## CBC
CBC加密说明：
- CBC固定IV
- PKCS5UnPadding补位

```go
//CBC加密，使用PKCSpadding填充
func CBCEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error)

//CBC解密，使用PKCSpadding填充
func CBCDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error)

//ECB加密，使用zeropadding填充
func ECBEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error)

//ECB解密，使用zeropadding填充|||
func ECBDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error)
```
