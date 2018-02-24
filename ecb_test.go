package aes

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_ECBEncrypt(t *testing.T) {
	ciphertext, _ := ECBEncrypt([]byte("asdfasdfasdfasd"), []byte(""))
	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))

	t.Log("success")
	return
}
func Test_ECBDecrypt(t *testing.T) {
	cipher := "ada8d11d92b037eeaa30c4bdde342d5d"
	ciphertext, _ := hex.DecodeString(cipher)
	aa, _ := ECBDecrypt(ciphertext, []byte(""))
	fmt.Printf("%s\n", string(aa))

	t.Log("success")
	return
}
