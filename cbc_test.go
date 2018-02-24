package aes

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_CBCEncrypt(t *testing.T) {
	textSlice := make([]byte, 0)
	cid := "abcd1234"
	textSlice = append(textSlice, []byte(cid)...)

	//var buf = make([]byte, 4)

	//timestamp := uint32(time.Now().Unix())
	//binary.BigEndian.PutUint32(buf, timestamp)
	//textSlice = append(textSlice, buf...)

	//binary.BigEndian.PutUint32(buf, rand.Uint32())
	//textSlice = append(textSlice, buf...)

	//binary.BigEndian.PutUint32(buf, uint32(101))
	//textSlice = append(textSlice, buf...)

	//fmt.Printf("%x-\n", textSlice)
	key := "0A8A76C0C10AE1DA"
	iv := "0A8A76C0C10AE1DA"
	ciphertext, err := CBCEncrypt(textSlice, []byte(key), []byte(iv))
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("%X\n", ciphertext)
	t.Log("success")
	return
}

func Test_CBCDecrypt(t *testing.T) {
	key := "0A8A76C0C10AE1DA"
	iv := "0A8A76C0C10AE1DA"

	cipher := "1C5EF7000AAC9269B6646C89B3951F426007142F751D3BEC0050D68EB8E56A4B"
	//cipher := ""
	ciphertext, _ := hex.DecodeString(cipher)
	//ciphertext := []byte{139, 107, 43, 172, 250, 119, 140, 58, 61, 189, 46, 11, 176, 80, 151, 160}
	plaintext, err := CBCDecrypt(ciphertext, []byte(key), []byte(iv))
	if err != nil {
		t.Error(err)
		return
	}
	//log.Printf("%x\n", plaintext)
	fmt.Printf("%x\n", plaintext)
	t.Log("success")
	return
}
