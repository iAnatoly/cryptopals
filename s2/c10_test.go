package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

/*

Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block"
called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
(verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise
to combine them.

The file here <10.txt> is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV
of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?

*/

func EncryptCBCviaECB(plainText []byte, key []byte, IV []byte) []byte {
	xIV := make([]byte, len(IV))
	copy(xIV, IV)

	if len(plainText)%16 != 0 {
		plainText = PadPKCS7(plainText, (len(plainText)/16+1)*16)
	}

	cipherText := make([]byte, len(plainText))
	buf := make([]byte, 16)

	for i := 0; i < len(plainText); i += 16 {
		for j := 0; j < 16; j++ {
			buf[j] = plainText[i+j] ^ xIV[j]
		}
		buf, err := openssl.AesECBEncrypt(buf, key, "")
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < 16; j++ {
			cipherText[i+j] = buf[j]
			xIV[j] = buf[j]
		}
	}
	return cipherText
}

func DecryptCBCviaECB(cipherText []byte, key []byte, IV []byte) []byte {
	xIV := make([]byte, len(IV))
	copy(xIV, IV)
	plainText := make([]byte, len(cipherText))

	for i := 0; i < len(cipherText); i += 16 {
		buf, err := openssl.AesECBDecrypt(cipherText[i:i+16], key, "")
		if err != nil {
			log.Fatal(err)
		}
		for j := 0; j < 16; j++ {
			plainText[i+j] = buf[j] ^ xIV[j]
			xIV[j] = cipherText[i+j]
		}
	}
	return plainText
}

func ReadBase64File(fileName string) []byte {
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}
	unBase, err := base64.StdEncoding.DecodeString(string(buffer))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decoded text content length: %d\n", len(unBase))
	return unBase
}

func TestEncryptDecryptCBCviaECB16b(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plainText := []byte("Hello, World!!!!")
	IV := make([]byte, 16)

	assert.Equal(t, plainText, DecryptCBCviaECB(EncryptCBCviaECB(plainText, key, IV), key, IV))
}
func TestEncryptDecryptCBCviaECB32b(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plainText := []byte("Hello, World!!!!0123456789ABCDEF")
	IV := make([]byte, 16)

	assert.Equal(t, plainText, DecryptCBCviaECB(EncryptCBCviaECB(plainText, key, IV), key, IV))
}

func TestDecryptCBCviaECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	IV := make([]byte, 16)
	cipherText := ReadBase64File("10.txt")
	plainText := DecryptCBCviaECB(cipherText, key, IV)
	assert.True(t, strings.HasPrefix(string(plainText), "I'm back and I'm ringin' the bell"))
}
