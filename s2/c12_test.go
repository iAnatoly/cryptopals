package main

/*

Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

    Detect that the function is using ECB. You already know, but do this step anyways.

    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real crypto.
Lots of people know that when you encrypt something in ECB mode, you can see penguins through it.
Not so many of them can decrypt the contents of those ciphertexts, and now you can.
If our experience is any guideline, this attack will get you code execution in security tests about once a year.


*/

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

const MysteryString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
const constantAESKey = "YELLOW SUBMARINE"

func PadAndEncryptECB(buf []byte, key []byte) []byte {
	suffix, err := base64.StdEncoding.DecodeString(MysteryString)
	if err != nil {
		log.Fatal(err)
	}
	plainText := append(buf, suffix...)
	cipherText, err := openssl.AesECBEncrypt(plainText, key, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}
	return cipherText
}

func guessBlockSize(constantAESKey []byte, encryptor func([]byte, []byte) []byte) int {
	prevLen := 0
	for i := 0; i < 16; i++ {
		text := strings.Repeat("A", i)
		cipherText := encryptor([]byte(text), constantAESKey)
		if prevLen == 0 {
			prevLen = len(cipherText)
		} else {
			delta := len(cipherText) - prevLen
			if delta > 0 {
				return delta
			}
		}
		// log.Println(cipherText)
	}
	return -1
}

func TestDiscoverBlockSize(t *testing.T) {
	//constantAESKey := GenerateRandomAESKey()
	blockSize := guessBlockSize([]byte(constantAESKey), PadAndEncryptECB)
	assert.Equal(t, 16, blockSize)
}

func TestVerifyECB(t *testing.T) {
	//constantAESKey := GenerateRandomAESKey()
	plainText := strings.Repeat("x", 3*16)
	cipherText := PadAndEncryptECB([]byte(plainText), []byte(constantAESKey))
	assert.True(t, DetectECB(cipherText)) // use DetectECB form C11
}

func OracleX(key []byte, blockSize int, detected []byte) (byte, error) {

	startingPosition := blockSize - 1 - len(detected)
	if startingPosition < 0 {
		startingPosition = -blockSize*(startingPosition/blockSize) - 1
	}
	log.Printf("Starting position: %d", startingPosition)

	plainTextBase := strings.Repeat("_", startingPosition)
	targetByte := PadAndEncryptECB([]byte(plainTextBase), key)[blockSize-1-len(detected)]
	oracleDict := make(map[byte]byte)

	for _, r := range "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ,!-=!@#$%^&*()[]{};:'" {
		oracleText := plainTextBase + string(detected) + string(r)
		oracleBytes := PadAndEncryptECB([]byte(oracleText), key)
		oracleDict[oracleBytes[blockSize-1-len(detected)]] = byte(r)
	}

	_, present := oracleDict[targetByte]
	if present {
		log.Printf("detected rune: %d -> %c", targetByte, oracleDict[targetByte])
		return oracleDict[targetByte], nil
	}
	log.Fatal("Not detected")
	return 0, errors.New("Not detected")
}

func TestAESPaddingOracle(t *testing.T) {
	//constantAESKey := GenerateRandomAESKey()
	blockSize := guessBlockSize([]byte(constantAESKey), PadAndEncryptECB)
	assert.Equal(t, 16, blockSize)

	plainText := strings.Repeat("x", 3*blockSize)
	cipherText := PadAndEncryptECB([]byte(plainText), []byte(constantAESKey))
	assert.True(t, DetectECB(cipherText))

	detected := make([]byte, 0, 100)

	for i := 0; i < 16; i++ {
		r, _ := OracleX([]byte(constantAESKey), blockSize, detected)
		detected = append(detected, r)
		log.Printf("%s %d", string(detected), len(detected))
	}
}
