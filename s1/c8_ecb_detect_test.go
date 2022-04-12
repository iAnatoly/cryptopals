package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
Detect AES in ECB mode

In this <8.txt> file are a bunch of hex-encoded ciphertexts.
One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
*/

func HasAllTopBitsSet(bytes []byte) bool {
	for _, b := range bytes {
		if b > 127 {
			return false
		}
	}
	return true
}

func RepeatingBlocksCount(cipherText []byte, blockSize int) int {
	repeatedBlockCount := 0
	for i := 0; i < len(cipherText); i += blockSize {
		for j := i + blockSize; j < len(cipherText); j += blockSize {
			if bytes.Equal(cipherText[i:i+blockSize], cipherText[j:j+blockSize]) {
				repeatedBlockCount++
			}
		}
	}
	return repeatedBlockCount
}

func TestECBDetect(t *testing.T) {
	cipherTexts := ReadFileAsSliceOfStrings("8.txt")
	for k, cipherText := range cipherTexts {
		unHex, err := hex.DecodeString(cipherText)
		if err != nil {
			log.Fatal(err)
		}

		r := RepeatingBlocksCount(unHex, 16)
		if r > 0 {
			log.Printf("Found %d blocks matching on line %d", r, k)
			assert.Equal(t, 132, k) // post-factum test - it is line 132, and 132 only
		}

	}
}
