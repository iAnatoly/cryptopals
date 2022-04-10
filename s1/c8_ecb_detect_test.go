package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
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

func TestECBDetect(t *testing.T) {
	const blockSize = 16

	cipherTexts := ReadFileAsSliceOfStrings("8.txt")
	for k, cipherText := range cipherTexts {
		unHex, err := hex.DecodeString(cipherText)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < len(unHex); i += 16 {
			for j := i + 16; j < len(unHex); j += 16 {
				if bytes.Equal(unHex[i:i+16], unHex[j:j+16]) {
					log.Printf("blocks %d, %d match on line %d", i, j, k)
				}
			}
		}

	}
}
