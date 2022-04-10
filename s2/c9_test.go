package main

/*
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext.
But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of
the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
*/

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func PadPKCS7(cipherText []byte, size int) []byte {
	padding := byte(size - len(cipherText))
	newSlice := make([]byte, padding)
	for i := range newSlice {
		newSlice[i] = padding
	}
	cipherText = append(cipherText, newSlice...)
	return cipherText
}

func TestHelloWorld(t *testing.T) {
	assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), PadPKCS7([]byte("YELLOW SUBMARINE"), 20))
}
