package main

/*
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
*/

import (
	"testing"

	"encoding/hex"

	"github.com/stretchr/testify/assert"
)

func XorStr(hexStr1, hexStr2 string) string {
	if len(hexStr1) != len(hexStr2) {
		return ""
	}
	bytes1, _ := hex.DecodeString(hexStr1)
	bytes2, _ := hex.DecodeString(hexStr2)
	resBuffer := make([]byte, len(bytes1))

	for i := range bytes1 {
		resBuffer[i] = bytes1[i] ^ bytes2[i]
	}
	res := hex.EncodeToString(resBuffer)
	return res
}

func TestXorStr(t *testing.T) {
	const plaintext = "1c0111001f010100061a024b53535009181c"
	const keymaterial = "686974207468652062756c6c277320657965"
	const ciphertext = "746865206b696420646f6e277420706c6179"

	result := XorStr(plaintext, keymaterial)
	assert.Equal(t, ciphertext, result)
}
