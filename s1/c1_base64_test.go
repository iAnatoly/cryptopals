package main

/*
Convert hex to base64

The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
*/
import (
	"testing"

	"encoding/base64"
	"encoding/hex"

	"github.com/stretchr/testify/assert"
)

func EncodeBase64(str string) string {
	bytes, _ := hex.DecodeString(str)
	res := base64.StdEncoding.EncodeToString(bytes)
	return res
}

func TestBase64Conversion(t *testing.T) {
	const hextext = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const ciphertext = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	result := EncodeBase64(hextext)
	assert.Equal(t, ciphertext, result)
}
