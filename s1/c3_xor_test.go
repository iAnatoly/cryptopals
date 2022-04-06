package main

/*
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

Achievement Unlocked: You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

*/

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"encoding/hex"

	"github.com/stretchr/testify/assert"
	aspell "github.com/trustmaster/go-aspell"
)

func IsPrintable(str string) bool {
	for _, r := range str {
		//if !unicode.IsPrint(r) ||
		if r > 127 || r < 10 {
			return false
		}
	}
	return true
}

func CountWords(str string, speller *aspell.Speller) int {
	wcounter := 0
	for _, word := range strings.Fields(str) {
		// fmt.Printf("w: %s\n", word)
		if speller.Check(word) {
			wcounter++
		}
	}
	return wcounter
}

func XorC(bstring []byte, key byte) []byte {
	resBuffer := make([]byte, len(bstring))
	for i, x := range bstring {
		resBuffer[i] = x ^ key
	}
	return resBuffer
}

func GetOrderedFrequencies(bytes []byte) ([]byte, map[byte]int) {
	freq := make(map[byte]int)
	for _, b := range bytes {
		_, present := freq[b]
		if present {
			freq[b]++
		} else {
			freq[b] = 1
		}
	}
	keys := make([]byte, 0, len(freq))
	for key := range freq {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return freq[keys[i]] > freq[keys[j]] })
	return keys, freq
}

func DecryptSingleChar(str string) string {
	bytes, _ := hex.DecodeString(str)
	speller, _ := aspell.NewSpeller(map[string]string{
		"lang": "en_US",
	})

	frequents, _ := GetOrderedFrequencies(bytes)
	fmt.Printf("Prediction: %d\n", frequents[0]^32)

	for c := 0; c < 256; c++ {
		resBuffer := XorC(bytes, byte(c))
		res := string(resBuffer)
		if IsPrintable(res) && CountWords(res, &speller) > 3 {
			fmt.Printf("%d: %s\n", c, res)
			return res
		}
	}
	return ""
}

func TestDecryptSingleChar(t *testing.T) {
	const plaintext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	result := DecryptSingleChar(plaintext)
	assert.Equal(t, "Cooking MC's like a pound of bacon", result)
}
