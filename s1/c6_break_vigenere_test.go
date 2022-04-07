package main

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"math/bits"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

/*

Break repeating-key XOR

There's a file here: https://cryptopals.com/static/challenge-data/6.txt
It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

        "this is a test"

    and

        "wokka wokka!!!"

    is 37. Make sure your code agrees before you proceed.

    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
    and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key.
    You could proceed perhaps with the smallest 2-3 KEYSIZE values.
    Or take 4 KEYSIZE blocks instead of 2 and average the distances.

    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the
    second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.

    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
    XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on.
Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

*/

// HammingDistance calculates Hamming distance (in bits) between two strings
func HammingDistance(s1, s2 string) int {
	assert.Equal(nil, len(s1), len(s2))
	distance := 0
	for i := range s1 {
		bitmask := uint(s1[i] ^ s2[i])
		distance += bits.OnesCount(bitmask)
	}
	return distance
}

// test for HammingDistance
func TestHammingDistance(t *testing.T) {
	distance := HammingDistance("this is a test", "wokka wokka!!!")
	assert.Equal(t, 37, distance)
}

// helper min function (batteries not included)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// get average hamming distance between given number of blocks of size keySize
func GetAvgHammingDistance(cipherText string, keySize int, blocks int) float64 {
	distances := 0
	for j := 0; j < blocks-1; j++ {
		s1 := cipherText[keySize*j : keySize*(j+1)]
		s2 := cipherText[keySize*(j+1) : keySize*(j+2)]
		distance := HammingDistance(s1, s2)
		distances += distance
	}
	return float64(distances) / float64(blocks-1)
}

// guess the key size based on hamming distance.
// return all key sizes ranked by hamming distance ASC
func GuessKeySize(cipherText string) []int {
	const minKeySize = 4
	const blocks = 3 // works much better with 4 blocks - but I need code working for worst-case scenarios
	maxKeySize := min(40, len(cipherText)/blocks)

	result := make(map[int]float64)
	keys := make([]int, 0, maxKeySize-minKeySize)

	for i := minKeySize; i < maxKeySize; i++ {
		distance := GetAvgHammingDistance(cipherText, i, blocks)
		result[i] = distance / float64(i) // normalized by key size
		keys = append(keys, i)
	}

	sort.Slice(keys, func(i, j int) bool { return result[keys[i]] < result[keys[j]] })

	// DEBUG: print out the scores in ranked order, along with the normalized hamming distance
	for _, x := range keys {
		log.Printf(" * %d: %f", x, result[x])
	}

	return keys
}

func TestGuessKeySize(t *testing.T) {
	assert.Equal(t, 8, GuessKeySize("abcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh")[0])
}

//split and transpose the ciphertext
func SplitAndTranspose(cipherText string, keySize int) []string {
	result := make([]string, keySize)
	for i, r := range cipherText {
		result[i%keySize] += string(r)
	}
	return result
}

func TestSplitAndTranspose(t *testing.T) {
	result := SplitAndTranspose("abcdabcdabcd", 4)
	assert.Equal(t, []string{"aaa", "bbb", "ccc", "ddd"}, result)
}

func IsAcceptable(str string) bool {
	for _, r := range str {
		//if !unicode.IsPrint(r) ||
		if r > 127 || r < 10 {
			return false
		}
	}
	return true
}

func GuessSingleCharXor(str string) (byte, error) {
	bytes := []byte(str)
	frequents, _ := GetOrderedFrequencies(bytes)

	for _, letter := range " Tea" {
		for _, c := range frequents {
			resBuffer := XorC(bytes, byte(c)^byte(letter))
			res := string(resBuffer)
			if IsAcceptable(res) { //&& CountWords(res, &speller) > 3 {
				return byte(c) ^ byte(letter), nil
			}
		}
	}
	return 0, errors.New("Could not find suitable key")
}

func GuessXorKey(transposedText []string) ([]byte, error) {
	guessedKey := make([]byte, 0, len(transposedText))
	for _, line := range transposedText {
		charKey, err := GuessSingleCharXor(line)
		if err != nil {
			return nil, err
		}
		guessedKey = append(guessedKey, charKey)
	}
	return guessedKey, nil
}

func FindXorKey(cipherText string) []byte {
	guessedKeySizes := GuessKeySize(cipherText)

	for _, guessedKeySize := range guessedKeySizes {

		log.Printf("Trying for guessed key size: %d", guessedKeySize)
		transposedText := SplitAndTranspose(cipherText, guessedKeySize)
		guessedKey, err := GuessXorKey(transposedText)
		if err != nil {
			log.Printf("Error guessing key for size %d: %s", guessedKeySize, err)
			continue
		}
		log.Println(string(guessedKey))
		return guessedKey
	}
	return nil

}

func TestFindXorKey(t *testing.T) {
	buffer, err := ioutil.ReadFile("6.txt")
	if err != nil {
		log.Fatal(err)
	}
	unhex, err := base64.StdEncoding.DecodeString(string(buffer))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decoded text content length: %d\n", len(unhex))
	content := string(unhex)

	key := FindXorKey(content)
	log.Println("Key:" + string(key))
	assert.Equal(t, "Terminator X: Bring the noise", string(key))

	plainText := EncryptRepeatedKeyXor(content, string(key))
	log.Println(string(plainText))
}
