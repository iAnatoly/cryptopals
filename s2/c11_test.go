package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	cryptorand "crypto/rand"
	rand "math/rand"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

/*

An ECB/CBC detection oracle

Now that you have ECB and CBC working:
* Write a function to generate a random AES key; that's just 16 random bytes.
* Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

* Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
* Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

Some explanation:
* we control the call tro encryption function, so we can pass it some plaintext that will make it obvious that ECB is used.
* we need to send a plaintext long enough to traverse two blocks, given that our JibberJabber encryption pads plaintext with random data.

*/

func GenerateRandomAESKey() []byte {
	key := make([]byte, 16)
	cryptorand.Read(key)
	return key
}

func WrapPlaintextInRandomPadding(text string) []byte {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	precedingBytesCount := 5 + rng.Intn(6)
	succeedingBytesCount := 5 + rng.Intn(6)

	precedingBuf := make([]byte, precedingBytesCount)
	succeedingBuf := make([]byte, succeedingBytesCount)

	cryptorand.Read(precedingBuf)
	cryptorand.Read(succeedingBuf)

	return append(precedingBuf, append([]byte(text), succeedingBuf...)...)
}

func EncryptJibberJabber(plainText string) ([]byte, bool) {
	key := GenerateRandomAESKey()
	input := WrapPlaintextInRandomPadding(plainText)

	var cipherText []byte
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	useECB := rng.Intn(2) == 1

	if useECB {
		buf, err := openssl.AesECBEncrypt(input, key, openssl.PKCS7_PADDING)
		if err != nil {
			log.Fatal(err)
		}
		cipherText = buf
	} else {
		IV := make([]byte, 16)
		cryptorand.Read(IV)
		cipherText = EncryptCBCviaECB(input, key, IV)
	}
	return cipherText, useECB
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

func DetectECB(cipherText []byte) bool {
	return RepeatingBlocksCount(cipherText, 16) > 0
}

func TestDetectECB(t *testing.T) {
	const attempts = 100

	plainText := strings.Repeat("x", 10+2*16+1) // 5-10 random chars + 2 full blocks

	detected := 0
	for i := 0; i < 100; i++ {
		cipherText, useECB := EncryptJibberJabber(plainText)
		if useECB == DetectECB(cipherText) {
			detected++
		}
	}
	log.Printf("Detected ECB encryption in %d%% of cases", detected*100/attempts)
	assert.Equal(t, attempts, detected)
}
