package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"log"
	rand "math/rand"
	"time"

	"github.com/forgoer/openssl"
)

/*

Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12.
Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
Stop and think for a second.

What's harder than challenge #12 about doing this?
How would you overcome that obstacle? T
he hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".

*/

const AnotherMysteryString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func GenerateRandomBytes() []byte {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	length := rng.Intn(42) + 8

	buf := make([]byte, length)
	cryptorand.Read(buf)
	return buf
}

func RandomPadAndEncryptECB(buf []byte, key []byte) []byte {
	suffix, err := base64.StdEncoding.DecodeString(MysteryString)
	if err != nil {
		log.Fatal(err)
	}
	prefix := GenerateRandomBytes()
	plainText := append(prefix, append(buf, suffix...)...)
	cipherText, err := openssl.AesECBEncrypt(plainText, key, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}
	return cipherText
}
