package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

/*

AES in ECB mode

The Base64-encoded content in this <https://cryptopals.com/static/challenge-data/7.txt> file has been encrypted
via AES-128 in ECB mode under the key "YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason.
You'll need it a lot later on, and not just for attacking ECB.

*/

func TestAESinECBmode(t *testing.T) {
	buffer, err := ioutil.ReadFile("7.txt")
	if err != nil {
		log.Fatal(err)
	}
	unBase, err := base64.StdEncoding.DecodeString(string(buffer))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decoded text content length: %d\n", len(unBase))
	//content := string(unhex)
	key := "YELLOW SUBMARINE"
	buf, err := openssl.AesECBDecrypt(unBase, []byte(key), openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decrypted content length: %d", len(buf))
	//log.Println(string(buf))
	assert.Equal(t, 2876, len(buf))
}
