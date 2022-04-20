package main

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

/*

# ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them,
whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves,
make a role=admin profile.

*/

func ParseURLEncodedstring(urlEncoded string) map[string]string {
	parsed, err := url.ParseQuery(urlEncoded)
	if err != nil {
		log.Fatal(err)
	}
	result := make(map[string]string)
	for k, v := range parsed {
		result[k] = v[0]
	}
	return result
}

func TestParseURLEncodedstring(t *testing.T) {
	assert.Equal(t, map[string]string{"email": "foo@bar.com", "role": "user", "uid": "10"}, ParseURLEncodedstring("email=foo@bar.com&uid=10&role=user"))
}

func GenerateProfileFor(upn string) string {
	upn = strings.ReplaceAll(upn, "&", "_")
	upn = strings.ReplaceAll(upn, "%", "_")
	upn = strings.ReplaceAll(upn, "=", "_")
	result := fmt.Sprintf("email=%s&uid=10&role=user", upn)
	return result
}

func TestGenerateProfileFor(t *testing.T) {
	assert.Equal(t, "email=admin@gmail.com&uid=10&role=user", GenerateProfileFor("admin@gmail.com"))
	assert.Equal(t, "email=admin@gmail.com_role_admin&uid=10&role=user", GenerateProfileFor("admin@gmail.com&role=admin"))
}

func TestEncryptDecrypt(t *testing.T) {
	randomAESkey := GenerateRandomAESKey()
	userProfile := GenerateProfileFor("user@gmail.com")
	cipherText, err := openssl.AesECBEncrypt([]byte(userProfile), randomAESkey, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}
	plainText, err := openssl.AesECBDecrypt(cipherText, randomAESkey, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, userProfile, string(plainText))
	log.Println(ParseURLEncodedstring(string(plainText)))
}

func XorStr(bytes1, bytes2 []byte) []byte {
	if len(bytes1) != len(bytes2) {
		log.Fatal("length is not equal")
	}
	resBuffer := make([]byte, len(bytes1))

	for i := range bytes1 {
		resBuffer[i] = bytes1[i] ^ bytes2[i]
	}
	return resBuffer
}

func TestEncryptMutateDecrypt(t *testing.T) {
	randomAESkey := GenerateRandomAESKey()

	// prepare a ciphertext where role falls into a separate ECB block
	// b0-1: email=<something>&uid=10&role=
	// b2: user<padding>
	lenPattern := 32 - len("email=&uid=10&role=")
	userProfile := GenerateProfileFor(strings.Repeat("_", lenPattern))
	log.Println(userProfile)

	cipherText, err := openssl.AesECBEncrypt([]byte(userProfile), randomAESkey, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}

	// prepare a ciphertext where word "admin" falls into a separate block. Add faux PKCS7 padding.
	// b0: email=<something>
	// b1: admin<faux PKCS7 padding>
	// b2+: &uid=10&role=user
	adminpattern := "admin"
	lenPadding := byte(16 - len(adminpattern))
	fauxPadding := strings.Repeat(string(rune(lenPadding)), int(lenPadding))
	adminWithPadding := strings.Repeat("_", 16-len("email=")) + adminpattern + fauxPadding
	userProfile2 := GenerateProfileFor(adminWithPadding)
	cipherText2, err := openssl.AesECBEncrypt([]byte(userProfile2), randomAESkey, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}

	// combine blocks 0 & 1 of the original ciphertext with a manufactured block 1 of next ciphertext
	combinedCipherText := append(cipherText[0:32], cipherText2[16:32]...)

	// receive a nice concatenated string as a result.
	plainText, err := openssl.AesECBDecrypt(combinedCipherText, randomAESkey, openssl.PKCS7_PADDING)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(plainText))
	log.Println(ParseURLEncodedstring(string(plainText)))
	assert.Equal(t, strings.ReplaceAll(userProfile, "=user", "=admin"), string(plainText))
}
