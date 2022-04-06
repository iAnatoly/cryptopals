package main

/*

Detect single-character XOR

One of the 60-character strings in [this](file:///./4.txt) file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)


*/

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"testing"

	"encoding/hex"

	aspell "github.com/trustmaster/go-aspell"
)

func DetectDecryptSingleChar(str string) string {
	bytes, _ := hex.DecodeString(str)
	speller, _ := aspell.NewSpeller(map[string]string{
		"lang": "en_US",
	})

	frequents, frequencies := GetOrderedFrequencies(bytes)

	if frequencies[frequents[0]] < 3 {
		return ""
	}

	for _, c := range frequents {
		resBuffer := XorC(bytes, byte(c)^32)
		res := string(resBuffer)
		if IsPrintable(res) && CountWords(res, &speller) > 3 {
			fmt.Printf("%d: %s\n", c, res)
			return res
		}
	}
	return ""
}

func ReadFileAsSliceOfStrings(filePath string) []string {
	file, err := os.Open(filePath)
	result := make([]string, 0)
	if err != nil {
		log.Fatal(err)
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return result
}

func TestDetectDecryptSingleChar(t *testing.T) {

	for _, line := range ReadFileAsSliceOfStrings("4.txt") {
		DetectDecryptSingleChar(line)
	}
}
