/*
	aes_test.go

	Official AES Known Answer Tests (KAT) downloaded from:
	http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip

	See: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

	Bash script for extracting and parsing of the official KAT files is provided
	in setup/aes-tests.sh

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	aes_test.go Daniel Havir, 2018
*/

package main

import (
	"bytes"
	"crypto/aes"
	"encoding/json"
	"fmt"
	"testing"
)

type teststruct struct {
	Key        string
	Iv         string
	Plaintext  string
	Ciphertext string
}

type testfile struct {
	Encrypt []teststruct
	Decrypt []teststruct
}

func cbcEncTestrun(t *testing.T, tests []teststruct) int {
	numTests := 0
	for _, test := range tests {
		key := decodehex([]byte(test.Key))
		block, err := aes.NewCipher(key)
		check(err)
		inputVec := decodehex([]byte(test.Iv))
		cipher := NewCBC(block, inputVec)
		plaintext := decodehex([]byte(test.Plaintext))
		expected := decodehex([]byte(test.Ciphertext))
		encrypted := cipher.Encrypt(plaintext)
		if !(bytes.Equal(encrypted, expected)) {
			t.Error("Expected ", string(encodehex(expected)),
				",got ", string(encodehex(encrypted)))
		}
		numTests++
	}
	return numTests
}

func cbcDecTestrun(t *testing.T, tests []teststruct) int {
	numTests := 0
	for _, test := range tests {
		key := decodehex([]byte(test.Key))
		block, err := aes.NewCipher(key)
		check(err)
		inputVec := decodehex([]byte(test.Iv))
		cipher := NewCBC(block, inputVec)
		ciphertext := decodehex([]byte(test.Ciphertext))
		expected := decodehex([]byte(test.Plaintext))
		decrypted := cipher.Decrypt(ciphertext)
		if !(bytes.Equal(decrypted, expected)) {
			t.Error("Expected ", string(encodehex(expected)),
				",got ", string(encodehex(decrypted)))
		}
		numTests++
	}
	return numTests
}

func ecbEncTestrun(t *testing.T, tests []teststruct) int {
	numTests := 0
	for _, test := range tests {
		key := decodehex([]byte(test.Key))
		block, err := aes.NewCipher(key)
		check(err)
		cipher := NewECB(block)
		plaintext := decodehex([]byte(test.Plaintext))
		expected := decodehex([]byte(test.Ciphertext))
		encrypted := cipher.Encrypt(plaintext)
		if !(bytes.Equal(encrypted, expected)) {
			t.Error("Expected ", string(encodehex(expected)),
				",got ", string(encodehex(encrypted)))
		}
		numTests++
	}
	return numTests
}

func ecbDecTestrun(t *testing.T, tests []teststruct) int {
	numTests := 0
	for _, test := range tests {
		key := decodehex([]byte(test.Key))
		block, err := aes.NewCipher(key)
		check(err)
		cipher := NewECB(block)
		ciphertext := decodehex([]byte(test.Ciphertext))
		expected := decodehex([]byte(test.Plaintext))
		decrypted := cipher.Decrypt(ciphertext)
		if !(bytes.Equal(decrypted, expected)) {
			t.Error("Expected ", string(encodehex(expected)),
				",got ", string(encodehex(decrypted)))
		}
		numTests++
	}
	return numTests
}

func TestCBCGFSbox128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCGFSbox128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCGFSbox128 tests: ", numEncTests+numDecTests)
}

func TestCBCGFSbox192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCGFSbox192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCGFSbox192 tests: ", numEncTests+numDecTests)
}

func TestCBCGFSbox256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCGFSbox256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCGFSbox256 tests: ", numEncTests+numDecTests)
}

func TestCBCKeySbox128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCKeySbox128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCKeySbox128 tests: ", numEncTests+numDecTests)
}

func TestCBCKeySbox192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCKeySbox192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCKeySbox192 tests: ", numEncTests+numDecTests)
}

func TestCBCKeySbox256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCKeySbox256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCKeySbox256 tests: ", numEncTests+numDecTests)
}

func TestCBCVarKey128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarKey128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarKey128 tests: ", numEncTests+numDecTests)
}

func TestCBCVarKey192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarKey192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarKey192 tests: ", numEncTests+numDecTests)
}

func TestCBCVarKey256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarKey256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarKey256 tests: ", numEncTests+numDecTests)
}

func TestCBCVarTxt128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarTxt128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarTxt128 tests: ", numEncTests+numDecTests)
}

func TestCBCVarTxt192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarTxt192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarTxt192 tests: ", numEncTests+numDecTests)
}

func TestCBCVarTxt256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/CBCVarTxt256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := cbcEncTestrun(t, file.Encrypt)
	numDecTests := cbcDecTestrun(t, file.Decrypt)
	fmt.Println("Num CBCVarTxt256 tests: ", numEncTests+numDecTests)
}

func TestECBGFSbox128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBGFSbox128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBGFSbox128 tests: ", numEncTests+numDecTests)
}

func TestECBGFSbox192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBGFSbox192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBGFSbox192 tests: ", numEncTests+numDecTests)
}

func TestECBGFSbox256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBGFSbox256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBGFSbox256 tests: ", numEncTests+numDecTests)
}

func TestECBKeySbox128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBKeySbox128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBKeySbox128 tests: ", numEncTests+numDecTests)
}

func TestECBKeySbox192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBKeySbox192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBKeySbox192 tests: ", numEncTests+numDecTests)
}

func TestECBKeySbox256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBKeySbox256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBKeySbox256 tests: ", numEncTests+numDecTests)
}

func TestECBVarKey128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarKey128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarKey128 tests: ", numEncTests+numDecTests)
}

func TestECBVarKey192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarKey192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarKey192 tests: ", numEncTests+numDecTests)
}

func TestECBVarKey256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarKey256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarKey256 tests: ", numEncTests+numDecTests)
}

func TestECBVarTxt128(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarTxt128.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarTxt128 tests: ", numEncTests+numDecTests)
}

func TestECBVarTxt192(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarTxt192.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarTxt192 tests: ", numEncTests+numDecTests)
}

func TestECBVarTxt256(t *testing.T) {
	var file testfile
	testJSON := readfile("jsontests/ECBVarTxt256.json")
	json.Unmarshal(testJSON, &file)
	numEncTests := ecbEncTestrun(t, file.Encrypt)
	numDecTests := ecbDecTestrun(t, file.Decrypt)
	fmt.Println("Num ECBVarTxt256 tests: ", numEncTests+numDecTests)
}
