/*
	utils.go

	Utility script for reading, writing files, hex encoding/decoding,
	padding, unpadding and element-wise XORing (chaining) of two byte arrays

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

	utils.go Daniel Havir, 2018
*/

package main

import (
	"bytes"
	hex "encoding/hex"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func readfile(path string) []byte {
	dat, err := ioutil.ReadFile(path)
	check(err)
	return dat
}

func writefile(text []byte, path string) {
	err := ioutil.WriteFile(path, text, 0664)
	check(err)
}

func decodehex(src []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(dst, src)
	return dst
}

func encodehex(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func readhexfile(path string) []byte {
	src := readfile(path)
	dst := decodehex(src)
	return dst
}

func writehexfile(src []byte, path string) {
	text := encodehex(src)
	writefile(text, path)
}

func pad(src []byte, blockSize int) []byte {
	pad := blockSize - len(src)%blockSize
	fill := bytes.Repeat([]byte{byte(pad)}, pad)
	// Reference: https://golang.org/ref/spec#Passing_arguments_to_..._parameters
	src = append(src, fill...)
	return src
}

func unpad(src []byte) []byte {
	unpad := int(src[len(src)-1])
	src = src[:(len(src) - unpad)]
	return src
}

// Inplace XOR operation
func xor(dst, arr1, arr2 []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = arr1[i] ^ arr2[i]
	}
}
