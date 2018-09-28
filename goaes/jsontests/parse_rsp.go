/*
	parse_rsp.go

	Script for parsing .rsp known answer test files to a .json file

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

	parse_rsp.go Daniel Havir, 2018
*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	s "strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type teststruct struct {
	Key        string `json:"key"`
	Iv         string `json:"iv"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type testfile struct {
	Encrypt []teststruct `json:"encrypt"`
	Decrypt []teststruct `json:"decrypt"`
}

func main() {
	var inputPath string
	flag.StringVar(&inputPath, "in", "CBCGFSbox128.rsp", "Path to input file.")
	flag.Parse()
	fmt.Println(inputPath)
	f, err := os.Open(inputPath)
	check(err)

	scanner := bufio.NewScanner(f)
	phase := ""
	var encPipe, decPipe [300]teststruct
	var key, iv, plain, cipher string
	var count int
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || s.HasPrefix(line, "#") {
			continue
		}
		if s.HasPrefix(line, "[") {
			phase = line[1 : len(line)-1]
			continue
		} else if s.HasPrefix(line, "COUNT") {
			count, err = strconv.Atoi(line[8:])
			check(err)
		} else if s.HasPrefix(line, "KEY") {
			key = line[6:]
		} else if s.HasPrefix(line, "IV") {
			iv = line[5:]
		} else if s.HasPrefix(line, "PLAIN") {
			plain = line[12:]

			if phase == "DECRYPT" {
				test := teststruct{Key: key, Iv: iv,
					Plaintext: plain, Ciphertext: cipher}
				decPipe[count] = test
			}
		} else if s.HasPrefix(line, "CIPHER") {
			cipher = line[13:]

			if phase == "ENCRYPT" {
				test := teststruct{Key: key, Iv: iv,
					Plaintext: plain, Ciphertext: cipher}
				encPipe[count] = test
			}
		}
	}

	enc := encPipe[:count+1]
	dec := decPipe[:count+1]

	file := testfile{Encrypt: enc, Decrypt: dec}

	outputPath := inputPath[:len(inputPath)-4] + ".json"

	testsJSON, err := json.Marshal(file)
	check(err)
	err = ioutil.WriteFile(outputPath, testsJSON, 0644)
	check(err)
}
