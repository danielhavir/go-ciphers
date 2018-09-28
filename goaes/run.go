/*
	run.go

	Main function for the AES CLI interface.

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

	run.go Daniel Havir, 2018
*/

package main

import (
	"crypto/aes"
	"crypto/rand"
	"flag"
	"strconv"
)

func main() {
	encrypt := flag.Bool("en", false, "Encrypt")
	decrypt := flag.Bool("de", false, "Decrypt")
	mode := flag.String("mode", "cbc", "AES mode of operation. ECB or CBC.")
	inputPath := flag.String("in", "file.txt", "Path to input file.")
	outputPath := flag.String("out", "out", "Path to output file.")
	keyString := flag.String("key", "0102030405060708090a0b0c0d0e0f10", "Encryption/decryption key. For encryption, choose a string between 5 and 32 characters.")
	useHex := flag.Bool("hex", false, "Encode to/from hex.")
	flag.Parse()

	if !(*encrypt || *decrypt) {
		panic("You must specify either either encrypt \"-en\" or decrypt \"-de\"")
	}

	if !(*mode == "ecb" || *mode == "cbc") {
		panic("You must specify either either encrypt \"-en\" or decrypt \"-de\"")
	}

	key := []byte(*keyString)

	if !(len(key) == 16 || len(key) == 24 || len(key) == 32) {
		panic("Key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256." +
			"Got: " + strconv.Itoa(len(key)))
	}

	block, err := aes.NewCipher(key)
	check(err)

	var intext []byte

	if *encrypt {
		intext = readfile(*inputPath)
		intext = pad(intext, block.BlockSize())
	} else if *decrypt {
		if *useHex {
			intext = readhexfile(*inputPath)
		} else {
			intext = readfile(*inputPath)
		}
	}

	if *mode == "cbc" {
		if *encrypt {
			inputVec := make([]byte, block.BlockSize())
			// Randomly initialize the input vector
			_, err = rand.Read(inputVec)
			check(err)
			cipher := NewCBC(block, inputVec)
			outtext := cipher.Encrypt(intext)

			// Append the initial input vector to the beginning of the ciphertext
			outtext = append(inputVec, outtext...)
			if *useHex {
				writehexfile(outtext, *outputPath)
			} else {
				writefile(outtext, *outputPath)
			}
		} else if *decrypt {
			// Read the input vector from the beginning of the ciphertext
			inputVec := intext[:block.BlockSize()]
			intext = intext[block.BlockSize():]
			cipher := NewCBC(block, inputVec)

			outtext := cipher.Decrypt(intext)
			outtext = unpad(outtext)
			writefile(outtext, *outputPath)
		}
	} else if *mode == "ecb" {
		cipher := NewECB(block)

		if *encrypt {
			outtext := cipher.Encrypt(intext)
			if *useHex {
				writehexfile(outtext, *outputPath)
			} else {
				writefile(outtext, *outputPath)
			}
		} else if *decrypt {
			outtext := cipher.Decrypt(intext)
			outtext = unpad(outtext)
			writefile(outtext, *outputPath)
		}
	}

}
