/*
	run.go

	Main function for the RC4 CLI interface.

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
	"flag"
	"fmt"
)

func main() {
	encrypt := flag.Bool("en", false, "Encrypt")
	decrypt := flag.Bool("de", false, "Decrypt")
	inputPath := flag.String("in", "file.txt", "Path to input file.")
	outputPath := flag.String("out", "out", "Path to output file.")
	keyString := flag.String("key", "\x01\x02\x03\x04\x05", "Encryption/decryption key. For encryption, choose a string between 5 and 32 characters.")
	offset := flag.Int("offset", 1536, "Number of bytes to discard before encryption")
	useHex := flag.Bool("hex", false, "Encode to/from hex.")
	flag.Parse()

	if !(*encrypt || *decrypt) {
		fmt.Println("You must specify either either encrypt \"-en\" or decrypt \"-de\"")
	}

	key := []byte(*keyString)

	rc4 := KSA(key)
	if *offset > 0 {
		rc4.PRGA(make([]byte, *offset))
	}

	if *encrypt {
		plain := readfile(*inputPath)
		cipher := rc4.PRGA(plain)
		if *useHex {
			writehexfile(cipher, *outputPath)
		} else {
			writefile(cipher, *outputPath)
		}
	} else if *decrypt {
		var cipher []byte
		if *useHex {
			cipher = readhexfile(*inputPath)
		} else {
			cipher = readfile(*inputPath)
		}
		plain := rc4.PRGA(cipher)
		writefile(plain, *outputPath)
	}

}
