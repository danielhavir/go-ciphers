/*
	aes.go

	Implementation of ECB and CBC modes of operation.

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

	aes.go Daniel Havir, 2018
*/

package main

import (
	"crypto/cipher"
	"strconv"
)

// ECB is the class for Electronic Code Book mode of operation
type ECB struct {
	aes       cipher.Block
	blockSize int
}

// CBC is the class for the Cipher Block Chaining mode of operation
type CBC struct {
	aes       cipher.Block
	blockSize int
	inputVec  []byte
}

// NewECB is a constructor for the ECB class
func NewECB(b cipher.Block) *ECB {
	return &ECB{
		aes:       b,
		blockSize: b.BlockSize(),
	}
}

// Encrypt is an ECB method for encryption
func (ecb *ECB) Encrypt(in []byte) []byte {
	out := make([]byte, len(in))

	for i := 0; i < len(in); i += ecb.blockSize {
		ecb.aes.Encrypt(out[i:i+ecb.blockSize], in[i:i+ecb.blockSize])
	}

	return out
}

// Decrypt is an ECB method for encryption
func (ecb *ECB) Decrypt(in []byte) []byte {
	if len(in)%ecb.blockSize != 0 {
		panic("The ciphertext does not fill the blocks. Remainder is " +
			strconv.Itoa(len(in)%ecb.blockSize) + " for block size " +
			strconv.Itoa(ecb.blockSize))
	}

	out := make([]byte, len(in))

	for i := 0; i < len(in); i += ecb.blockSize {
		ecb.aes.Decrypt(out[i:i+ecb.blockSize], in[i:i+ecb.blockSize])
	}

	return out
}

// NewCBC is a constructor for the CBC class
func NewCBC(b cipher.Block, inputVec []byte) *CBC {
	return &CBC{
		aes:       b,
		blockSize: b.BlockSize(),
		inputVec:  inputVec,
	}
}

// Encrypt is a CBC method for encryption
func (cbc *CBC) Encrypt(in []byte) []byte {
	out := make([]byte, len(in))

	for i := 0; i < len(in); i += cbc.blockSize {
		xor(out[i:i+cbc.blockSize], in[i:i+cbc.blockSize], cbc.inputVec)
		cbc.aes.Encrypt(out[i:i+cbc.blockSize], out[i:i+cbc.blockSize])
		cbc.inputVec = out[i : i+cbc.blockSize]
	}

	return out
}

// Decrypt is a CBC method for decryption
func (cbc *CBC) Decrypt(in []byte) []byte {
	if len(in)%cbc.blockSize != 0 {
		panic("The ciphertext does not fill the blocks. Remainder is " +
			strconv.Itoa(len(in)%cbc.blockSize) + " for block size " +
			strconv.Itoa(cbc.blockSize))
	}

	out := make([]byte, len(in))

	// Temporarily store the last `blockSize` bytes that will
	// serve as input vector for further encryption afterwards
	lastInputVec := make([]byte, len(cbc.inputVec))
	copy(lastInputVec, in[len(in)-cbc.blockSize:])

	for i := len(in) - cbc.blockSize; i > 0; i -= cbc.blockSize {
		cbc.aes.Decrypt(in[i:i+cbc.blockSize], in[i:i+cbc.blockSize])
		xor(out[i:i+cbc.blockSize], in[i:i+cbc.blockSize], in[i-cbc.blockSize:i])
	}

	cbc.aes.Decrypt(in[:cbc.blockSize], in[:cbc.blockSize])
	xor(out[:cbc.blockSize], in[:cbc.blockSize], cbc.inputVec)

	cbc.inputVec = lastInputVec

	return out
}
