/*
	rc4.go

	Implementation of RC4, including the key-scheduling algorithm and
	pseudo-random generation algorithm.

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

	rc4.go Daniel Havir, 2018
*/

package main

import (
	"errors"
)

// RC4 is a class
type RC4 struct {
	s    [256]uint8
	x, y uint8
}

// KSA is the Key-scheduling algorithm
// KSA serves as an RC4 constructor
func KSA(key []byte) *RC4 {
	keyLength := len(key)

	if keyLength < 5 || keyLength > 32 {
		panic(errors.New("Key should be between 5 and 32 characters, i.e. between 40-bits and 256-bits"))
	}
	var rc4 RC4

	for i := 0; i < 256; i++ {
		rc4.s[i] = uint8(i)
	}

	j := uint8(0)

	for i := 0; i < 256; i++ {
		// We don't need to perform module 256 since j is 8-bit uint
		j = (j + rc4.s[i]) + key[i%keyLength]
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]
	}

	// Return pointer to the object
	return &rc4
}

// PRGA is the pseudo-random generation algorithm
// PRGA is an RC4 method
func (rc4 *RC4) PRGA(in []byte) []byte {
	out := make([]byte, len(in))

	i := rc4.x
	j := rc4.y

	for idx := 0; idx < len(in); idx++ {
		i++
		j += rc4.s[i]
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]

		out[idx] = in[idx] ^ rc4.s[rc4.s[i]+rc4.s[j]]
	}

	rc4.x, rc4.y = i, j

	return out
}
