# Cipher Implementations

This project is an implementation of the following ciphers - RC4 and two Advanced Encryption Standards (AES) modes of operation, namely ECB and CBC.

____

## Setup
### Requirements
* [go](https://golang.org/dl/)

### Install go
* `cd setup`
* `bash install-go.sh`
* `export PATH=$PATH:/usr/local/go/bin`

Test:
* `go version`
* `go env`

### Uninstall go
* `cd setup`
* `sudo bash uninstall-go.sh`

# RC4

RC4 (also known as ARC4 or ARCFOUR) is a stream cipher. Even though **RC4 has now been proven to be cryptographically insecure**, it's an interesting cipher that have historically been wildly used in protocols such as WEP.

## Build
* Run `go build gorc4/*.go` to compile all RC4-related .go files

## Run
* Run `./rc4 -en -in=<input_file> -out=<output_file> -key=<password>` for encryption
* Run `./rc4 -de -in=<input_file> -out=<output_file> -key=<password>` for decryption
* Optionally, you can also:
    * Specify the preferred offset, i.e. number of bytes of the key stream to be discarded in the beginning. By default, offset is set to 1536 bytes as recommended in [RFC4345](https://tools.ietf.org/html/rfc4345)
    * Use the `-hex` flag to encode encrypted ciphertext to hex encoding, or decode ciphertext for decription from hex encoding.

### Help
* For more info run `./rc4 -h`

## Tests
This project also implements Test Vectors for the RC4 (RFC6229, see Resource).

* Navigate to **gorc4**: `cd gorc4`
* Run the tests: `go test`

## References
* [Original posting of RC4 algorithm to Cypherpunks mailing list](http://cypherpunks.venona.com/archive/1994/09/msg00304.html)
* Improved Arcfour Modes for the Secure Shell (SSH) Transport Layer Protocol [RFC4345](https://tools.ietf.org/html/rfc4345)
* Test Vectors for the Stream Cipher RC4 [RFC6229](https://tools.ietf.org/html/rfc6229)
* Rise R., Cho Suk-Hyun, Kaylor D. - [RC4 Encryption](https://sites.math.washington.edu/~nichifor/310_2008_Spring/Pres_RC4%20Encryption.pdf)

## Other implementations
* [OpenSSL RC4 implementation](https://github.com/plenluno/openssl/tree/master/openssl/crypto/rc4)
* [Official Go RC4 implementation](https://golang.org/pkg/crypto/rc4/)

# AES - ECB, CBC
AES is a U.S. National Insitute of Standards and Technology (NIST) specification for the encryption of electronic data. For this project, I chose 2 modes of operation, namely ECB and CBC. CBC is arguably the most common. **ECB is not a secure mode of operation and serves solely as demonstration.**

## Build
* Run `go build goaes/*.go` to compile all AES-related .go files

## Run
* Run `./aes -en -in=<input_file> -out=<output_file> -key=<password>` for encryption
* Run `./aes -de -in=<input_file> -out=<output_file> -key=<password>` for decryption
* Optionally, you can also:
    * Specify the preferred mode of operation ("ecb" or "cbc"). By default, "cbc" is used as "ecb" is NOT a secure mode of operation.
    * Use the `-hex` flag to encode encrypted ciphertext to hex encoding, or decode ciphertext for decription from hex encoding.

Please note that **password must be either 128, 192 or 256 bits long, i.e. 16, 24 or 32 bytes / characters long.

### Help
* For more info run `./aes -h`

## Tests
This project also implements official AES Known Answer Tests (KAT) downloaded from [here](http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip)

* Download the .zip archive containing KAT files from [here](http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip). Make sure it is in the `goaes/jsontests` directory.
* Run `bash setup/aes-tests.sh` to extract and parse the KAT files
* Navigate to **goaes**: `cd goaes`
* Run the tests: `go test`

## References
* NIST SP 800-38A: [Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
* Mezenes A., van Ooorschot P. C., Vanstone S. A. - Handbook of Applied Cryptography
* Aumasson, Jean-Philippe. Serious Cryptography: a Practical Introduction to Modern Encryption.
* Gligor V. D, Donescu P. - [Fast Encryption and Authentication: XCBC Encryption and XECB Authentication Modes](http://web.cs.ucdavis.edu/~rogaway/ocb/xecb-mac-spec.pdf)
* [Golang AES library](https://golang.org/pkg/crypto/aes/)

## Other implementations
* [OpenSSL AES implementation](https://github.com/openssl/openssl/tree/master/crypto/aes)
* [Official Go AES modes of operation implementation](https://golang.org/pkg/crypto/cipher/) (CBC only)
