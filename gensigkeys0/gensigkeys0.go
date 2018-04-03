//   Copyright (C) 2015 Piotr Chmielnicki
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the Free Software Foundation,
//   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const ExitSuccess int = 0
const ExitError int = 9
const PrivKeyExt string = ".priv.lkey"
const PubKeyExt string = ".pub.lkey"
const PrivKeySize int64 = 512 * 2 * 512 / 8

var Cipher cipher.Stream // AES256_CTR
var Sources []*os.File
var PrivKey *os.File = nil
var PubKey *os.File = nil

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "form 1: gensigkeys0 privkey-file\n")
	fmt.Fprintf(os.Stderr, "form 2: gensigkeys0 number\n\n")
	fmt.Fprintf(os.Stderr, "privkey-file: a .priv.lkey file to generate. If the file exists, only the public key will be generated.\n")
	fmt.Fprintf(os.Stderr, "number      : a number of private keys to generate\n")
	fmt.Fprintf(os.Stderr, "Environment:\n\n")
	fmt.Fprintf(os.Stderr, "CSTRNG: cryptographically secure true random number generator. Readable file expected (multiple files can be supplied separated by ':')\n")
	fmt.Fprintf(os.Stderr, "PRNG  : pseudo-random number generator. Readable file expected (multiple files can be supplied separated by ':')\n\n")
	fmt.Fprintf(os.Stderr, "Return values:\n\n")
	fmt.Fprintf(os.Stderr, "0: success\n")
	fmt.Fprintf(os.Stderr, "9: error\n")
	os.Exit(ExitError)
}

func FatalCheck(err error) {
	if err != nil {
		FatalError(err.Error())
	}
}

func FatalError(err string) {
	fmt.Fprintf(os.Stderr, "genlkeys0: error: %s\n", err)
	CleanExit(ExitError)
}

func CleanExit(status int) {
	for _, f := range Sources {
		if f != nil {
			f.Close()
		}
	}
	if PubKey != nil {
		PubKey.Close()
	}
	if PrivKey != nil {
		PrivKey.Close()
	}
	os.Exit(status)
}

func InitRandom() {
	var sources []string
	sources = append(sources, strings.Split(os.Getenv("CSTRNG"), ":")...)
	if len(sources) == 0 || ((len(sources) == 1) && (sources[0] == "")) {
		fmt.Printf("genlkeys0: notice: no CSTRNG in use.\n")
	}
	sources = append(sources, strings.Split(os.Getenv("PRNG"), ":")...)
	for _, source := range sources {
		if source != "" {
			f, err := os.Open(source)
			FatalCheck(err)
			Sources = append(Sources, f)
		}
	}
	iv := make([]byte, 16)
	aesKey := make([]byte, 32)
	_, err := rand.Read(iv) // There is a ReadFull inside rand.Read
	FatalCheck(err)
	_, err = rand.Read(aesKey)
	FatalCheck(err)
	for _, f := range Sources {
		var i uint64
		_iv := make([]byte, 16)
		_aesKey := make([]byte, 32)
		_, err = io.ReadFull(f, iv)
		FatalCheck(err)
		_, err = io.ReadFull(f, aesKey)
		FatalCheck(err)
		for i = 0; i < 16; i++ {
			iv[i] ^= _iv[i]
		}
		for i = 0; i < 32; i++ {
			aesKey[i] ^= _aesKey[i]
		}
	}
	AES, err := aes.NewCipher(aesKey)
	FatalCheck(err)
	Cipher = cipher.NewCTR(AES, iv)
}

func GenPrivKey() (key []byte) {
	var i int64
	key = make([]byte, PrivKeySize)
	_key := make([]byte, PrivKeySize)
	_, err := rand.Read(key)
	FatalCheck(err)
	for _, f := range Sources {
		_, err := io.ReadFull(f, _key)
		FatalCheck(err)
		for i = 0; i < PrivKeySize; i++ {
			key[i] ^= _key[i]
		}
	}
	Cipher.XORKeyStream(key, key)
	return key
}

func GenPubKey(privKey []byte) (pubKey []byte) {
	var i, j int64
	pubKey = make([]byte, sha512.Size)
	_key := make([]byte, PrivKeySize)
	for i = 0; i < 1024; i++ {
		_h := sha512.Sum512(privKey[i*sha512.Size : (i*sha512.Size)+63])
		for j = 0; j < sha512.Size; j++ {
			_key[(i*sha512.Size)+j] = _h[j]
		}
	}
	_h := sha512.Sum512(_key)
	for i = 0; i < sha512.Size; i++ {
		pubKey[i] = _h[i]
	}
	return pubKey
}

func GenKeyPair(privKey string) {
	var pubKey string = strings.Replace(privKey, PrivKeyExt, PubKeyExt, -1)
	var _priv, _pub []byte
	info, err := os.Stat(privKey)
	if err != nil {
		if os.IsNotExist(err) {
			_priv = GenPrivKey()
			PrivKey, err = os.Create(privKey)
			FatalCheck(err)
			_, err = PrivKey.Write(_priv)
			FatalCheck(err)
			FatalCheck(PrivKey.Close())
			PrivKey = nil
			fmt.Printf("genlkeys0: success: private key %s generated\n", privKey)
		} else {
			FatalCheck(err)
		}
	} else {
		if info.Size() != PrivKeySize {
			FatalError(fmt.Sprintf("existing but invalid key %s", privKey))
		}
		_priv = make([]byte, PrivKeySize)
		PrivKey, err = os.Open(privKey)
		_, err = io.ReadFull(PrivKey, _priv)
		FatalCheck(err)
		FatalCheck(PrivKey.Close())
		PrivKey = nil
		fmt.Printf("genlkeys0: success: loaded private key from %s\n", privKey)
	}
	_pub = GenPubKey(_priv)
	PubKey, err = os.Create(pubKey)
	FatalCheck(err)
	_, err = PubKey.Write(_pub)
	FatalCheck(err)
	FatalCheck(PubKey.Close())
	PubKey = nil
	fmt.Printf("genlkeys0: success: public key %s generated\n", pubKey)
}

func main() {
	if len(os.Args) != 2 {
		Usage()
	}
	indx := strings.Index(os.Args[1], PrivKeyExt)
	if (indx <= 0) || (indx != (len(os.Args[1]) - len(PrivKeyExt))) {
		var i, n uint64
		n, err := strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			Usage()
		}
		InitRandom()
		for i = 0; i < n; i++ {
			GenKeyPair(fmt.Sprintf("%s%s", strconv.FormatInt(time.Now().UnixNano(), 16), PrivKeyExt))
		}
	} else {
		InitRandom()
		GenKeyPair(os.Args[1])
	}
	CleanExit(ExitSuccess)
}
