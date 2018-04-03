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
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"strings"
)

const ExitSuccess int = 0
const ExitBadSignature int = 1
const ExitError int = 9
const PubKeyExt string = ".pub.lkey"
const SigExt string = ".lsig"
const SigSize int64 = 512 * 3 * 512 / 8
const BufferSize int64 = 1024 * 1024

var Fkey *os.File = nil
var Fin *os.File = nil
var Fsig *os.File = nil

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "verify0 pubkey-file signature [signed-file]\n")
	fmt.Fprintf(os.Stderr, "pubkey-file: a valid .pub.lkey file\n")
	fmt.Fprintf(os.Stderr, "signature: a valid signature\n")
	fmt.Fprintf(os.Stderr, "signed-file: the signed file (if not specified, signature = signed-file.lsig)\n\n")
	fmt.Fprintf(os.Stderr, "Return values:\n\n")
	fmt.Fprintf(os.Stderr, "0: success\n")
	fmt.Fprintf(os.Stderr, "1: bad signature\n")
	fmt.Fprintf(os.Stderr, "9: other error\n")
	os.Exit(ExitError)
}

func FatalCheck(err error) {
	if err != nil {
		FatalError(err.Error())
	}
}

func FatalError(err string) {
	fmt.Fprintf(os.Stderr, "verify0: error: %s\n", err)
	CleanExit(ExitError)
}

func CleanExit(status int) {
	if Fkey != nil {
		Fkey.Close()
	}
	if Fin != nil {
		Fin.Close()
	}
	if Fsig != nil {
		Fsig.Close()
	}
	os.Exit(status)
}

func IsGoodPubkey(pubkey, sig []byte) bool {
	var i, j int
	h := sha512.Sum512(sig[0:(sha512.Size * 1024)])
	for i = 0; i < (len(pubkey) / sha512.Size); i++ {
		for j = 0; j < sha512.Size; j++ {
			if pubkey[(i*sha512.Size)+j] != h[j] {
				break
			}
			if (j + 1) == sha512.Size {
				return true
			}
		}
	}
	return false
}

func Verify(h, sig []byte) bool {
	var i, j, size, indx uint
	for i = 0; i < 512; i++ {
		_h := sha512.Sum512(sig[(1024+i)*sha512.Size : ((1024+i)*sha512.Size)+63])
		if (h[i/8] & (1 << (7 - (i % 8)))) != 0 { // bit i of h is 'one'
			indx = ((i * 2) + 1) * sha512.Size
		} else {
			indx = (i * 2) * sha512.Size
		}
		size = sha512.Size // int => uint
		for j = 0; j < size; j++ {
			if sig[indx+j] != _h[j] {
				return false
			}
		}
	}
	return true
}

func ReadPubKey() (pubKey []byte) {
	indx := strings.Index(os.Args[1], PubKeyExt)
	if (indx <= 0) || (indx != (len(os.Args[1]) - len(PubKeyExt))) {
		Usage()
	}
	info, err := os.Stat(os.Args[1])
	FatalCheck(err)
	if (info.Size() % sha512.Size) != 0 {
		FatalError(fmt.Sprintf("% is malformed", os.Args[1]))
	}
	pubKey = make([]byte, info.Size()) // We assume that the public key smaller than available RAM :-)
	Fkey, err = os.Open(os.Args[1])
	FatalCheck(err)
	_, err = io.ReadFull(Fkey, pubKey)
	FatalCheck(err)
	return pubKey
}

func ReadSig() (sig []byte) {
	sig = make([]byte, SigSize)
	info, err := os.Stat(os.Args[2])
	FatalCheck(err)
	if info.Size() != SigSize {
		FatalError(fmt.Sprintf("% is malformed", os.Args[2]))
	}
	Fsig, err = os.Open(os.Args[2])
	FatalCheck(err)
	_, err = io.ReadFull(Fsig, sig)
	FatalCheck(err)
	return sig
}

func ReadInput() (h []byte) {
	var i int64
	var fname string
	if len(os.Args) == 3 {
		indx := strings.Index(os.Args[2], SigExt)
		if (indx <= 0) || (indx != (len(os.Args[2]) - len(SigExt))) {
			Usage()
		}
		fname = strings.Replace(os.Args[2], SigExt, "", -1)
	} else if len(os.Args) == 4 {
		fname = os.Args[3]
	} else {
		Usage()
	}
	info, err := os.Stat(fname)
	FatalCheck(err)
	var toRead int64 = info.Size()
	var blocks int64 = (toRead / BufferSize) + 1
	_h := sha512.New()
	Fin, err = os.Open(fname)
	for i = 0; i < blocks; i++ {
		todo := BufferSize
		if i == (blocks - 1) {
			todo = toRead % BufferSize
		}
		buff := make([]byte, todo)
		_, err = io.ReadFull(Fin, buff)
		FatalCheck(err)
		_, err = _h.Write(buff)
		FatalCheck(err)
	}
	return _h.Sum(nil)
}

func main() {
	if len(os.Args) < 3 {
		Usage()
	}
	pubKey := ReadPubKey()
	sig := ReadSig()
	if IsGoodPubkey(pubKey, sig) == false {
		fmt.Fprintf(os.Stderr, "verify0: error: bad signature1\n")
		CleanExit(ExitBadSignature)
	}
	if Verify(ReadInput(), sig) == false {
		fmt.Fprintf(os.Stderr, "verify0: error: bad signature\n")
		CleanExit(ExitBadSignature)
	}
	fmt.Printf("verify0: success: good signature\n")
	CleanExit(ExitSuccess)
}
