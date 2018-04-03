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
const ExitError int = 9
const PrivKeyExt string = ".priv.lkey"
const PrivKeySize int64 = 512 * 2 * 512 / 8
const UsedKeyExt string = ".x.lkey"
const SigExt string = ".lsig"
const SigSize int64 = 512 * 3 * 512 / 8
const BufferSize int64 = 1024 * 1024

var Fkey *os.File = nil
var Fin *os.File = nil
var Fsig *os.File = nil

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "sign0 privkey-file file-to-sign\n")
	fmt.Fprintf(os.Stderr, "privkey-file: a valid .priv.lkey file to generate.\n\n")
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
	fmt.Fprintf(os.Stderr, "sign0: error: %s\n", err)
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
		if (status != ExitSuccess) && (len(os.Args) == 3) {
			os.Remove(fmt.Sprintf("%s%s", os.Args[2], SigExt))
		}
	}
	os.Exit(status)
}

func Sign(h []byte, privKey []byte) (sig []byte) {
	var i, j, b uint
	sig = make([]byte, SigSize)
	for i = 0; i < 1024; i++ {
		_h := sha512.Sum512(privKey[i*sha512.Size : (i*sha512.Size)+63])
		for j = 0; j < sha512.Size; j++ {
			sig[(i*sha512.Size)+j] = _h[j]
		}
	}
	for i = 0; i < 512; i++ {
		if (h[i/8] & (1 << (7 - (i % 8)))) != 0 { // bit i of h is 'one'
			b = 1
		} else {
			b = 0
		}
		for j = 0; j < sha512.Size; j++ {
			sig[((1024+i)*sha512.Size)+j] = privKey[(((i*2)+b)*sha512.Size)+j]
		}
	}
	return sig
}

func ReadPrivKey() (privKey []byte) {
	privKey = make([]byte, PrivKeySize)
	indx := strings.Index(os.Args[1], PrivKeyExt)
	if (indx <= 0) || (indx != (len(os.Args[1]) - len(PrivKeyExt))) {
		Usage()
	}
	info, err := os.Stat(os.Args[1])
	FatalCheck(err)
	if info.Size() != PrivKeySize {
		FatalError(fmt.Sprintf("% is malformed", os.Args[1]))
	}
	Fkey, err = os.Open(os.Args[1])
	FatalCheck(err)
	_, err = io.ReadFull(Fkey, privKey)
	FatalCheck(err)
	return privKey
}

func ReadInput() (h []byte) {
	var i int64
	info, err := os.Stat(os.Args[2])
	FatalCheck(err)
	var toRead int64 = info.Size()
	var blocks int64 = (toRead / BufferSize) + 1
	_h := sha512.New()
	Fin, err = os.Open(os.Args[2])
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
	if len(os.Args) != 3 {
		Usage()
	}
	privKey := ReadPrivKey()
	in := ReadInput()
	sig := Sign(in, privKey)
	FatalCheck(os.Rename(os.Args[1],
		strings.Replace(os.Args[1],
			PrivKeyExt,
			UsedKeyExt, -1)))
	Fsig, err := os.Create(fmt.Sprintf("%s%s", os.Args[2], SigExt))
	FatalCheck(err)
	_, err = Fsig.Write(sig)
	fmt.Printf("sign0: success\n")
	CleanExit(ExitSuccess)
}
