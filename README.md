Post-quantum signature
=======================

Features
---------

Sign0 is a simple implementation of the [Lamport signature scheme](https://en.wikipedia.org/wiki/Lamport_signature). **It is maybe not the best or the most eficient** but it was designed for **security** and **simplicity**.

Sign0's security is only based on the security of [SHA-512](https://en.wikipedia.org/wiki/SHA-2). Almost every signature system's security is based on the security of a hash function. Sign0 is **only** based on it. 

Assumptions
------------

Sign0 scrurely works only if the following assumptions are true.

* Any environment that "can see" private keys is safe (no possible unauthorized access to data, no malwares, no backdoors, no TEMPEST...).
* **One private key is used once and ONLY ONCE** (this is a limitation of the Lamport system).
* Random number generation is cryptographically secure.
* SHA-512 is secure.

Changelog
----------

Versions of sign0 are composed of 3 numbers X.Y.Z.

X is increased when major changes that can break retro-compatibility happen.

Y is increased when new features are added.

Z is increased when for minor changes such as bug fixes or code clean-ups.

* 0.0.0
  * Initial release

License
--------

All the work related to sign0 is Copyright 2015, Piotr Chmielnicki. The code is under GNU GPL version 3.

User guide
===========

Crypt0 is a set of tools:

* `gensigkeys0`: the command-line command for key generation
* `sign0`: the command-line command for signing
* `verify0`: the command-line command for signature verification

Usages
--------

### gensigkeys0

    Usage:
    
    form 1: gensigkeys0 privkey-file
    form 2: gensigkeys0 number
    
    privkey-file: a .priv.lkey file to generate. If the file exists, only the public key will be generated.
    number      : a number of private keys to generate
    Environment:
    
    CSTRNG: cryptographically secure true random number generator. Readable file expected (multiple files can be supplied separated by ':')
    PRNG  : pseudo-random number generator. Readable file expected (multiple files can be supplied separated by ':')
    
    Return values:
    
    0: success
    9: error

Public keys can be concatenated into a single `.pub.lkey` file. You can bundle 1024 public keys in 64 Kio.

### sign0

    Usage:
    
    sign0 privkey-file file-to-sign
    privkey-file: a valid .priv.lkey file to generate.
    
    Return values:
    
    0: success
    9: error

### verify0

    Usage:
    
    verify0 pubkey-file signature [signed-file]
    pubkey-file: a valid .pub.lkey file
    signature: a valid signature
    signed-file: the signed file (if not specified, signature = signed-file.lsig)
    
    Return values:
    
    0: success
    1: bad signature
    9: other error

Internals
==========

There is only a little diffrence between a basic Lamport public key and a `.pub.lkey` file: the `.pub.lkey` actualy contains the SHA-512 fingerprint of public key.
This is for making the public key smaller (the size is divided by 1024).

The `.lsig` file is the concatenation of the full Lamport public key (checked against its fingerprint) and the Lamport signature.

Building sign0
===============

You will need a Go compiler.
The reference compiler will always be the latest stable release of the official Go compiler.
On Linux a makefile is available, `make all` will compile the project and `make install` will install it for an unprivileged user.
Other options are available. The makefile is easy to read.

