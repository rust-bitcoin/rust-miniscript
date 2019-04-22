[![Status](https://travis-ci.org/apoelstra/rust-miniscript.png?branch=master)](https://travis-ci.org/apoelstra/rust-miniscript)

# Miniscript

Library for handling [Miniscript](http://bitcoin.sipa.be/miniscript/miniscript.html),
which is a subset of Bitcoin Script designed to support simple and general tooling.

In particular, it supports

* Parsing and serializing Miniscript to Script
* Parsing and serializing Miniscript to a human-readable string format
* Determining which public keys and hash preimages are needed to satisfy a Miniscript, at a given time
* Filling in `bitcoin::TxIn` objects with satisfactions to a Miniscript, given valid signatures
* Optimally compiling an ad-hoc "policy language" to Miniscript, with the `policy` flag
* Abstracting Miniscript as an `AbstractPolicy` object on which some more advanced forms of analysis can be done

This library is stable enough that it will no longer publish breaking changes
in minor releases. However, the library (and Miniscript itself) is still under
active development and is not held to the same standards as `rust-bitcoin` or
`rust-secp256k1`.

For this reason, it is not recommended to use it in production.

**Minimim Compiler Version:** 1.22.0

