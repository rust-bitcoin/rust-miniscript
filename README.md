[![Status](https://travis-ci.org/apoelstra/rust-miniscript.png?branch=master)](https://travis-ci.org/apoelstra/rust-miniscript)

**Minimum Supported Rust Version:** 1.22.0

# Miniscript

Library for handling [Miniscript](http://bitcoin.sipa.be/miniscript/),
which is a subset of Bitcoin Script designed to support simple and general
tooling. Miniscripts represent threshold circuits of spending conditions,
and can therefore be easily visualized or serialized as human-readable
strings.

## High-Level Features

This library supports

* [Output descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
including embedded Miniscripts
* Parsing and serializing descriptors to a human-readable string format
* Compilation of abstract spending policies to Miniscript (enabled by the
`compiler` flag)
* Semantic analysis of Miniscripts and spending policies, with user-defined
public key types
* Encoding and decoding Miniscript as Bitcoin Script, given key types that
are convertible to `bitcoin::PublicKey`
* Determining satisfiability, and optimal witnesses, for a given descriptor;
completing an unsigned `bitcoin::TxIn` with appropriate data
* Determining the specific keys, hash preimages and timelocks used to spend
coins in a given Bitcoin transaction

More information can be found in [the documentation](https://docs.rs/miniscript)
or in [the `examples/` directory](https://github.com/apoelstra/rust-miniscript/tree/master/examples)

## Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](http://webchat.freenode.net/?channels=%23%23miniscript) on
freenode.

## Stability

This library is stable enough that it will no longer publish breaking changes
in minor releases. However, the library (and Miniscript itself) is still under
active development and is not held to the same standards as `rust-bitcoin` or
`rust-secp256k1`.

For this reason, it is not recommended to use it in production.


