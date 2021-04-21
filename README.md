![Build](https://github.com/rust-bitcoin/rust-miniscript/workflows/Continuous%20integration/badge.svg)

**Minimum Supported Rust Version:** 1.29.0

*This crate uses "2015" edition and won't be ported over "2018" edition
in the near future as this will change the MSRV to 1.31.*

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


## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.29**.

Because some dependencies have broken the build in minor/patch releases, to
compile with 1.29.0 you will need to run the following version-pinning command:
```
cargo update -p cc --precise "1.0.41" --verbose
```

In order to use the `use-serde` feature or to build the unit tests with 1.29.0,
the following version-pinning commands are also needed:
```
cargo update --package "serde" --precise "1.0.98"
cargo update --package "serde_derive" --precise "1.0.98"
```


## Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](http://webchat.freenode.net/?channels=%23%23miniscript) on
freenode.

# Release Notes

See [CHANGELOG.md](CHANGELOG.md).
