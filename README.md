![Build](https://github.com/rust-bitcoin/rust-miniscript/workflows/Continuous%20integration/badge.svg)

**Minimum Supported Rust Version:** 1.41.1

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
* `no_std` support enabled by disabling the `default-features` and enabling
`"no-std"`. See `embedded/` for an example.

More information can be found in [the documentation](https://docs.rs/miniscript)
or in [the `examples/` directory](https://github.com/apoelstra/rust-miniscript/tree/master/examples)

## Building

The cargo feature `std` is enabled by default. At least one of the features `std` or `no-std` or both must be enabled.

Enabling the `no-std` feature does not disable `std`. To disable the `std` feature you must disable default features. The `no-std` feature only enables additional features required for this crate to be usable without `std`. Both can be enabled without conflict.

## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features (minus
`no-std`) on **Rust 1.41.1** or **Rust 1.47** with `no-std`.

Some dependencies do not play nicely with our MSRV, if you are running the tests
you may need to pin as follows:

```
cargo update --package url --precise 2.2.2
cargo update --package form_urlencoded --precise 1.0.1
cargo update -p once_cell --precise 1.13.1
cargo update -p bzip2 --precise 0.4.2
```

## Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](https://web.libera.chat/?channels=##miniscript) on Libera.


## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
