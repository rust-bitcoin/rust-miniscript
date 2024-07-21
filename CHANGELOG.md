# # 12.2.0 - July 20, 2024

- Fix panics while decoding large miniscripts from script [#712](https://github.com/rust-bitcoin/rust-miniscript/pull/712)

# 12.1.0 - July 9, 2024

- Make `LoggerAssetProvider` constructible [#697](https://github.com/rust-bitcoin/rust-miniscript/pull/697)
- Explicitly track recursion depth in fragments [#704](https://github.com/rust-bitcoin/rust-miniscript/pull/704)

# 12.0.0 - May 22, 2024

- Update MSRV to Rust `v1.56.1` [#639](https://github.com/rust-bitcoin/rust-miniscript/pull/639)
- Remove sketchy `LikelyFalse` error [#645](https://github.com/rust-bitcoin/rust-miniscript/pull/645)
- Drop the `Property` trait entirely [#652](https://github.com/rust-bitcoin/rust-miniscript/pull/652)
- Improve compiler logic when deciding between conjunctions and `multi`/`multi_a` [#657](https://github.com/rust-bitcoin/rust-miniscript/pull/657)
- Several locktime improvements [#654](https://github.com/rust-bitcoin/rust-miniscript/pull/654)
- Derive `Hash` for `pub` items [#659](https://github.com/rust-bitcoin/rust-miniscript/pull/659)
- Upgrade `bech32` dependency to `v0.11.0` [#661](https://github.com/rust-bitcoin/rust-miniscript/pull/661)
- Return `Weight` type for `max_weight_to_satisfy` methods [#664](https://github.com/rust-bitcoin/rust-miniscript/pull/664)

## Introduce a new `Threshold` type

- [#660](https://github.com/rust-bitcoin/rust-miniscript/pull/660)
- [#674](https://github.com/rust-bitcoin/rust-miniscript/pull/674)
- [#676](https://github.com/rust-bitcoin/rust-miniscript/pull/676)

## Performance/compiled time improvements

- Remove recursion in `semantic` module [#612](https://github.com/rust-bitcoin/rust-miniscript/pull/612)
- Remove generics from `Error` by making fragment a `String` [#642](https://github.com/rust-bitcoin/rust-miniscript/pull/642)
- Remove unused generic on `check_witness` [#644](https://github.com/rust-bitcoin/rust-miniscript/pull/644)
- Add conditional formatting for `Terminal` [#651](https://github.com/rust-bitcoin/rust-miniscript/pull/651)

## Other internal cleanups / improvements

- Remove `internals` dependency [#631](https://github.com/rust-bitcoin/rust-miniscript/pull/631)
- Introduce an example binary useful for profiling [#646](https://github.com/rust-bitcoin/rust-miniscript/pull/646)
- Refactor out `type_check` [#649](https://github.com/rust-bitcoin/rust-miniscript/pull/649)
- Replace macros with traits, using trait bound trick [#650](https://github.com/rust-bitcoin/rust-miniscript/pull/650)

# 11.0.0 - November 16, 2023

- Add the planning module [#592](https://github.com/rust-bitcoin/rust-miniscript/pull/592)
- Bump MSRV to 1.48 [#569](https://github.com/rust-bitcoin/rust-miniscript/pull/569)
- Upgrade `rust-bitcoin` to v0.31.0 [#618](https://github.com/rust-bitcoin/rust-miniscript/pull/618)
- Reduce binary bloat by removing generic param from type_check [584](https://github.com/rust-bitcoin/rust-miniscript/pull/584)
- Add height to tap tree [588](https://github.com/rust-bitcoin/rust-miniscript/pull/588)
- Improve `TapTree` API [617](https://github.com/rust-bitcoin/rust-miniscript/pull/617)
- Remove "unstable" feature [482](https://github.com/rust-bitcoin/rust-miniscript/pull/482)
- Remove hashbrown dependency [564](https://github.com/rust-bitcoin/rust-miniscript/pull/564)
- Add method to convert expr_raw_pkh into pkh [557](https://github.com/rust-bitcoin/rust-miniscript/pull/557)
- psbt: Rewrite input replacement to avoid forgetting fields [568](https://github.com/rust-bitcoin/rust-miniscript/pull/568)

# 10.0.0 - May 24, 2023

- Works with rust-bitcoin 0.30.0
- Add support for [multi-path descriptors] (https://github.com/rust-bitcoin/rust-miniscript#470)
- Fix bugs in [max_satisfaction_weight](https://github.com/rust-bitcoin/rust-miniscript#476)
- DefiniteDescriptorKey: provide additional methods for converting to a DescriptorPublicKey (https://github.com/rust-bitcoin/rust-miniscript#492)
- Remove `DummyKey` (https://github.com/rust-bitcoin/rust-miniscript#508)
- Update TranslatePk trait to cleanly separate errors during translation itself and script context errors. [PR](https://github.com/rust-bitcoin/rust-miniscript/pull/493/)
- Fixes to improve CI infrastructure with [Nix](https://github.com/rust-bitcoin/rust-miniscript/pull/538/) support and [bitcoind](https://github.com/rust-bitcoin/rust-miniscript/pull/536/) tests.

# 9.0.0 - November 5, 2022

- Fixed a bug dealing with dissatisfying pkh inside thresh
- Changed the signature of `Satisfier::lookup_raw_pkh_pk` API. Only custom implementations
  of `Satisfier` need to be updated. The psbt APIs are unchanged.
- Fixed a bug related to display of `raw_pk_h`. These descriptors are experimental
  and only usable by opting via `ExtParams` while parsing string.
# 8.0.0 - October 20, 2022

This release contains several significant API overhauls, as well as a bump
of our MSRV from 1.29 to 1.41. Users are encouraged to update their compiler
to 1.41 *before* updating to this version.

It includes more Taproot support, but users should be aware that Taproot
support for Miniscript is **not** standardized and is subject to change in
the future. See [this gist](https://gist.github.com/sipa/06c5c844df155d4e5044c2c8cac9c05e)
for our thinking regarding this at the time of release.

- Works with bitcoin crate 0.29
- Correctly [return an error when `SortedMulti` is constructed with too many keys](https://github.com/rust-bitcoin/rust-miniscript/pull/366/)
- Cleanly separate [`experimental/insane miniscripts`](https://github.com/rust-bitcoin/rust-miniscript/pull/461) from sane miniscripts.
- allow disabling the checksum with [`alternate Display`](https://github.com/rust-bitcoin/rust-miniscript/pull/478)
- Correct [`max_satisfaction_size` of `from_multi_a` fragment](https://github.com/rust-bitcoin/rust-miniscript/pull/346/)
- [Add `PsbtInputExt` trait with `update_with_descriptor` method](https://github.com/rust-bitcoin/rust-miniscript/pull/339/) and [`PsbtOutputExt` trait](https://github.com/rust-bitcoin/rust-miniscript/pull/465/)
- Rename [several descriptor types](https://github.com/rust-bitcoin/rust-miniscript/pull/376/) to reduce redundancy
- [**Bump MSRV to 1.41** and edition to 2018](https://github.com/rust-bitcoin/rust-miniscript/pull/365/)
- Rename [`as_public` to `to_public` on some descriptor key types](https://github.com/rust-bitcoin/rust-miniscript/pull/377/)
- Split fully derived `DescriptorPublicKey`s [into their own type](https://github.com/rust-bitcoin/rust-miniscript/pull/345/) [followup](https://github.com/rust-bitcoin/rust-miniscript/pull/448/)
- [Remove the `DescriptorTrait`](https://github.com/rust-bitcoin/rust-miniscript/pull/386/) in favor of the `Descriptor` enum
- Fix signature costing [to account for ECDSA vs Schnorr](https://github.com/rust-bitcoin/rust-miniscript/pull/340/)
- **Add a Taproot-enabled compiler** [v1](https://github.com/rust-bitcoin/rust-miniscript/pull/291/) [v2](https://github.com/rust-bitcoin/rust-miniscript/pull/342/) [v3](https://github.com/rust-bitcoin/rust-miniscript/pull/418/)
- Rename [`stackelem` to `stack_elem`](https://github.com/rust-bitcoin/rust-miniscript/pull/411/) in the interpreter
- Add [`no-std`](https://github.com/rust-bitcoin/rust-miniscript/pull/277)
- Reworked the [`TranslatePk`](https://github.com/rust-bitcoin/rust-miniscript/pull/426) APIs. Add a Translator trait to cleanly allow downstream users without dealing with APIs that accept function pointers. Also provides `translate_assoc_clone` and `translate_assoc_fail` macros for helping in writing code.
- Updated [`MiniscriptKey trait`](https://github.com/rust-bitcoin/rust-miniscript/pull/434),https://github.com/rust-bitcoin/rust-miniscript/pull/439 to accept associated types for Sha256, Hash256, Ripemd160 and
Hash160. This allows users to write abstract miniscripts hashes as "sha256(H)" instead of specifying the entire hash in the string.
that updates the psbt with descriptor bip32 paths.
- Re-name [`as_public`](https://github.com/rust-bitcoin/rust-miniscript/pull/377) APIs -> `to_public`
- Significantly improve the [timelock](https://github.com/rust-bitcoin/rust-miniscript/pull/414) code with new rust-bitcoin APIs.
- rust-miniscript minor implementation detail: `PkH` fragment now has `Pk` generic instead of `Pk::Hash`. This only concerns users
that operate with `MiniscriptKey = bitcoin::PublicKey` or users that use custom implementation of `MiniscriptKey`. Users that use
`DescriptorPublicKey` need not be concerned. See [PR](https://github.com/rust-bitcoin/rust-miniscript/pull/431) for details.
  - To elaborate, "pkh(<20-byte-hex>)" is no longer parsed by the `MiniscriptKey = bitcoin::PublicKey`.
This is consistent with the descriptor spec as defined. Parsing from `bitcoin::Script` for pkh<20-byte-hex> is still supported, but the library would not analyze them. These raw descriptors are still in spec discussions. Rust-miniscript will support them once they are completely specified.

# 7.0.0 - April 20, 2022

- Fixed miniscript type system bug. This is a security vulnerability and users are strongly encouraged to upgrade.
See this (link)[https://github.com/rust-bitcoin/rust-miniscript/pull/349/commits/db97c39afa4053c2c3917f04392f6e24964b3972] for details.
- Support for `tr` descriptors with miniscript leaves and multi_a fragment
- Changes to MiniscriptKey and ToPublicKey traits for x-only keys support
- Add `PsbtExt` trait for psbt operations
  - `Psbt::update_desc` adds information from a descriptor to a psbt. This figures
    out the type of the descriptor and adds corresponding redeem script/witness script
    and tap tree information
- Add `derived_descriptor` API to Descriptor so that users no longer need to use
`translate` APIs. See examples/`xpub_descriptor` for usage
- Update `DescriptorTrait`: `script_code` and `explicit_script` can now fail because
  of taproot descriptors
- Add `PreTaprootDescriptor` and `PreTaprootDescriptorTrait` to support non-failing versions
  of `script_code` and `explicit_script` for non taproot descriptors
- Overhaul the interpreter API to provide simpler APIs `iter(prevouts)` and `iter_assume_sig()`
  so that it no longer takes a closure input.
- Add interpreter support for taproot transactions.
- Works with rust-bitcoin 0.28.0
# 6.0.1 - Aug 5, 2021

- The `lift` method on a Miniscript node was fixed. It would previously mix up
  the `X` and `Y` argument of an `andor` fragment.

# 6.0.0 - Jul 29, 2021

- bump `rust-bitcoin` to 0.27
- several bugfixes

# 5.0.0 - Jan 14, 2021

- Remove `PkCtx` from the API
- Move descriptors into their own types, with an enum containing all of them
- Move descriptor functionality into a trait
- Remove `FromStr` bound from `MiniscriptKey`and `MiniscriptKey::Hash`
- Various `DescriptorPublicKey` improvements
- Allow hardened paths in `DescriptorPublicKey`, remove direct `ToPublicKey` implementation
- Change `Option` to `Result` in all APIs
- bump `rust-bitcoin` to 0.26

# 4.0.0 - Nov 23, 2020

- Add support for parsing secret keys
- Add sortedmulti descriptor
- Added standardness and other sanity checks
- Cleaned up `Error` type and return values of most of the API
- Overhauled `satisfied_constraints` module into a new `Iterpreter` API

# 3.0.0 - Oct 13, 2020

- **Bump MSRV to 1.29**

# 2.0.0 - Oct 1, 2020

- Changes to the miniscript type system to detect an invalid
  combination of heightlocks and timelocks
     - Lift miniscripts can now fail. Earlier it always succeeded and gave
       the resulting Semantic Policy
     - Compiler will not compile policies that contain at least one
     unspendable path
- Added support for Descriptor PublicKeys(xpub)
- Added a generic psbt finalizer and extractor
- Updated Satisfaction API for checking time/height before setting satisfaction
- Added a policy entailment API for more miniscript semantic analysis

# 1.0.0 - July 6, 2020

- Added the following aliases to miniscript for ease of operations
	- Rename `pk` to `pk_k`
	- Rename `thresh_m` to `multi`
	- Add alias `pk(K)` = `c:pk_k(K)`
	- Add alias `pkh(K)` = `c:pk_h(K)`
- Fixed Miniscript parser bugs when decoding Hashlocks
- Added scriptContext(`Legacy` and `Segwitv0`) to Miniscript.
- Miscellaneous fixes against DoS attacks for heavy nesting.
- Fixed Satisfier bug that caused flipping of arguments for `and_v` and `and_n` and `and_or`

