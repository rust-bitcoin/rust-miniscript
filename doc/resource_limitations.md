TODO: Rust-miniscript behaviour for resource limitations:

# Safe vs Valid vs Sanity/Analyzable/Liftable
This document refers to bitcoin consensus and standardness rules as of bitcoin core release 0.20.

One of Miniscript’s goals are to make advanced Script functionality accommodate both machine and human analysis. However such an analysis is not possible in all cases.

- **Validity**: Validity refers to whether the Miniscript tree constructions follows the grammar rules. For eg: Top level must be `B`, or `thresh` must have all of it's arguments being dissatifyable.
- **Safety**: Whether all satisfactions of Miniscript require a digital signature.
- **Sanity/Analyzable/Liftable**: Even if the given is valid and safe, it does not imply that Miniscript is consensus and standardness complete. That is, there may exist some semantics implied by the lifted miniscript which cannot be realized in bitcoin network rules. This maybe because of three main reasons
    - Miniscript may contain an [invalid timelock and heightlock combination](https://medium.com/blockstream/dont-mix-your-timelocks-d9939b665094).
    - Resource limitations: Discussed in the next section
    - Repeated use of public keys or public key hashes

This library accepts all miniscripts that are safe and valid and the signing logic will correctly work for all of those scripts. However, analyzing/lifting such miniscripts would fail. The functions `Miniscript::parse` and `Miniscript::from_str` only succeed on sane miniscripts. Use the insane versions(`Miniscript::parse_insane` and `Miniscript::from_str_insane`) for dealing with "insane" miniscripts. The descriptor APIs all work only for sane scripts.

# Resource Limitations

Various types of Bitcoin Scripts have different resource limitations, either through consensus or standardness. Some of them affect otherwise valid Miniscripts.

There are two types of limitations within the resource limitations: 1) Those that depend on the satisfactions and 2) limitations independent of satisfactions.

## Limitations independent of satisfactions

Certain limitations like script size are independent of satisfactions and as such those can script creation time. If there is any script that does not satisfy these
- Scripts over 520 bytes are invalid by consensus (P2SH).
- Scripts over 10000 bytes are invalid by consensus (bare, P2SH, P2WSH, P2SH-P2WSH).
- For bare scripts (ie not P2PKH, P2SH, [p2sh-]P2WPKH, [p2sh-]P2WSH), anything but c:pk(key) (P2PK), c:pk_h(key) (P2PKH), and thresh_m(k,...) up to n=3 is invalid by standardness.
- Scripts over 3600 bytes are invalid by standardness (P2WSH, P2SH-P2WSH).

rust-miniscript errors on parsing descriptors with these limitations and the compiler would not create these scripts.

## Limitations dependent on satisfactions

Some limitations are dependent on satisfaction path taken by script. It is possible that certain script satisfaction paths are not valid because they exceed the following limits:

- Script satisfactions where the total number of non-push opcodes plus the number of keys participating in all executed thresh_ms, is above 201, are invalid by consensus (bare, P2SH, P2WSH, P2SH-P2WSH).
- Script satisfactions with a serialized scriptSig over 1650 bytes are invalid by standardness (P2SH).
- Script satisfactions with a witness consisting of over 100 stack elements (excluding the script itself) are invalid by standardness (P2WSH, P2SH-P2WSH).

rust-miniscript correctly parses these miniscripts, but does not allow lifting/analyzing these scripts if any of the spend paths exceeds the above limits. The satisfier logic does **not** guarantee to find the satisfactions for these scripts. The policy compiler would not create such scripts.
