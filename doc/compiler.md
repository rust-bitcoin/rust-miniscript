## Miniscript Compiler

This library provides a Policy compiler that converts bitcoin Policy to Miniscript which can
be used with "compiler" feature. The compiler offers a simple way to interface with
Miniscript and often the first place beginners start to play with Miniscript. There are
however several limitations and caveats to the compiler. This document tries to explain the compiler
inner working as well as the guarantees it offers (or does not offer).

### The Miniscript compiler

As mentioned, the policy compiler takes in input a policy and converts it to a Miniscript. The
compiler algorithm is essentially a brute force based algorithm with some heuristics to
reduce the search space. For each sub-policy, and for each Miniscript type, satisfaction probability
and dissatisfaction probability, the compiler tries to find a Miniscript that minimizes the spending
weight. The spending weight is computed as

`spending_weight = spk_cost + witness_cost`

where `spk_cost` is the cost of the scriptPubKey and `witness_cost` is the expected cost of the witness
with the given satisfaction and dissatisfaction probabilities.

### Compiler guarantees/limitations

If the compiler is able to output a Miniscript

- the Miniscript it produces is a valid Miniscript.
- It also guarantees that the Miniscript produced will be spendable (assuming available witness) under the standardness rules.

The compiler does not guarantee that the Miniscript it produces is the most efficient Miniscript. It maybe possible
to re-arrange the policy tree to produce a even more efficient Miniscript. When dealing with large policies, the compiler also does not guarantee that it will be able to produce a Miniscript even if there exists some Miniscript that can be used to spend the policy. The compiler also does not optimize 1 of n ORs or split thresh into respective ANDs and ORs. Overall, the compiler should be seen as doing a good enough job, but not the best possible job. In our experience, it is still almost always better than hand-written (mini)scripts or scripts. As an example, the compiler was able to produce better versions of lightning HTLC scripts than the ones designed by LN experts. See the following issues for more details: https://github.com/rust-bitcoin/rust-miniscript/issues/126 and https://github.com/rust-bitcoin/rust-miniscript/issues/114

It is possible that higher weight, but lower opcode exists sub-compilation might be best compilation, because the smaller weight sub-policy compilation that we chose exceeds the op-code count. There is also a similar issue with initial stack element count. The compiler does not try to optimize for these cases. If the final compiler output is not a valid Miniscript, it will simply fail and not try sub-optimal compilation that could fit inside these resource limits.

These problems are addressed to a large extent with taproot descriptors as the resource limitations are either really large or completely removed.
This library also supports a taproot descriptor compiler. The details of taproot compiler are can be found in the [taproot compiler document](./taproot_compiler.pdf).

### Non-determinism and stability guarantees of compiler

The compiler outputs are not stable. They can change from version to version, machine to machine or even execution to execution on the same machine. The rust and C++ versions can produce different outputs even if the policy is the same. There could also be other implementations of compiler optimizing for different resource limits.
However, the compiler will **always** output a valid Miniscript which might not be the same as some previous execution. As a simple example, `and_b(A,B)` could become `and_b(B,A)`. Therefore, it is **not recommended** to use policy as a stable identifier for a Miniscript. You should use the policy compiler once, and then use the Miniscript output as a stable identifier.
