### Security Advisory on Miniscript MinimalIF bug (`d:` wrapper is not `u` )

_ALl of the affected versions have been yanked_. Users should upgrade to `1.1.0`,
`2.1.0`, `3.1.0`, `4.1.0`, `5.2.0`, `6.1.0` or `7.0.0`.

Andrew Poelstra recently discovered a vulnerability in miniscript spec that could
potentially allow miners to steal coins locked in certain miniscript fragments. We
recommend all users upgrade to the latest miniscript version as soon as possible.
Details of the vulnerability are mentioned towards the end of the post.

For ease of upgrade, we have released a bug fix release for versions 1.1.0, 2.1.0,
3.1.0, 4.1.0, 5.2.0, and 6.1.0. All other previous releases have been yanked for
safety. The miniscript website (bitcoin.sipa.be/miniscript) and compiler have
been updated so that they no longer produce the vulnerable scripts.

### Details of the vulnerability:

The wrapper `d` (`OP_DUP OP_IF [X] OP_ENDIF`) was incorrectly marked to have the
`u` property. The `u` property states "When [X] is satisfied, this expression will
put an exact 1 on the stack (as opposed to any nonzero value)". However, this is
only true if we have a `MINIMALIF` consensus rule. Unfortunately, this is only a
policy rule for segwitv0 and p2sh scripts. `MINIMALIF` is a consensus rule since
the taproot upgrade.

In other words, this vulnerability only affects coins with sh, wsh and shwsh. If
your coins are under taproot descriptor, you are not vulnerable.

### How can this be exploited?

Certain combinations of `d` wrapper inside `or_c` or `or_d` are innocuous. However,
when combined with thresh, this could allow miners to steal coins from the threshold
provided the underlying condition in `d` wrapper is satisfied.

Consider the script `thresh(2, pk(A), s:pk(B), sdv:older(2) )` . Semantically, this
means that either A and B can spend this before 2 blocks, or after 2 blocks either
A or B can spend these funds. The `thresh` fragment expects all of its children to
result in either 1/0 (not any other number). However, a miner could malleate the
user-provided OP_1 in `d` wrapper to OP_2, setting empty signatures A and B bypassing
the threshold check.

### How to check if you are affected?

If the latest version of miniscript cannot spend your funds, you could be
affected. In particular, if you are using a `thresh` construction like above,
and the timelock has expired, your coins are vulnerable. If the timelock has not
expired, your funds are not at risk if you move them before the timelock activates.

If you cannot spend funds with the new update, please contact us. We will assist
you with next steps.

Alekos(@afillini) and Riccardo Casetta scanned the blockchain for all spent outputs since
the miniscript release to check if there were vulnerable. Fortunately, they could
not find any funds that were vulnerable.

If you have more questions or need any assistance. Feel free to contact us via IRC or email.