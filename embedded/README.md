# Running

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo run +nightly --target thumbv7m-none-eabi
```

Output should be something like:

```text
heap size 1048576
descriptor sh(wsh(or_d(c:pk_k(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),c:pk_k(0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352))))
p2sh address 3CJxbQBfWAe1ZkKiGQNEYrioV73ZwvBWns
```
