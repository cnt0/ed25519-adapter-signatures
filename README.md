Proof-of-concept implementation of cryptographic protocol from [this paper](https://link.springer.com/chapter/10.1007/978-3-030-54455-3_38) for ed25519 curve.

This protocol is implemented in `test_full_protocol()` function.

However, this protocol doesn't seem to provide an "atomic exchange of secrets". Why Alice generates all the secrets (`R1`, `R2`, `T`), maybe I missed something?

So I decided to modify it. Now Alice generates `R1` and `T`, and Bob generates `R2`. This way they're not obligated to trust each other. This modified protocol is implemented in `test_modified_protocol()` function.

TODO: turn it into usable library.
