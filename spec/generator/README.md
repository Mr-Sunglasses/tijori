# Vector generator

An independent Python implementation of the Tijori format that writes the
test vectors in [`../vectors`](../vectors). It uses libsodium (PyNaCl) for
every primitive, cross-checks BLAKE2b and `crypto_kdf` with `hashlib`, and
cross-checks deterministic CBOR with `cbor2`. It never calls the Rust core.

See [`../vectors/README.md`](../vectors/README.md) for usage and conventions.
Requires Python 3.12 and the packages in `requirements.txt`.
