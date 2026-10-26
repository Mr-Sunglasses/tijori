# Test vectors

Produced by [`../generator/gen.py`](../generator/gen.py) using libsodium
(PyNaCl), never by the Rust core. Every implementation of the format must pass
all of them.

| File | Covers |
|---|---|
| `kek.json` | KEK for slot types 1–3, NFC and non-ASCII passwords |
| `keyslot.json` | Wrap/unwrap of MK in one keyslot |
| `subkeys.json` | `K_hmac`, `K_root`, `K_obj`, object keys |
| `header.json` | Full 1120-byte headers and MAC (unlock steps 1–5) |
| `padme.json` | Padmé lengths, content length → stored plaintext → disk size |
| `object.json` | Encrypted objects (random stream headers: decrypt, do not re-encrypt) |
| `root.json` | Root pointers for slots A and B |
| `dir.json` | Exact deterministic CBOR for directories |
| `vault.json` + `vault/` | Complete small vaults, including a torn newest root slot |

## Conventions

- Bytes are lowercase hex. Text is UTF-8 JSON strings.
- `cases` must succeed and match the expected outputs. `negative` cases must
  fail with exactly the error class in `error`: `wrong_secret`, `tampered`,
  `damaged` or `unsupported`.
- Large contents are given as `{"pattern": "mod251", "len": N}`: byte `i` is
  `i % 251`. Small ones are `{"hex": "..."}`.
- In `object.json`, a negative case with `base` is a mutation of the positive
  case of that name: `truncate_to`, `append_hex`, `swap` (`[a, b, c, d]` swaps
  the ranges `[a, b)` and `[c, d)`) or `set_byte` (`[offset, value]`).
- `header.json` negative cases apply to a single header with no backup.
- Argon2id uses the minimum parameters the reader limits allow
  (64 MiB, t = 2) so tests stay fast.

## Error classes chosen where the spec leaves room

- Anything that fails authentication, or is truncated or extended, is
  `tampered`.
- Structural problems inside authenticated data (bad CBOR, non-zero padding,
  wrong tag, missing field) are `damaged`: only a key holder could write them.
- Parameters outside the §12 limits are `damaged`.
- A header with no usable slot for the secret, or a slot whose stored
  parameters, index or vault UUID were changed, is `wrong_secret`.

## Regenerating

```sh
cd spec/generator
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python gen.py           # rewrites everything (object.json and vault/ change every run)
.venv/bin/python gen.py --check   # deterministic files must match the committed ones
```
