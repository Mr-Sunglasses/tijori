# Appendix A — Tijori Vault Format Specification v1.0 (draft)

## 1. Conventions

- **MUST / MUST NOT / SHOULD / MAY** as in RFC 2119.
- All integers are **little-endian**, unsigned unless stated. `a || b` is byte concatenation.
- `"TJRI ..."` strings are ASCII with no terminator.
- KiB = 1024 bytes; MiB = 1024 KiB.
- Text is UTF-8. Passwords and names are normalized to **Unicode NFC** before use.
- Structured data is **deterministic CBOR** (RFC 8949 §4.2.1): definite lengths, shortest integer forms, map keys sorted.
- Out of scope for v1: hidden volumes, compression, deduplication, symlinks, extended attributes, hardware keys.

## 2. Drive layout

The vault is the folder `TIJORI` at the root of an **exFAT** volume.

```
/ (exFAT root)
├── README-TIJORI.txt        optional, plain text
└── TIJORI/
    ├── vault.header         1120 bytes (§5)
    ├── vault.header.bak     byte-identical backup
    ├── vault.root.a         root pointer slot A (§8)
    ├── vault.root.b         root pointer slot B
    ├── .lock                only while a writer is active
    └── objects/
        └── 3f/
            └── 3f9a…e1.tjo  64 lowercase hex chars + .tjo
```

- Object path: `objects/<first 2 hex chars>/<64 hex chars>.tjo`.
- Files and directories are both objects and look identical on disk.
- `*.tmp` files are incomplete writes; readers MUST ignore them.

## 3. Primitives

| Name | Algorithm | libsodium equivalent | Sizes |
|---|---|---|---|
| `ARGON2ID` | Argon2id v1.3, **lanes = 1** | `crypto_pwhash` (`ALG_ARGON2ID13`), memlimit = `mem_kib × 1024`, opslimit = `t` | salt 16, out 32 |
| `AEAD` | XChaCha20-Poly1305 (IETF) | `crypto_aead_xchacha20poly1305_ietf_*` | key 32, nonce 24, tag 16 |
| `STREAM` | secretstream XChaCha20-Poly1305 | `crypto_secretstream_xchacha20poly1305_*` | key 32, header 24, +17 bytes per chunk |
| `H(key, msg)` | BLAKE2b, 32-byte output, key optional | `crypto_generichash` | key none or 32 |
| `KDF(key, id)` | BLAKE2b subkey derivation, context `"TJRIv1__"` | `crypto_kdf_derive_from_key` | key 32, id u64, out 32 |

- `KDF(key, id)` equals BLAKE2b(key = key, message = empty, out = 32, salt = `LE64(id) || 0x00×8`, personal = `"TJRIv1__" || 0x00×8`).
- Lanes are fixed at 1 (libsodium supports only 1). Readers MUST reject other values.
- Randomness from the OS CSPRNG only. All tag/MAC/hash comparisons constant-time.
- Every hashed message begins with a distinct ASCII label, giving domain separation.

## 4. Key hierarchy

The Master Key **MK** is 32 random bytes, generated at creation, never stored unwrapped.

Key-encryption keys:

```
Type 1  password:            KEK = ARGON2ID(NFC(password), salt, m, t)
Type 2  password + keyfile:  A   = ARGON2ID(NFC(password), salt, m, t)
                             KF  = H(none, "TJRI keyfile v1" || keyfile_bytes)
                             KEK = H(KF, "TJRI kek v1" || A)
Type 3  recovery phrase:     E   = 32-byte entropy decoded from 24 English BIP-39 words
                             KEK = H(E, "TJRI recovery v1" || salt)
```

Subkeys: `K_hmac = KDF(MK, 1)` (header MAC), `K_root = KDF(MK, 2)` (root pointers), `K_obj = KDF(MK, 3)` (object keys). Ids ≥ 4 reserved.

Object keys:

```
object_key = H(K_obj, "TJRI obj v1" || kind || object_id)
kind = 0x01 file, 0x02 directory; object_id = 32 random bytes
```

Changing a password rewraps MK only. Re-keying (new MK, every object rewritten) is a separate operation.

## 5. Vault header

`vault.header` is exactly **1120 bytes**.

### 5.1 Header layout

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `TJRI` |
| 4 | 2 | `format_major` | `1` |
| 6 | 2 | `format_minor` | `0` |
| 8 | 4 | `required_features` | Readers MUST refuse unknown bits. v1: `0` |
| 12 | 4 | `optional_features` | Unknown bits MAY be ignored. v1: `0` |
| 16 | 16 | `vault_uuid` | Random, fixed for the vault's life |
| 32 | 1024 | `keyslots[8]` | 8 × 128 bytes (§5.2) |
| 1056 | 32 | `reserved` | Zero |
| 1088 | 32 | `header_mac` | `H(K_hmac, header bytes 0..1088)` |

### 5.2 Keyslot (128 bytes)

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 1 | `slot_type` | 0 empty, 1 password, 2 password + keyfile, 3 recovery; 4 reserved (FIDO2) |
| 1 | 1 | `kdf_id` | 1 Argon2id (types 1, 2); 2 BLAKE2b (type 3) |
| 2 | 2 | `reserved` | Zero |
| 4 | 4 | `argon_mem_kib` | Zero for type 3 |
| 8 | 4 | `argon_ops` | Zero for type 3 |
| 12 | 4 | `argon_lanes` | `1`; zero for type 3 |
| 16 | 16 | `salt` | Random; new on every rewrap |
| 32 | 24 | `nonce` | Random per wrap |
| 56 | 48 | `wrapped_mk` | `AEAD(KEK, nonce, MK, ad)` = 32 + 16 tag |
| 104 | 24 | `reserved` | Zero |

Empty slot = 128 zero bytes.

```
ad = "TJRI ks v1" || vault_uuid || slot_index (1 byte, 0–7) || keyslot bytes 0..32
```

### 5.3 MAC and backup

- MAC is checked after MK is unwrapped (constant time).
- `vault.header.bak` MUST equal `vault.header`. Update order: backup first, then primary, each tmp → fsync → rename.
- If the primary fails to parse, unwrap or verify, try the backup. If a keyslot opens but both fail the MAC, report **Tampered**.

### 5.4 Default Argon2id parameters

| Created on | Memory | t | Target |
|---|---|---|---|
| Desktop | 262,144 KiB (256 MiB) | tuned, ≥ 3 | ≈ 1 s on the creating machine |
| Android | 131,072 KiB (128 MiB) | tuned, ≥ 4 | ≈ 1 s on the creating phone |

## 6. Unlock procedure

1. Read `vault.header`: exactly 1120 bytes, magic `TJRI`, `format_major = 1`, no unknown required bits.
2. Check every non-empty slot against §12 limits; any violation → reject this header (then try backup).
3. Choose candidate slots: password → types 1, and 2 if a keyfile was given; recovery phrase → type 3.
4. For each candidate derive the KEK and open `wrapped_mk`. First success wins. None → **WrongSecret**.
5. Derive `K_hmac`, `K_root`, `K_obj`; verify `header_mac`. Failure → repeat with `vault.header.bak`; both fail → **Tampered**.
6. Open root slots A and B (§8.1); use the valid one with higher `rev`. Neither → **Damaged**.
7. Compare with the device rollback record (§10); add warnings to the report.
8. Load the root directory object, verify its hash against the root pointer, show the tree.
9. Wipe password, KEK and keyfile bytes. Keep MK-derived keys in locked memory until lock.

## 7. Objects

### 7.1 Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `object_version` = 1 |
| 1 | 24 | `stream_header` |
| 25 | varies | chunks: `STREAM` ciphertext of ≤ 65,536 plaintext bytes + 17 |

- All chunks but the last carry exactly 65,536 plaintext bytes, tag `MESSAGE`. The last carries 0–65,536 bytes, tag `FINAL`. Data after `FINAL` or a missing `FINAL` → reject.
- Every chunk's associated data = `kind || object_id` (33 bytes).
- Objects are immutable; a change gets a new random `object_id`.

### 7.2 Plaintext stream

```
plaintext = content_length (u64) || content || zero padding
total     = padme(8 + content_length)   if padding is on
          = 8 + content_length          if padding is off
```

Readers MUST check `content_length ≤ total − 8` and that all padding bytes are zero.

### 7.3 Padmé

```
E = floor(log2(L));  S = floor(log2(E)) + 1
mask = 2^(E − S) − 1
padme(L) = (L + mask) & ~mask          (L ≥ 8 here)
```

Examples (content → stored plaintext): 0 → 8; 92 → 104; 992 → 1,024; 65,536 → 67,584; 1,000,000 → 1,015,808; 10^9 → 1,006,632,960. Worst-case overhead ≈ 11.6%.

### 7.4 Observable size

On-disk size = `25 + total + 17 × ceil(total / 65536)`.

## 8. Directory tree and root pointers

### 8.1 Root pointer files (`vault.root.a`, `vault.root.b`)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `root_version` = 1 |
| 1 | 24 | `nonce` |
| 25 | varies | `AEAD(K_root, nonce, cbor, ad)` |

`ad = "TJRI root v1" || vault_uuid || slot_letter` (ASCII `a` or `b`).

CBOR map:

| Key | Field | Type |
|---|---|---|
| 1 | `rev` | uint, +1 per commit |
| 2 | `root_id` | bytes(32) |
| 3 | `root_hash` | bytes(32) = `H(none, root object file bytes)` |
| 4 | `settings` | map: `1` padding (bool), `2` private_only (bool), `3` label (text ≤ 64 bytes) |
| 5 | `written_at` | uint, Unix seconds |
| 6 | `writer_id` | bytes(16) |

### 8.2 Directory objects (kind 0x02)

Content CBOR: `{1: dir_version = 1, 2: [entries…]}`, entries sorted by name bytes.

| Key | Field | Type | Rule |
|---|---|---|---|
| 1 | `name` | text | NFC, §11 |
| 2 | `kind` | uint | 1 file, 2 directory |
| 3 | `id` | bytes(32) | child object ID |
| 4 | `hash` | bytes(32) | `H(none, child object file bytes)` |
| 5 | `size` | uint | content bytes (files only) |
| 6 | `mtime` | int | Unix milliseconds |
| 7 | `mode` | uint | optional; bit 0 = executable |

Readers MUST verify `hash` before decrypting a child. Unknown keys: readers ignore; writers keep them on unchanged entries.

## 9. Writing

### 9.1 Commit

1. Take the write lock.
2. Write new file objects: `<id>.tjo.tmp` → fsync → rename → fsync folder.
3. Write new directory objects for every folder from the change up to the root.
4. Write the new root pointer (`rev + 1`) into the slot holding the **lower** (or invalid) `rev`, via tmp → fsync → rename. **Commit point.**
5. Update the device rollback record.
6. Release the lock. Old objects are left for GC.

### 9.2 Lock

`TIJORI/.lock` created with exclusive-create, containing a random lock ID, writer ID and timestamp. If present, open read-only and say who holds it. A lock older than 10 minutes with no live process MAY be broken after user confirmation. One writer at a time.

### 9.3 Garbage collection

Walk trees reachable from **both** root slots; delete `.tjo` files not reached and any `.tmp` files.

## 10. Rollback detection

Per device, outside the drive: `vault_uuid → { max_rev, root_hash, last_seen }`, encrypted with a key in the OS keychain.

| Drive vs record | Result |
|---|---|
| No record | First use; create record |
| `rev` > `max_rev` | Normal; update |
| `rev` = `max_rev`, same hash | Normal |
| `rev` = `max_rev`, different hash | **Fork warning** |
| `rev` < `max_rev` | **Rollback warning** |

Warnings offer: continue read-only, accept the older state, or cancel.

## 11. Names and metadata

- 1–255 bytes UTF-8 after NFC. No `/`, no NUL, not `.` or `..`.
- Unique within a directory (NFC bytes). Case-sensitive.
- Export/mount to case-insensitive hosts shows clashing or reserved names with a visible suffix; never silently overwrites.
- Stored: `mtime`, optional executable bit. Not stored: creation time, owner, ACLs, xattrs. Symlinks and special files are skipped on import with a warning.
- Writers SHOULD set modified/accessed time of every vault file to 2000-01-01T00:00:00Z.

## 12. Parser limits

| Item | Min | Max |
|---|---|---|
| `vault.header` size | 1120 | 1120 |
| `argon_mem_kib` | 65,536 | 1,048,576 |
| `argon_ops` | 2 | 64 |
| `argon_lanes` | 1 | 1 |
| Non-empty keyslots | 1 | 8 |
| Root pointer file | 41 bytes | 4 KiB |
| Directory plaintext | 8 bytes | 64 MiB |
| Entries per directory | 0 | 200,000 |
| Tree depth | 1 | 256 |
| Name length | 1 byte | 255 bytes |
| Object plaintext | 8 bytes | 2^62 bytes |

Writers SHOULD NOT create slots above 256 MiB. CBOR readers: definite lengths only; no tags, floats or undefined; reject duplicate keys, non-shortest integers and type mismatches.

## 13. Versioning

| Change | Mechanism | Old reader |
|---|---|---|
| Optional new field | New CBOR key | Ignores, preserves |
| Optional feature | `optional_features` bit | Ignores |
| Feature changing how data is read | `required_features` bit | Refuses, names required version |
| New keyslot / KDF | New `slot_type` / `kdf_id` | Skips slot |
| Incompatible redesign | `format_major` = 2 | Refuses |

Upgrading a vault to a newer format MUST ask the user first.

## 14. Security considerations

Visible to anyone holding the drive: that it is a Tijori vault; the number of objects; Padmé-rounded sizes; which keyslot types are used; Argon2 parameters; some exFAT creation times.

Known limits: old headers can survive on flash after a password change (only re-keying revokes an old password); deleted ciphertext can survive on flash; rollback is detected only on devices that saw the newer state; a compromised host sees everything while unlocked; weak passwords are the biggest risk (writers MUST require zxcvbn score ≥ 3).

Deliberate choices: no compression, no deduplication, random 192-bit nonces, immutable objects, keys zeroized and wiped on lock, sleep, drive removal and idle.

## 15. Test vectors (`spec/vectors/`)

| File | Covers | Negative cases |
|---|---|---|
| `kek.json` | KEK for slot types 1–3, NFC and non-ASCII passwords | wrong keyfile, NFD password |
| `keyslot.json` | wrap/unwrap MK | changed parameter, swapped slot index, other vault UUID |
| `subkeys.json` | `K_hmac`, `K_root`, `K_obj`, object keys | — |
| `header.json` | full headers + MAC | flipped MAC bit, unknown required bit, out-of-range Argon2 |
| `padme.json` | padded lengths 8 B … 2^40 | — |
| `object.json` | objects decryptable with given keys | truncated, extended, reordered chunk, wrong kind, non-zero padding |
| `root.json` | root pointers A and B | swapped slot letter, other vault UUID |
| `dir.json` | exact deterministic CBOR bytes | unsorted entries, duplicate names, floats |
| `vault/` | complete small vaults | torn newest root slot must open at previous commit |

Each vector gives inputs and expected outputs in hex, and for negative cases the error class (`wrong_secret`, `tampered`, `damaged`, `unsupported`).
