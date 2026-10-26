#!/usr/bin/env python3
"""Generate the Tijori test vectors listed in spec/SPEC.md section 15.

This is an independent implementation of the format: it uses libsodium (via
PyNaCl) for every primitive, hashlib to cross-check BLAKE2b and crypto_kdf,
cbor2 to cross-check deterministic CBOR, and mnemonic for BIP-39. It never
calls the Rust core.

Everything is deterministic (inputs come from det()) except secretstream
headers, which libsodium always draws at random. So object.json and vault/
change on every run; all other files are byte-stable and `--check` verifies
that the committed copies match a fresh run.

Usage:
    python gen.py [--out DIR]     write vectors (default: ../vectors)
    python gen.py --only F...     write only some files (object.json and vault.json are random)
    python gen.py --check         regenerate deterministic files and compare
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import unicodedata
from pathlib import Path

import cbor2
import nacl.bindings as nb
from mnemonic import Mnemonic

TAG_MESSAGE = nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL
TAG_PUSH = nb.crypto_secretstream_xchacha20poly1305_TAG_PUSH
CHUNK = 65536
HEADER_LEN = 1120

# The cheapest Argon2id parameters the reader limits allow (section 12), so
# that vector tests stay fast. Real vaults use far more (section 5.4).
MEM_KIB = 65536
OPS = 2

KIND_FILE = 1
KIND_DIR = 2

DETERMINISTIC_FILES = [
    "kek.json",
    "keyslot.json",
    "subkeys.json",
    "header.json",
    "padme.json",
    "root.json",
    "dir.json",
]
RANDOM_FILES = ["object.json"]

# ---------------------------------------------------------------------------
# Helpers


def det(label: str, n: int) -> bytes:
    """Deterministic pseudo-random bytes, so regenerated vectors are stable."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.blake2b(
            f"{label}#{i}".encode(), digest_size=64, person=b"TJRI-vectors"
        ).digest()
        i += 1
    return out[:n]


def hx(b: bytes) -> str:
    return b.hex()


def pattern(n: int) -> bytes:
    """Content pattern used for large files: byte i is i mod 251."""
    return bytes(i % 251 for i in range(n))


def content_json(data: bytes) -> dict:
    if len(data) <= 4096:
        return {"hex": hx(data)}
    assert data == pattern(len(data))
    return {"pattern": "mod251", "len": len(data)}


def nfc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode()


# ---------------------------------------------------------------------------
# Primitives (section 3)


def H(key, *parts: bytes) -> bytes:
    msg = b"".join(parts)
    a = hashlib.blake2b(msg, digest_size=32, key=key or b"").digest()
    b = nb.crypto_generichash_blake2b_salt_personal(msg, digest_size=32, key=key or b"")
    assert a == b
    return a


def KDF(key: bytes, sub_id: int) -> bytes:
    salt = struct.pack("<Q", sub_id) + bytes(8)
    person = b"TJRIv1__" + bytes(8)
    a = hashlib.blake2b(b"", digest_size=32, key=key, salt=salt, person=person).digest()
    b = nb.crypto_generichash_blake2b_salt_personal(
        b"", digest_size=32, key=key, salt=salt, person=person
    )
    assert a == b
    return a


_argon_cache: dict = {}


def ARGON2ID(pw: bytes, salt: bytes, mem_kib: int, ops: int) -> bytes:
    k = (pw, salt, mem_kib, ops)
    if k not in _argon_cache:
        _argon_cache[k] = nb.crypto_pwhash_alg(
            32, pw, salt, ops, mem_kib * 1024, nb.crypto_pwhash_ALG_ARGON2ID13
        )
    return _argon_cache[k]


def aead_encrypt(key: bytes, nonce: bytes, msg: bytes, ad: bytes) -> bytes:
    return nb.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, nonce, key)


def stream_encrypt(key: bytes, ad: bytes, chunks):
    """Encrypt [(plaintext, tag), ...] with secretstream.

    Returns (header, [ciphertext chunk, ...]). The header is random.
    """
    state = nb.crypto_secretstream_xchacha20poly1305_state()
    header = nb.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    out = [nb.crypto_secretstream_xchacha20poly1305_push(state, m, ad, tag) for m, tag in chunks]
    return header, out


# ---------------------------------------------------------------------------
# Keys (section 4)


def kek_password(pw: str, salt: bytes, mem: int, ops: int) -> bytes:
    return ARGON2ID(nfc(pw), salt, mem, ops)


def kek_keyfile_parts(pw: str, keyfile: bytes, salt: bytes, mem: int, ops: int):
    a = ARGON2ID(nfc(pw), salt, mem, ops)
    kf = H(None, b"TJRI keyfile v1", keyfile)
    return a, kf, H(kf, b"TJRI kek v1", a)


def kek_recovery(entropy: bytes, salt: bytes) -> bytes:
    return H(entropy, b"TJRI recovery v1", salt)


def subkeys(mk: bytes):
    return KDF(mk, 1), KDF(mk, 2), KDF(mk, 3)


def object_key(k_obj: bytes, kind: int, oid: bytes) -> bytes:
    return H(k_obj, b"TJRI obj v1", bytes([kind]), oid)


MNEMO = Mnemonic("english")


def phrase_of(entropy: bytes) -> str:
    return MNEMO.to_mnemonic(entropy)


# ---------------------------------------------------------------------------
# Header and keyslots (section 5)


def slot_prefix(slot_type, kdf_id, mem, ops, lanes, salt) -> bytes:
    p = struct.pack("<BBHIII", slot_type, kdf_id, 0, mem, ops, lanes) + salt
    assert len(p) == 32
    return p


def slot_ad(uuid: bytes, index: int, prefix: bytes) -> bytes:
    return b"TJRI ks v1" + uuid + bytes([index]) + prefix


def secret_kek(slot_type, secret, salt, mem, ops) -> bytes:
    if slot_type == 1:
        return kek_password(secret["password"], salt, mem, ops)
    if slot_type == 2:
        return kek_keyfile_parts(secret["password"], secret["keyfile"], salt, mem, ops)[2]
    if slot_type == 3:
        return kek_recovery(secret["entropy"], salt)
    raise ValueError(slot_type)


def make_slot(uuid, index, slot_type, secret, mk, label, mem=MEM_KIB, ops=OPS, kek_params=None):
    """Build a 128-byte keyslot. `kek_params` overrides the parameters used to
    derive the KEK (for negative cases where the stored ones are changed)."""
    salt = det(f"{label} salt", 16)
    nonce = det(f"{label} nonce", 24)
    if slot_type == 3:
        kdf_id, mem, ops, lanes = 2, 0, 0, 0
    else:
        kdf_id, lanes = 1, 1
    prefix = slot_prefix(slot_type, kdf_id, mem, ops, lanes, salt)
    km, ko = kek_params or (mem, ops)
    kek = secret_kek(slot_type, secret, salt, km, ko)
    wrapped = aead_encrypt(kek, nonce, mk, slot_ad(uuid, index, prefix))
    slot = prefix + nonce + wrapped + bytes(24)
    assert len(slot) == 128
    return slot


def header_body(uuid, slots, major=1, minor=0, required=0, optional=0, reserved=bytes(32)):
    slots = list(slots) + [bytes(128)] * (8 - len(slots))
    body = b"TJRI" + struct.pack("<HHII", major, minor, required, optional) + uuid
    body += b"".join(slots) + reserved
    assert len(body) == 1088
    return body


def make_header(mk, uuid, slots, **kw) -> bytes:
    body = header_body(uuid, slots, **kw)
    return body + H(KDF(mk, 1), body)


def secret_json(secret) -> dict:
    out = {}
    if "password" in secret:
        out["password"] = secret["password"]
    if "keyfile" in secret:
        out["keyfile_hex"] = hx(secret["keyfile"])
    if "entropy" in secret:
        out["recovery_phrase"] = phrase_of(secret["entropy"])
    return out


# ---------------------------------------------------------------------------
# Padme and objects (section 7)


def padme(L: int) -> int:
    E = L.bit_length() - 1
    S = E.bit_length()
    mask = (1 << (E - S)) - 1
    return (L + mask) & ~mask


def object_plaintext(content: bytes, padding: bool) -> bytes:
    total = padme(8 + len(content)) if padding else 8 + len(content)
    return struct.pack("<Q", len(content)) + content + bytes(total - 8 - len(content))


def split_chunks(pt: bytes):
    chunks = [pt[i : i + CHUNK] for i in range(0, len(pt), CHUNK)]
    return [(c, TAG_FINAL if i == len(chunks) - 1 else TAG_MESSAGE) for i, c in enumerate(chunks)]


def make_object(k_obj, kind, oid, content, padding, version=1):
    pt = object_plaintext(content, padding)
    key = object_key(k_obj, kind, oid)
    header, chunks = stream_encrypt(key, bytes([kind]) + oid, split_chunks(pt))
    return bytes([version]) + header + b"".join(chunks)


def object_disk_size(total: int) -> int:
    return 25 + total + 17 * -(-total // CHUNK)


# ---------------------------------------------------------------------------
# CBOR (deterministic, section 1). A tiny manual encoder so negative cases can
# break the rules; valid encodings are cross-checked against cbor2.


def cb_head(major: int, n: int, width=None) -> bytes:
    if width is None:
        width = 0 if n < 24 else 1 if n < 0x100 else 2 if n < 0x10000 else 4 if n < 0x100000000 else 8
    if width == 0:
        return bytes([(major << 5) | n])
    ai = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")


def cb(v) -> bytes:
    """Deterministic encoding of int, bytes, str, bool, list and dict."""
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return cb_head(0, v) if v >= 0 else cb_head(1, -1 - v)
    if isinstance(v, bytes):
        return cb_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return cb_head(3, len(b)) + b
    if isinstance(v, list):
        return cb_head(4, len(v)) + b"".join(cb(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cb(k), cb(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return cb_head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def cb_checked(v) -> bytes:
    out = cb(v)
    assert out == cbor2.dumps(v, canonical=True), v
    return out


def cb_map_raw(pairs) -> bytes:
    """Map from already-encoded (key, value) pairs, in the given order."""
    return cb_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


# ---------------------------------------------------------------------------
# Directories and root pointers (section 8)


def entry(name, kind, oid, ohash, mtime, size=None, mode=None, extra=None) -> dict:
    e = {1: name, 2: kind, 3: oid, 4: ohash, 6: mtime}
    if size is not None:
        e[5] = size
    if mode is not None:
        e[7] = mode
    if extra:
        e.update(extra)
    return e


def dir_content(entries) -> bytes:
    entries = sorted(entries, key=lambda e: e[1].encode())
    return cb_checked({1: 1, 2: entries})


def entry_json(e: dict) -> dict:
    out = {"name": e[1], "kind": e[2], "id": hx(e[3]), "hash": hx(e[4]), "mtime": e[6]}
    if 5 in e:
        out["size"] = e[5]
    if 7 in e:
        out["mode"] = e[7]
    unknown = {str(k): hx(cb(v)) for k, v in e.items() if k not in range(1, 8)}
    if unknown:
        out["unknown_cbor"] = unknown
    return out


def root_ad(uuid: bytes, letter: str) -> bytes:
    return b"TJRI root v1" + uuid + letter.encode()


def root_fields(rev, root_id, root_hash, padding, private_only, label, written_at, writer_id):
    return {
        1: rev,
        2: root_id,
        3: root_hash,
        4: {1: padding, 2: private_only, 3: label},
        5: written_at,
        6: writer_id,
    }


def make_root(k_root, uuid, letter, nonce, plaintext: bytes, version=1) -> bytes:
    return bytes([version]) + nonce + aead_encrypt(k_root, nonce, plaintext, root_ad(uuid, letter))


def root_json(f: dict) -> dict:
    return {
        "rev": f[1],
        "root_id": hx(f[2]),
        "root_hash": hx(f[3]),
        "settings": {"padding": f[4][1], "private_only": f[4][2], "label": f[4][3]},
        "written_at": f[5],
        "writer_id": hx(f[6]),
    }


# ---------------------------------------------------------------------------
# Vector files


def gen_subkeys():
    cases = []
    for label, mk in [("random", det("subkeys mk", 32)), ("zero", bytes(32))]:
        k_hmac, k_root, k_obj = subkeys(mk)
        oks = []
        for kind in (KIND_FILE, KIND_DIR):
            oid = det(f"subkeys {label} oid {kind}", 32)
            oks.append({"kind": kind, "object_id": hx(oid), "object_key": hx(object_key(k_obj, kind, oid))})
        cases.append(
            {
                "name": label,
                "mk": hx(mk),
                "k_hmac": hx(k_hmac),
                "k_root": hx(k_root),
                "k_obj": hx(k_obj),
                "object_keys": oks,
            }
        )
    return {"description": "KDF(MK, 1..3) subkeys and object keys (sections 3, 4)", "cases": cases}


def gen_padme():
    lengths = [8, 9, 10, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 1000,
               1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536, 65537, 65544, 100008, 1000008,
               2**20, 2**20 + 1, 10**9 + 8, 2**32 - 1, 2**32, 2**32 + 1, 2**40 - 1, 2**40]
    examples = {0: 8, 92: 104, 992: 1024, 65536: 67584, 1000000: 1015808, 10**9: 1006632960}
    for c, stored in examples.items():
        assert padme(8 + c) == stored
    return {
        "description": "padme(L) for L >= 8 (section 7.3), and content length -> stored plaintext length",
        "cases": [{"l": L, "padme": padme(L)} for L in lengths],
        "content_examples": [
            {"content_length": c, "stored_plaintext": s, "disk_size": object_disk_size(s)}
            for c, s in examples.items()
        ],
    }


PW_ASCII = "correct horse battery staple"
PW_UNICODE = "तिजोरी की चाबी – café"
PW_NFD = unicodedata.normalize("NFD", "café crème brûlée")
PW_KF = "keyfile pass phrase"


def gen_kek():
    cases, neg = [], []
    for name, pw, mem, ops in [
        ("type1 ascii", PW_ASCII, MEM_KIB, OPS),
        ("type1 unicode nfc", PW_UNICODE, MEM_KIB, OPS),
        ("type1 nfd input is normalized to nfc", PW_NFD, MEM_KIB, OPS),
        ("type1 ops 3", PW_ASCII, MEM_KIB, 3),
    ]:
        salt = det(f"kek {name} salt", 16)
        cases.append(
            {
                "name": name,
                "slot_type": 1,
                "password": pw,
                "password_utf8_hex": hx(pw.encode()),
                "salt": hx(salt),
                "mem_kib": mem,
                "ops": ops,
                "kek": hx(kek_password(pw, salt, mem, ops)),
            }
        )
    keyfile = det("kek keyfile", 100)
    salt2 = det("kek type2 salt", 16)
    a, kf, kek2 = kek_keyfile_parts(PW_KF, keyfile, salt2, MEM_KIB, OPS)
    cases.append(
        {
            "name": "type2 password + keyfile",
            "slot_type": 2,
            "password": PW_KF,
            "password_utf8_hex": hx(PW_KF.encode()),
            "keyfile_hex": hx(keyfile),
            "salt": hx(salt2),
            "mem_kib": MEM_KIB,
            "ops": OPS,
            "argon_output": hx(a),
            "kf": hx(kf),
            "kek": hx(kek2),
        }
    )
    for name, entropy in [("type3 random", det("kek entropy", 32)), ("type3 zero entropy", bytes(32))]:
        salt = det(f"kek {name} salt", 16)
        cases.append(
            {
                "name": name,
                "slot_type": 3,
                "recovery_phrase": phrase_of(entropy),
                "entropy": hx(entropy),
                "salt": hx(salt),
                "kek": hx(kek_recovery(entropy, salt)),
            }
        )
    neg.append(
        {
            "name": "type2 wrong keyfile",
            "slot_type": 2,
            "password": PW_KF,
            "keyfile_hex": hx(det("kek wrong keyfile", 100)),
            "salt": hx(salt2),
            "mem_kib": MEM_KIB,
            "ops": OPS,
            "must_not_equal": hx(kek2),
            "error": "wrong_secret",
        }
    )
    nfd_salt = det("kek type1 nfd input is normalized to nfc salt", 16)
    raw = ARGON2ID(PW_NFD.encode(), nfd_salt, MEM_KIB, OPS)
    norm = kek_password(PW_NFD, nfd_salt, MEM_KIB, OPS)
    assert raw != norm
    neg.append(
        {
            "name": "nfd bytes hashed without normalization",
            "slot_type": 1,
            "argon_input_utf8_hex": hx(PW_NFD.encode()),
            "salt": hx(nfd_salt),
            "mem_kib": MEM_KIB,
            "ops": OPS,
            "argon_output": hx(raw),
            "must_not_equal": hx(norm),
            "error": "wrong_secret",
        }
    )
    return {"description": "KEK derivation for slot types 1-3 (section 4)", "cases": cases, "negative": neg}


def gen_keyslot():
    uuid = det("keyslot uuid", 16)
    mk = det("keyslot mk", 32)
    keyfile = det("keyslot keyfile", 64)
    entropy = det("keyslot entropy", 32)
    s_pw = {"password": PW_ASCII}
    s_kf = {"password": PW_KF, "keyfile": keyfile}
    s_rc = {"entropy": entropy}
    slot_pw = make_slot(uuid, 0, 1, s_pw, mk, "keyslot pw")
    slot_kf = make_slot(uuid, 1, 2, s_kf, mk, "keyslot kf")
    slot_rc = make_slot(uuid, 5, 3, s_rc, mk, "keyslot rc")

    def case(name, index, slot, secret, use_uuid=uuid, **extra):
        c = {"name": name, "vault_uuid": hx(use_uuid), "slot_index": index, "slot": hx(slot)}
        c.update(secret_json(secret))
        c.update(extra)
        return c

    cases = [
        case("type1 password", 0, slot_pw, s_pw, mk=hx(mk)),
        case("type2 password + keyfile", 1, slot_kf, s_kf, mk=hx(mk)),
        case("type3 recovery phrase", 5, slot_rc, s_rc, mk=hx(mk)),
    ]
    changed = bytearray(slot_pw)
    changed[8:12] = struct.pack("<I", OPS + 1)
    wrong_ent = det("keyslot wrong entropy", 32)
    neg = [
        case("changed argon_ops", 0, bytes(changed), s_pw, error="wrong_secret"),
        case("swapped slot index", 1, slot_pw, s_pw, error="wrong_secret"),
        case("other vault uuid", 0, slot_pw, s_pw, use_uuid=det("keyslot other uuid", 16), error="wrong_secret"),
        case("wrong password", 0, slot_pw, {"password": PW_ASCII + "!"}, error="wrong_secret"),
        case("wrong keyfile", 1, slot_kf, {"password": PW_KF, "keyfile": det("x", 64)}, error="wrong_secret"),
        case("wrong recovery phrase", 5, slot_rc, {"entropy": wrong_ent}, error="wrong_secret"),
    ]
    return {"description": "Wrap and unwrap of MK in one keyslot (section 5.2)", "cases": cases, "negative": neg}


def gen_header():
    uuid = det("header uuid", 16)
    mk = det("header mk", 32)
    keyfile = det("header keyfile", 48)
    entropy = det("header entropy", 32)
    s_pw = {"password": PW_ASCII}
    s_kf = {"password": PW_KF, "keyfile": keyfile}
    s_rc = {"entropy": entropy}
    slots = [
        make_slot(uuid, 0, 1, s_pw, mk, "header s0"),
        make_slot(uuid, 1, 3, s_rc, mk, "header s1"),
        make_slot(uuid, 2, 2, s_kf, mk, "header s2"),
    ]
    good = make_header(mk, uuid, slots)
    k_hmac = KDF(mk, 1)

    def case(name, header, secret, **extra):
        c = {"name": name, "header": hx(header)}
        c.update(secret_json(secret))
        c.update(extra)
        return c

    common = {"mk": hx(mk), "vault_uuid": hx(uuid), "header_mac": hx(good[1088:])}
    cases = [
        case("password opens slot 0", good, s_pw, opened_slot=0, **common),
        case("recovery phrase opens slot 1", good, s_rc, opened_slot=1, **common),
        case("password + keyfile opens slot 2", good, s_kf, opened_slot=2, **common),
    ]
    opt = make_header(mk, uuid, slots, optional=1 << 7)
    cases.append(case("unknown optional feature bit is ignored", opt, s_pw, opened_slot=0, mk=hx(mk)))
    unknown_type = bytearray(128)
    unknown_type[0] = 4
    unknown_type[1] = 9
    with_unknown = make_header(mk, uuid, [bytes(unknown_type), slots[1], slots[2]] + [bytes(128)] * 2 + [
        make_slot(uuid, 5, 1, s_pw, mk, "header s5")])
    cases.append(case("unknown slot type is skipped", with_unknown, s_pw, opened_slot=5, mk=hx(mk)))

    flipped = bytearray(good)
    flipped[-1] ^= 0x01
    reserved_flip = bytearray(good)
    reserved_flip[1060] ^= 0x80
    empty_slot_flip = bytearray(good)
    empty_slot_flip[32 + 6 * 128 + 50] ^= 0x01
    # The parser must reject these before running Argon2id, so the wrap uses cheap parameters.
    cheap = (MEM_KIB, OPS)
    big_mem = make_slot(uuid, 0, 1, s_pw, mk, "header s0", mem=2 * 1048576, kek_params=cheap)
    small_ops = make_slot(uuid, 0, 1, s_pw, mk, "header s0", ops=1, kek_params=cheap)
    lanes = bytearray(slots[0])
    lanes[12:16] = struct.pack("<I", 2)
    t3_mem = bytearray(slots[1])
    t3_mem[4:8] = struct.pack("<I", 65536)
    bad_magic = bytearray(good)
    bad_magic[0:4] = b"TJRX"
    neg = [
        case("flipped MAC bit", bytes(flipped), s_pw, error="tampered"),
        case("flipped reserved bit", bytes(reserved_flip), s_pw, error="tampered"),
        case("flipped bit in an empty slot", bytes(empty_slot_flip), s_pw, error="tampered"),
        case("unknown required feature bit", make_header(mk, uuid, slots, required=1 << 3), s_pw, error="unsupported"),
        case("format_major 2", make_header(mk, uuid, slots, major=2), s_pw, error="unsupported"),
        case("argon_mem_kib above 1 GiB", make_header(mk, uuid, [big_mem] + slots[1:]), s_pw, error="damaged"),
        case("argon_ops below 2", make_header(mk, uuid, [small_ops] + slots[1:]), s_pw, error="damaged"),
        case("argon_lanes 2", make_header(mk, uuid, [bytes(lanes)] + slots[1:]), s_pw, error="damaged"),
        case("type 3 slot with argon_mem_kib set", make_header(mk, uuid, [slots[0], bytes(t3_mem)]), s_rc,
             error="damaged"),
        case("no keyslots", make_header(mk, uuid, []), s_pw, error="damaged"),
        case("bad magic", bytes(bad_magic), s_pw, error="damaged"),
        case("1119 bytes", good[:-1], s_pw, error="damaged"),
        case("1121 bytes", good + b"\x00", s_pw, error="damaged"),
        case("wrong password", good, {"password": "not the password"}, error="wrong_secret"),
        case("keyfile slot without keyfile", good, {"password": PW_KF}, error="wrong_secret"),
    ]
    assert len(good) == HEADER_LEN and H(k_hmac, good[:1088]) == good[1088:]
    return {
        "description": "Full vault headers and MAC (sections 5, 6 steps 1-5). "
        "Negative cases apply to a single header file with no backup.",
        "cases": cases,
        "negative": neg,
    }


def gen_object():
    k_obj = det("object k_obj", 32)
    cases, neg = [], []

    def obj_case(name, kind, content, padding):
        oid = det(f"object {name} id", 32)
        data = make_object(k_obj, kind, oid, content, padding)
        total = len(object_plaintext(content, padding))
        assert len(data) == object_disk_size(total)
        cases.append(
            {
                "name": name,
                "kind": kind,
                "object_id": hx(oid),
                "object_key": hx(object_key(k_obj, kind, oid)),
                "padding": padding,
                "content": content_json(content),
                "plaintext_total": total,
                "object": hx(data),
                "hash": hx(H(None, data)),
            }
        )
        return oid, data

    obj_case("empty file, padding on", KIND_FILE, b"", True)
    obj_case("92 bytes, padding on", KIND_FILE, det("object 92", 92), True)
    obj_case("one full chunk, padding off", KIND_FILE, pattern(CHUNK - 8), False)
    big_id, big = obj_case("three chunks, padding off", KIND_FILE, pattern(140000), False)
    obj_case("two chunks, padding on", KIND_FILE, pattern(100000), True)
    dir_id, dir_obj = obj_case("directory object", KIND_DIR, dir_content([]), True)

    # Mutations of the objects above, applied by the test to the named base case:
    # truncate_to N, append_hex H, swap [a, b) with [c, d), set byte at offset.
    def mut(name, base, error, kind=None, object_id=None, **mutation):
        c = next(c for c in cases if c["name"] == base)
        neg.append(
            {
                "name": name,
                "base": base,
                "kind": kind or c["kind"],
                "object_id": object_id or c["object_id"],
                "mutation": mutation,
                "error": error,
            }
        )

    three = "three chunks, padding off"
    full = CHUNK + 17
    mut("truncated: final chunk removed", three, "tampered", truncate_to=25 + 2 * full)
    mut("truncated: mid chunk", three, "tampered", truncate_to=len(big) - 5)
    mut("truncated: header only", three, "tampered", truncate_to=25)
    mut("truncated: shorter than header", three, "tampered", truncate_to=20)
    mut("extended: garbage after FINAL", three, "tampered", append_hex="00")
    mut("reordered chunks", three, "tampered", swap=[25, 25 + full, 25 + full, 25 + 2 * full])
    mut("flipped ciphertext bit", three, "tampered", set_byte=[25 + full + 3, big[25 + full + 3] ^ 1])
    mut("flipped stream header bit", three, "tampered", set_byte=[1, big[1] ^ 0x80])
    mut("wrong kind", "directory object", "tampered", kind=KIND_FILE)
    mut("wrong object id", "directory object", "tampered", object_id=hx(det("object other id", 32)))
    mut("object_version 2", "directory object", "unsupported", set_byte=[0, 2])
    mut("object_version 0", "directory object", "damaged", set_byte=[0, 0])
    assert dir_id and dir_obj

    def crafted(name, chunks, error, version=1):
        oid = det(f"object crafted {name}", 32)
        key = object_key(k_obj, KIND_FILE, oid)
        header, cts = stream_encrypt(key, bytes([KIND_FILE]) + oid, chunks)
        neg.append(
            {
                "name": name,
                "kind": KIND_FILE,
                "object_id": hx(oid),
                "object": hx(bytes([version]) + header + b"".join(cts)),
                "error": error,
            }
        )

    pt = object_plaintext(b"hello", True)
    crafted("extended: valid chunk after FINAL", [(pt, TAG_FINAL), (b"more", TAG_MESSAGE)], "tampered")
    crafted("missing FINAL tag", [(pt, TAG_MESSAGE)], "tampered")
    crafted("non-zero padding", [(pt[:-1] + b"\x01", TAG_FINAL)], "damaged")
    crafted("content_length beyond plaintext", [(struct.pack("<Q", 9) + bytes(8), TAG_FINAL)], "damaged")
    crafted("plaintext shorter than 8 bytes", [(b"\x00" * 5, TAG_FINAL)], "damaged")
    crafted("PUSH tag on last chunk", [(pt, TAG_PUSH)], "damaged")
    return {
        "description": "Encrypted objects (section 7). Stream headers are random, so this file changes "
        "on every generator run; tests decrypt it rather than re-encrypting.",
        "content_pattern_mod251": "byte i of the content is i % 251",
        "k_obj": hx(k_obj),
        "cases": cases,
        "negative": neg,
    }


def gen_root():
    mk = det("root mk", 32)
    uuid = det("root uuid", 16)
    k_root = KDF(mk, 2)
    cases, neg = [], []
    rid, rhash, wid = det("root id", 32), det("root hash", 32), det("root writer", 16)
    fa = root_fields(1, rid, rhash, True, False, "", 1767225600, wid)
    fb = root_fields(2, det("root id 2", 32), det("root hash 2", 32), False, True, "Family photos ✓", 1767312000, wid)
    files = {}
    for letter, f in (("a", fa), ("b", fb)):
        nonce = det(f"root nonce {letter}", 24)
        pt = cb_checked(f)
        data = make_root(k_root, uuid, letter, nonce, pt)
        files[letter] = data
        cases.append(
            {"name": f"slot {letter}", "slot": letter, "file": hx(data), "cbor": hx(pt), "fields": root_json(f)}
        )

    def n(name, data, error, slot="a", use_uuid=uuid):
        neg.append({"name": name, "slot": slot, "vault_uuid": hx(use_uuid), "file": hx(data), "error": error})

    def enc(label, pt, version=1):
        return make_root(k_root, uuid, "a", det(f"root neg {label}", 24), pt, version)

    n("swapped slot letter", files["a"], "tampered", slot="b")
    n("other vault uuid", files["a"], "tampered", use_uuid=det("root other uuid", 16))
    flipped = bytearray(files["a"])
    flipped[30] ^= 0x04
    n("flipped ciphertext bit", bytes(flipped), "tampered")
    n("root_version 2", enc("v2", cb(fa), version=2), "unsupported")
    n("root_version 0", enc("v0", cb(fa), version=0), "damaged")
    n("40 bytes", files["a"][:25] + bytes(15), "damaged")
    n("4097 bytes", b"\x01" + bytes(4096), "damaged")
    # Validly encrypted but malformed CBOR (only a key holder could write these).
    pairs = [(cb(k), cb(v)) for k, v in sorted(fa.items())]
    non_shortest = cb_map_raw([(cb(1), cb_head(0, 1, width=1))] + pairs[1:])
    n("non-shortest integer", enc("ns", non_shortest), "damaged")
    n("missing root_hash", enc("mh", cb({k: v for k, v in fa.items() if k != 3})), "damaged")
    n("rev as text", enc("rt", cb({**fa, 1: "1"})), "damaged")
    n("root_id 31 bytes", enc("r31", cb({**fa, 2: rid[:31]})), "damaged")
    n("settings without label", enc("nl", cb({**fa, 4: {1: True, 2: False}})), "damaged")
    n("label longer than 64 bytes", enc("ll", cb({**fa, 4: {1: True, 2: False, 3: "x" * 65}})), "damaged")
    n("float written_at", enc("fl", cb_map_raw(pairs[:4] + [(cb(5), b"\xfb" + struct.pack(">d", 1.5))] + pairs[5:])),
      "damaged")
    n("duplicate key", enc("dk", cb_map_raw([pairs[0], pairs[0]] + pairs[1:])), "damaged")
    n("trailing bytes", enc("tb", cb(fa) + b"\x00"), "damaged")
    return {
        "description": "Root pointer files (section 8.1)",
        "mk": hx(mk),
        "k_root": hx(k_root),
        "vault_uuid": hx(uuid),
        "cases": cases,
        "negative": neg,
    }


def gen_dir():
    cases, neg = [], []
    i1, h1 = det("dir id 1", 32), det("dir hash 1", 32)
    i2, h2 = det("dir id 2", 32), det("dir hash 2", 32)
    i3, h3 = det("dir id 3", 32), det("dir hash 3", 32)
    i4, h4 = det("dir id 4", 32), det("dir hash 4", 32)
    i5, h5 = det("dir id 5", 32), det("dir hash 5", 32)
    entries = [
        entry("a.txt", KIND_FILE, i1, h1, 1700000000000, size=5),
        entry("Docs", KIND_DIR, i2, h2, 1700000000123),
        entry("café.txt", KIND_FILE, i3, h3, -86400000, size=0),
        entry("run.sh", KIND_FILE, i4, h4, 1700000000000, size=1234567, mode=1),
        entry("x", KIND_FILE, i5, h5, 0, size=2**40, extra={99: "kept by writers", 100: [1, 2]}),
    ]
    for name, es in [("empty", []), ("mixed", entries)]:
        content = dir_content(es)
        cases.append(
            {
                "name": name,
                "cbor": hx(content),
                "entries": [entry_json(e) for e in sorted(es, key=lambda e: e[1].encode())],
            }
        )

    good = sorted(entries[:2], key=lambda e: e[1].encode())  # Docs, a.txt

    def ent_pairs(e):
        return [(cb(k), cb(v)) for k, v in sorted(e.items())]

    def dir_raw(items_cbor: bytes, n_items: int, version=cb(1)) -> bytes:
        return cb_map_raw([(cb(1), version), (cb(2), cb_head(4, n_items) + items_cbor)])

    def n(name, data, error="damaged"):
        neg.append({"name": name, "cbor": hx(data), "error": error})

    n("unsorted entries", dir_raw(cb(good[1]) + cb(good[0]), 2))
    n("duplicate names", dir_raw(cb(good[1]) + cb(good[1]), 2))
    n("float mtime", dir_raw(cb_map_raw([(cb(k), b"\xf9\x3c\x00" if k == 6 else cb(v))
                                          for k, v in sorted(good[0].items())]), 1))
    n("non-shortest dir_version", dir_raw(b"", 0, version=cb_head(0, 1, width=1)))
    n("non-shortest size", dir_raw(cb_map_raw([(cb(k), cb_head(0, v, width=8) if k == 5 else cb(v))
                                                for k, v in sorted(good[1].items())]), 1))
    n("indefinite-length array", cb_map_raw([(cb(1), cb(1)), (cb(2), b"\x9f\xff")]))
    n("indefinite-length name", dir_raw(cb_map_raw([(cb(k), b"\x7f\x61D\x63ocs\xff" if k == 1 else cb(v))
                                                     for k, v in sorted(good[0].items())]), 1))
    n("duplicate key in entry", dir_raw(cb_map_raw(ent_pairs(good[0])[:1] + ent_pairs(good[0])), 1))
    n("unsorted keys in entry", dir_raw(cb_map_raw(list(reversed(ent_pairs(good[0])))), 1))
    n("tagged value", dir_raw(cb_map_raw([(cb(k), b"\xc0" + cb(v) if k == 1 else cb(v))
                                           for k, v in sorted(good[0].items())]), 1))
    n("undefined value", dir_raw(cb_map_raw(ent_pairs(good[0]) + [(cb(99), b"\xf7")]), 1))
    n("invalid utf-8 name", dir_raw(cb({**good[0], 1: "Docs"}).replace(b"Docs", b"Do\xffs"), 1))
    for label, bad in [("non-NFC name", unicodedata.normalize("NFD", "café")), ("name '.'", "."),
                       ("name '..'", ".."), ("name with '/'", "a/b"), ("name with NUL", "a\x00b"),
                       ("empty name", ""), ("name of 256 bytes", "n" * 256)]:
        n(label, dir_raw(cb({**good[0], 1: bad}), 1))
    n("missing hash", dir_raw(cb({k: v for k, v in good[0].items() if k != 4}), 1))
    n("id of 31 bytes", dir_raw(cb({**good[0], 3: i1[:31]}), 1))
    n("file without size", dir_raw(cb({k: v for k, v in good[1].items() if k != 5}), 1))
    n("directory with size", dir_raw(cb({**good[0], 5: 1}), 1))
    n("unknown kind 3", dir_raw(cb({**good[0], 2: 3}), 1))
    n("negative size", dir_raw(cb({**good[1], 5: -1}), 1))
    n("trailing bytes", dir_content([]) + b"\x00")
    n("top level is an array", cb([1, []]))
    n("dir_version 2", dir_raw(b"", 0, version=cb(2)), "unsupported")
    return {
        "description": "Directory object content: exact deterministic CBOR (sections 1, 8.2, 11, 12). "
        "unknown_cbor maps unknown entry keys to their encoded values, which writers keep.",
        "cases": cases,
        "negative": neg,
    }


# ---------------------------------------------------------------------------
# Complete vaults (vault/)

README_TEXT = (
    "This drive holds a Tijori vault (folder TIJORI).\n"
    "The files inside are encrypted. Open them with the Tijori app:\n"
    "install it, plug in this drive, and enter your password.\n"
    "Do not rename, edit or delete anything inside the TIJORI folder.\n"
)


class VaultBuilder:
    def __init__(self, root: Path, name: str, padding=True):
        self.dir = root / name / "TIJORI"
        self.name = name
        self.mk = det(f"vault {name} mk", 32)
        self.uuid = det(f"vault {name} uuid", 16)
        self.k_hmac, self.k_root, self.k_obj = subkeys(self.mk)
        self.padding = padding
        self.writer = det(f"vault {name} writer", 16)
        self.n = 0

    def write(self, rel: str, data: bytes):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (946684800, 946684800))

    def put_object(self, kind, content) -> tuple:
        self.n += 1
        oid = det(f"vault {self.name} object {self.n}", 32)
        data = make_object(self.k_obj, kind, oid, content, self.padding)
        h = oid.hex()
        self.write(f"objects/{h[:2]}/{h}.tjo", data)
        return oid, H(None, data)

    def put_dir(self, entries) -> tuple:
        return self.put_object(KIND_DIR, dir_content(entries))

    def put_root(self, letter, rev, root, label, written_at):
        oid, ohash = root
        f = root_fields(rev, oid, ohash, self.padding, False, label, written_at, self.writer)
        nonce = det(f"vault {self.name} root {rev}", 24)
        self.write(f"vault.root.{letter}", make_root(self.k_root, self.uuid, letter, nonce, cb_checked(f)))


def file_entry(vb: VaultBuilder, name, content, mtime, mode=None):
    oid, h = vb.put_object(KIND_FILE, content)
    return entry(name, KIND_FILE, oid, h, mtime, size=len(content), mode=mode)


def tree_json(tree: dict, prefix="") -> list:
    out = []
    for name in sorted(tree, key=lambda s: s.encode()):
        v = tree[name]
        path = f"{prefix}/{name}"
        if isinstance(v, dict):
            out.append({"path": path, "kind": "dir"})
            out += tree_json(v, path)
        else:
            out.append({"path": path, "kind": "file", "size": len(v), "content": content_json(v)})
    return out


def gen_vaults(out: Path) -> dict:
    vroot = out / "vault"
    if vroot.exists():
        shutil.rmtree(vroot)
    vb = VaultBuilder(vroot, "basic")
    entropy = det("vault basic entropy", 32)
    slots = [
        make_slot(vb.uuid, 0, 1, {"password": PW_ASCII}, vb.mk, "vault basic s0"),
        make_slot(vb.uuid, 1, 3, {"entropy": entropy}, vb.mk, "vault basic s1"),
    ]
    header = make_header(vb.mk, vb.uuid, slots)
    vb.write("vault.header", header)
    vb.write("vault.header.bak", header)
    (vroot / "basic" / "README-TIJORI.txt").write_text(README_TEXT)

    t = 1767225600000
    hello, cafe, big = b"Hello, Tijori!\n", b"NFC name\n", pattern(70000)
    docs_entries = [
        file_entry(vb, "café.txt", cafe, t + 1),
        file_entry(vb, "empty.bin", b"", t + 2),
        file_entry(vb, "big.bin", big, t + 3, mode=1),
    ]
    docs = vb.put_dir(docs_entries)
    hello_e = file_entry(vb, "hello.txt", hello, t)
    docs_e = entry("Docs", KIND_DIR, docs[0], docs[1], t + 4)
    root1 = vb.put_dir([hello_e, docs_e])
    vb.put_root("a", 1, root1, "Vectors", 1767225600)

    notes = b"second commit\n"
    root2 = vb.put_dir([hello_e, docs_e, file_entry(vb, "notes.txt", notes, t + 5)])
    vb.put_root("b", 2, root2, "Vectors", 1767225700)

    tree1 = {"hello.txt": hello, "Docs": {"café.txt": cafe, "empty.bin": b"", "big.bin": big}}
    tree2 = {**tree1, "notes.txt": notes}

    torn = vroot / "torn-newest-root"
    shutil.copytree(vroot / "basic", torn)
    rb = torn / "TIJORI" / "vault.root.b"
    rb.write_bytes(rb.read_bytes()[: len(rb.read_bytes()) // 2])
    os.utime(rb, (946684800, 946684800))

    secrets = {"password": PW_ASCII, "recovery_phrase": phrase_of(entropy)}
    return {
        "description": "Complete vaults on disk (section 15). Object stream headers are random, so these "
        "change on every generator run. Argon2id uses the minimum parameters to keep tests fast.",
        "vaults": [
            {
                "name": "basic",
                "path": "vault/basic",
                **secrets,
                "vault_uuid": hx(vb.uuid),
                "mk": hx(vb.mk),
                "expected_rev": 2,
                "settings": {"padding": True, "private_only": False, "label": "Vectors"},
                "tree": tree_json(tree2),
            },
            {
                "name": "torn newest root slot opens at the previous commit",
                "path": "vault/torn-newest-root",
                **secrets,
                "vault_uuid": hx(vb.uuid),
                "mk": hx(vb.mk),
                "expected_rev": 1,
                "settings": {"padding": True, "private_only": False, "label": "Vectors"},
                "tree": tree_json(tree1),
            },
        ],
    }


# ---------------------------------------------------------------------------


def dump(obj) -> str:
    return json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


GENERATORS = {
    "subkeys.json": gen_subkeys,
    "padme.json": gen_padme,
    "kek.json": gen_kek,
    "keyslot.json": gen_keyslot,
    "header.json": gen_header,
    "object.json": gen_object,
    "root.json": gen_root,
    "dir.json": gen_dir,
}


def main() -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=here.parent / "vectors")
    ap.add_argument("--check", action="store_true", help="compare deterministic files with --out")
    ap.add_argument("--only", nargs="+", metavar="FILE", help="write only these files (e.g. object.json vault.json)")
    args = ap.parse_args()

    if args.check:
        bad = []
        for name in DETERMINISTIC_FILES:
            fresh = dump(GENERATORS[name]())
            if (args.out / name).read_text() != fresh:
                bad.append(name)
        if bad:
            print("out of date: " + ", ".join(bad), file=sys.stderr)
            return 1
        print("deterministic vectors match")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    wanted = set(args.only or list(GENERATORS) + ["vault.json"])
    for name, gen in GENERATORS.items():
        if name in wanted:
            (args.out / name).write_text(dump(gen()))
            print("wrote", name)
    if "vault.json" in wanted:
        (args.out / "vault.json").write_text(dump(gen_vaults(args.out)))
        print("wrote vault.json and vault/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
