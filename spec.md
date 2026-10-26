Tijori Vault Format Specification v1
26 Oct 2026 · @Kanishk Pachauri · Draft for review
1. Status and conventions
This spec defines Tijori vault format v1.0: the exact bytes on the drive, so the Rust core and any future implementation read and write the same vaults. It is a draft for peer review; nothing here is frozen until test vectors exist.
• MUST / MUST NOT / SHOULD / MAY carry their RFC 2119 meanings.
• All integers are little-endian, unsigned unless stated.
• a || b means byte concatenation. [n] is a byte string of length n.
• "TJRI ..." strings are ASCII with no terminator.
• Sizes: KiB = 1024 bytes, MiB = 1024 KiB.
• Text is UTF-8. Passwords and names are normalized to Unicode NFC before use.
• Structured data is deterministic CBOR (RFC 8949 section 4.2.1): definite lengths, shortest integer forms, map keys sorted.
Out of scope for v1: hidden volumes, compression, deduplication, symlinks, extended attributes and hardware security keys.
2. Drive layout
A vault is one folder named TIJORI at the root of an exFAT volume; nothing outside it is read or written except an optional readme.
/ (exFAT root)
├── README-TIJORI.txt        optional, plain text
└── TIJORI/
    ├── vault.header         1120 bytes, keyslots + MAC (section 5)
    ├── vault.header.bak     byte-identical backup
    ├── vault.root.a         root pointer, slot A (section 8)
    ├── vault.root.b         root pointer, slot B
    ├── .lock                present only while a writer is active
    └── objects/
        └── 3f/
            └── 3f9a…e1.tjo  encrypted object, 64 lowercase hex chars
• An object's path is objects/<first 2 hex chars>/<64 hex chars>.tjo. The 256 fan-out folders keep exFAT directory scans fast.
• Files and directories are both stored as objects and look identical on disk.
• Files ending in .tmp are incomplete writes and MUST be ignored by readers.
• This replaces root.manifest from the design doc: the tree is now a set of directory objects plus two root pointers.
3. Cryptographic primitives
v1 uses exactly five primitives, all available in libsodium, so every implementation can be checked against one reference library.
Name in this spec
Algorithm
libsodium equivalent
Sizes
ARGON2ID
Argon2id v1.3, lanes = 1
crypto_pwhash with ALG_ARGON2ID13
salt 16, output 32
AEAD
XChaCha20-Poly1305 (IETF)
crypto_aead_xchacha20poly1305_ietf_*
key 32, nonce 24, tag 16
STREAM
secretstream with XChaCha20-Poly1305
crypto_secretstream_xchacha20poly1305_*
key 32, header 24, overhead 17 per chunk
H(key, msg)
BLAKE2b, 32-byte output, optional key
crypto_generichash
key 0 or 32
KDF(key, id)
BLAKE2b subkey derivation, context "TJRIv1__"
crypto_kdf_derive_from_key
key 32, id u64, output 32
• Lanes are fixed at 1 because libsodium only implements single-lane Argon2. A reader MUST reject any other value.
• Randomness MUST come from the OS CSPRNG (getrandom, SecRandomCopyBytes, SecureRandom).
• Every tag and MAC comparison MUST be constant-time.
• Every message that is hashed starts with a distinct ASCII label (for example "TJRI obj v1"), so no two uses of H can collide.
4. Key hierarchy
Every secret the user holds unlocks the same random 32-byte Master Key (MK); MK never touches the disk unwrapped, and all working keys are derived from it.
Any one slot opens MK; every working key below it is derived, so nothing but the wrapped MK is ever stored.
Key-encryption keys (one per keyslot type)
Type 1  password:            KEK = ARGON2ID(NFC(password), salt, m, t)
Type 2  password + keyfile:  A   = ARGON2ID(NFC(password), salt, m, t)
                             KF  = H(none, "TJRI keyfile v1" || keyfile_bytes)
                             KEK = H(KF, "TJRI kek v1" || A)
Type 3  recovery key:        E   = 32 bytes of entropy from 24 BIP-39 words
                             KEK = H(E, "TJRI recovery v1" || salt)
The recovery key skips Argon2id because 256 bits of entropy cannot be guessed; stretching it adds delay without adding safety.
Subkeys of MK
id
Key
Used for
1
K_hmac
Header MAC (section 5.3)
2
K_root
Encrypting the root pointers (section 8.1)
3
K_obj
Parent of every object key
Each is KDF(MK, id). Ids 4 and above are reserved.
Object keys
object_key = H(K_obj, "TJRI obj v1" || kind || object_id)
    kind = 0x01 file, 0x02 directory;  object_id = 32 random bytes
Binding the kind and ID into the key means an object cannot be moved to another ID, or a file passed off as a directory, without failing decryption.
Consequences
• Changing a password rewraps MK in one keyslot. No file is re-encrypted.
• Re-keying (new MK, every object rewritten) is a separate, slow operation. It is the only way to cut off someone who copied an old header (section 14).
5. Vault header
vault.header is exactly 1120 bytes: a 32-byte preamble, eight 128-byte keyslots, 32 reserved bytes and a 32-byte MAC.
5.1 Header layout
Offset
Size
Field
Rule
0
4
magic
ASCII TJRI
4
2
format_major
1
6
2
format_minor
0
8
4
required_features
Bit set; a reader MUST refuse unknown bits. v1: 0
12
4
optional_features
Bit set; unknown bits MAY be ignored. v1: 0
16
16
vault_uuid
Random, fixed for the vault's life
32
1024
keyslots[8]
8 × 128 bytes (5.2)
1056
32
reserved
Zero
1088
32
header_mac
H(K_hmac, bytes 0..1088)
5.2 Keyslot layout (128 bytes each)
Offset
Size
Field
Rule
0
1
slot_type
0 empty, 1 password, 2 password + keyfile, 3 recovery
1
1
kdf_id
1 = Argon2id (types 1 and 2), 2 = BLAKE2b (type 3)
2
2
reserved
Zero
4
4
argon_mem_kib
Memory in KiB; zero for type 3
8
4
argon_ops
Iterations (t); zero for type 3
12
4
argon_lanes
1; zero for type 3
16
16
salt
Random per slot, new on every rewrap
32
24
nonce
Random per wrap
56
48
wrapped_mk
AEAD(KEK, nonce, MK, ad): 32-byte MK + 16-byte tag
104
24
reserved
Zero
An empty slot is 128 zero bytes. The wrap's associated data ties the slot to its vault, position and parameters:
ad = "TJRI ks v1" || vault_uuid || slot_index (1 byte) || keyslot bytes 0..32
So changing an Argon2 parameter, swapping two slots, or copying a slot into another vault makes the unwrap fail.
5.3 Header MAC and backup
• The MAC can only be checked after unwrapping MK. It protects the fields no keyslot covers: other slots, feature bits and reserved bytes.
• vault.header.bak MUST be byte-identical to vault.header. To update, a writer writes the backup first, then the primary, each via temp file, fsync and rename.
• If the primary fails to parse, unwrap or MAC-check, the reader tries the backup. If both fail with the right secret, the vault is reported as tampered, never as "wrong password".
5.4 Default Argon2id parameters
Created on
Memory
Iterations (t)
Target time
Desktop
256 MiB (262144 KiB)
tuned, at least 3
about 1 s on the creating machine
Android
128 MiB (131072 KiB)
tuned, at least 4
about 1 s on the creating phone
Parameters live in each slot, so they can be raised later per slot. Creation tunes t upwards from the minimum, never lowers memory, and never exceeds the reader limits in section 12.
6. Unlock procedure
Unlocking validates everything cheap before running Argon2id, and checks integrity before showing a single file name.
1. Read vault.header. It MUST be exactly 1120 bytes, start with TJRI, have format_major = 1, and set no unknown required feature bits.
2. Check every non-empty slot against the limits in section 12. Any slot out of range: refuse the whole header, then try the backup.
3. Pick the candidate slots that match what the user supplied: a password tries types 1 and 2 (type 2 only if a keyfile was given); a recovery phrase tries type 3.
4. For each candidate, derive the KEK (section 4) and try to open wrapped_mk. Stop at the first success. If none succeed, report wrong password or keyfile.
5. Derive K_hmac, K_root and K_obj. Check header_mac in constant time. On failure, repeat from step 1 with vault.header.bak; if that also fails, report tampered.
6. Open both root pointers (section 8.1). Use the valid one with the higher rev. If neither opens, report damaged.
7. Compare rev and the root hash with this device's rollback record (section 10). Warn if the vault went backwards.
8. Load the root directory object, check its hash against the pointer, and show the tree.
9. Wipe the password, KEK and any keyfile bytes from memory. Keep MK and subkeys in locked memory until the vault is locked.
The error messages are deliberately distinct: "wrong password" means no slot opened, while "tampered" means a slot opened but something else failed. Merging them would hide attacks from the user.
7. Encrypted objects
Every file and directory is one immutable .tjo object: a version byte, a secretstream header, then 64 KiB authenticated chunks over a length-prefixed, padded plaintext.
7.1 Object file layout
Offset
Size
Field
0
1
object_version = 1
1
24
stream_header (random, from STREAM init)
25
varies
chunks: each is STREAM ciphertext of up to 65536 plaintext bytes + 17 bytes overhead
• Every chunk except the last carries exactly 65536 plaintext bytes and tag MESSAGE.
• The last chunk carries 0 to 65536 bytes and tag FINAL. Bytes after it, or a missing FINAL, mean the object is truncated or extended and MUST be rejected.
• Every chunk's associated data is kind || object_id (33 bytes).
• Objects are never modified in place. A changed file gets a new random object_id (section 9).
7.2 Plaintext stream
plaintext = content_length (u64) || content || zero padding
total     = padme(8 + content_length)   when padding is on
          = 8 + content_length          when padding is off
The length prefix sits inside the encryption, so it is never visible. Readers MUST check content_length ≤ total − 8 and that every padding byte is zero.
7.3 Padmé
Padmé rounds a length L so only the top few bits of its binary form survive, which caps overhead at about 12% while hiding most of the size.
E = floor(log2(L))            # position of the highest set bit
S = floor(log2(E)) + 1        # bits needed to write E
mask = 2^(E − S) − 1
padme(L) = (L + mask) & ~mask
Content size
Stored plaintext
Overhead
0 bytes (empty file)
8 bytes
none
92 bytes
104 bytes
4.0%
992 bytes
1,024 bytes
2.4%
64 KiB (65,536 bytes)
67,584 bytes
3.1%
1 MB (1,000,000 bytes)
1,015,808 bytes
1.6%
1 GB (10^9 bytes)
1,006,632,960 bytes
0.7%
Worst case over all sizes up to 2 MB is 11.6%, and it falls as files grow. Padding is a per-vault setting stored in the encrypted root pointer, so the choice itself is not visible on the drive.
7.4 What an observer sees
File size on disk is 25 + total + 17 × ceil(total / 65536) (total is at least 8, so there is always at least one FINAL chunk). Since total is Padmé-rounded, the disk size reveals only the rounded size, and files and directories cannot be told apart.
8. Directory tree and root pointers
The tree is a hash-linked chain: two encrypted root pointers name the root directory object, and every directory lists its children's IDs and ciphertext hashes. Checking one hash at each level verifies the whole path.
8.1 Root pointer files
vault.root.a and vault.root.b have the same layout:
Offset
Size
Field
0
1
root_version = 1
1
24
nonce (random)
25
varies
AEAD(K_root, nonce, cbor, ad) where ad = "TJRI root v1" || vault_uuid || slot_letter
slot_letter is ASCII a or b. The decrypted CBOR map:
Key
Field
Type
Meaning
1
rev
uint
Commit counter, +1 on every commit
2
root_id
bytes(32)
Object ID of the root directory
3
root_hash
bytes(32)
H(none, root object file bytes)
4
settings
map
1: padding (bool), 2: private-mode-only (bool), 3: label (text, max 64 bytes)
5
written_at
uint
Unix seconds of the commit
6
writer_id
bytes(16)
Random ID of the device that committed
Settings live here, encrypted, so an attacker can neither read them nor switch off private-mode-only.
8.2 Directory objects
A directory is an object of kind 0x02 whose content is a CBOR map:
Key
Field
Type
1
dir_version
uint, 1
2
entries
array of entry maps, sorted by name bytes
Each entry:
Key
Field
Type
Rule
1
name
text
NFC, rules in section 11
2
kind
uint
1 file, 2 directory
3
id
bytes(32)
Child object ID
4
hash
bytes(32)
H(none, child object file bytes)
5
size
uint
Content bytes; files only
6
mtime
int
Unix milliseconds
7
mode
uint
Optional: bit 0 = executable
Readers MUST verify hash before decrypting a child. AEAD already proves an object is authentic for its ID; the hash additionally proves it is the exact version the parent expects.
Unknown keys are ignored by readers and kept by writers when an entry is copied unchanged, so v1.x can add fields without breaking v1.0.
9. Writing safely
Every change is copy-on-write and becomes real in one small write: the root pointer in the older A/B slot. Pull the drive out at any moment and the vault opens at either the old or the new state, never a mix.
9.1 Commit procedure
1. Take the write lock (9.2).
2. Write each new or changed file as a fresh object: <id>.tjo.tmp, fsync, rename to <id>.tjo, fsync the folder.
3. Rewrite every directory on the path from the change up to the root as new objects, the same way, each listing the new child IDs and hashes.
4. Write a new root pointer with rev + 1 into whichever slot holds the lower rev (or an invalid one), via temp file, fsync and rename. This is the commit point.
5. Record the new rev and root hash in this device's rollback record (section 10).
6. Release the lock. Old objects are left for garbage collection.
Two slots matter because exFAT does not promise an atomic rename. If a crash tears the new slot, the other slot still holds the previous complete commit.
9.2 Write lock
• A writer creates TIJORI/.lock with exclusive-create. It holds a random lock ID, the writer ID and a timestamp, as plain text.
• If the lock exists, the app opens the vault read-only and says who holds it.
• A lock older than 10 minutes with no matching running process MAY be broken, after the user confirms.
• v1 supports one writer at a time. Two machines writing the same drive is out of scope.
9.3 Garbage collection
On a writable unlock, and after large deletes:
1. Walk the trees reachable from both root slots and collect every live ID.
2. Delete .tjo files whose ID is not live, and any .tmp files.
Keeping the previous commit's objects means a torn latest commit always has a complete fallback. Deleted data stays recoverable from the flash chips until overwritten; section 14 covers this.
10. Rollback detection
A drive cannot stop someone restoring an older copy of itself, so each device remembers the newest state it has seen and warns when the drive goes backwards.
Each device keeps a local record, outside the drive, per vault:
vault_uuid → { max_rev, root_hash at max_rev, last_seen }
What the drive shows, against this device's record
Result
No record yet
First time on this device; create the record
rev > max_rev
Normal; update the record
rev = max_rev, same hash
Normal
rev = max_rev, different hash
Fork warning: two versions share a revision
rev < max_rev
Rollback warning: this drive is older than one already seen here
• Warnings let the user continue read-only, accept the older state, or cancel.
• The record lives in the app's private storage (macOS Application Support, Linux $XDG_DATA_HOME, Android app storage). It is encrypted with a key held in the OS keychain where available.
• This cannot protect a vault on a device that has never seen it. That limit is stated in section 14.
11. Names and metadata
Names are stored exactly once, inside encrypted directory objects, and follow strict rules so a vault made on macOS opens identically on Linux and Android.
• A name is 1 to 255 bytes of UTF-8, normalized to NFC before storing or comparing. macOS often supplies decomposed (NFD) names; without this, café could appear twice.
• A name MUST NOT contain / or NUL, and MUST NOT be . or ...
• Names are unique within a directory, compared as NFC bytes. The format is case-sensitive: Notes.txt and notes.txt may both exist.
• On exporting or mounting to a case-insensitive or Windows host, the app shows clashing or reserved names (CON, trailing dots) with a visible suffix. It never silently overwrites.
• mtime is preserved. Creation time, owner, group, ACLs and extended attributes are not stored in v1.
• Symlinks, hard links, devices and sockets are skipped on import with a warning.
11.1 Host-visible metadata
exFAT records its own timestamps on each .tjo file, which could reveal when the vault was used. Writers SHOULD set the modified and accessed times of every file inside TIJORI/ to 2000-01-01T00:00:00Z. exFAT creation times cannot be reset on every platform, so some write-time information may still leak (section 14).
12. Parser limits
A hostile drive is the main attack surface, so readers enforce these limits before allocating memory or running Argon2id, and reject anything outside them.
Item
Minimum
Maximum
Why
vault.header size
1120 bytes
1120 bytes
Fixed layout
argon_mem_kib
65,536 (64 MiB)
1,048,576 (1 GiB)
Floor keeps guessing costly; cap stops a drive exhausting RAM
argon_ops
2
64
Cap bounds unlock time
argon_lanes
1
1
libsodium compatibility
Non-empty keyslots
1
8
Fixed table
Root pointer file
41 bytes
4 KiB
Small fixed map
Directory plaintext
8 bytes
64 MiB
Bounds memory per folder
Entries per directory
0
200,000
Same
Tree depth
1
256
Stops recursion attacks
Name length
1 byte
255 bytes
Matches common file systems
Object plaintext
8 bytes
2^62 bytes
Avoids integer overflow
Writers SHOULD NOT create slots above 256 MiB, because low-end phones may fail to open them. Readers allow up to 1 GiB so a user can choose stronger settings deliberately, with a warning.
CBOR rules for readers
• Only definite-length items; no tags, floats or undefined values.
• Reject duplicate map keys and non-shortest integer encodings.
• Reject any value whose type differs from the schema in section 8.
• Fuzz every parser (header, keyslot, root pointer, directory, object stream) with cargo-fuzz in CI.
13. Versioning
A reader opens a vault only when it understands everything the vault requires; older apps refuse newer vaults cleanly rather than corrupting them.
Change
Mechanism
Old reader's behaviour
New optional field in a directory entry or root pointer
New CBOR key
Ignores it; keeps it when copying entries
New optional feature that old readers can safely skip
Bit in optional_features
Ignores it
Feature that changes how data must be read
Bit in required_features
Refuses to open, names the needed app version
New keyslot or KDF type
New slot_type or kdf_id
Skips that slot; other slots still work
Incompatible redesign
format_major = 2
Refuses to open
• format_minor increases with every published change to this spec; it is informational only.
• Version bytes inside objects and root pointers let one part evolve without a new major version.
• An upgrade that writes a newer format MUST ask the user first, because older Tijori apps on their other devices will stop opening the drive.
14. Security considerations
The design protects contents, names and structure against anyone holding the drive; this section lists exactly what still leaks or is out of reach, so users and reviewers are not surprised.
14.1 Visible to anyone holding the drive
What
How much
Mitigation
It is a Tijori vault
Fully (folder name, magic bytes)
None in v1; hidden volumes are a non-goal
Number of objects (files + folders combined)
Exact
None in v1
Object sizes
Padmé-rounded
Padding on by default
Which keyslot types are in use
Exact (slot_type is plain)
Accepted; hiding it would mean running Argon2id up to 8 times per unlock
Argon2id parameters
Exact
Accepted; they are not secret
When the vault was written
Partly (exFAT creation times)
Fixed modified/accessed times (11.1)
14.2 Known limits
• Old headers survive on flash. USB drives remap blocks internally, so an overwritten header may still be readable with lab tools. Changing a password does not lock out someone who copied the old header and knows the old password; only re-keying does. The app MUST say this when a password is changed.
• Deleted files survive on flash for the same reason, but stay encrypted; without MK they are as safe as live data.
• Rollback is detected only on devices that saw the newer state (section 10).
• A compromised host sees everything while the vault is unlocked. No format can fix that.
• Weak passwords remain the biggest risk. Writers MUST refuse passwords scoring below 3 on zxcvbn and SHOULD suggest a 6-word passphrase.
14.3 Deliberate choices
• No compression. Compressing before encrypting can leak content through size changes.
• No deduplication. Sharing objects between identical files would reveal that two files are the same.
• Random 192-bit nonces everywhere. Nonce reuse is not a practical risk, so no counters need to survive crashes.
• Immutable objects. No ciphertext is ever overwritten in place, which removes a whole class of nonce and torn-write bugs.
• Memory hygiene. Keys use zeroize and secrecy, are locked in RAM where the OS allows, and are wiped on lock, sleep, drive removal and idle timeout.
15. Test vectors
The spec is frozen only when every implementation passes one shared set of JSON vectors in spec/vectors/, generated by an independent script that calls libsodium directly rather than by the Rust core.
File
Checks
Includes failing cases
kek.json
KEK for all three slot types, including NFC and non-ASCII passwords
Wrong keyfile, NFD password
keyslot.json
Wrap and unwrap of MK
Changed parameter, swapped slot index, other vault UUID
subkeys.json
K_hmac, K_root, K_obj, object keys
None
header.json
Full 1120-byte headers and MAC
Flipped MAC bit, unknown required bit, out-of-range Argon2
padme.json
Padded lengths for selected sizes from 8 bytes to 2^40
None
object.json
Encrypted objects from fixed keys and stream headers
Truncated, extended, reordered chunk, wrong kind, non-zero padding
root.json
Root pointers for slots A and B
Swapped slot letter, other vault UUID
dir.json
Exact deterministic CBOR bytes for directories
Unsorted entries, duplicate names, float values
vault/
Complete small vaults on disk
A vault with a torn newest root slot that must open at the previous commit
Each vector lists its inputs in hex, expected output in hex, and for failing cases the exact error class (wrong_secret, tampered, damaged, unsupported). The Kotlin and Python bindings run the same files in CI.
16. Open questions for review
Six questions remain before v1.0 is frozen; none changes the layout above, so coding the core can start now.
[ ] Large folders. One object per directory means a folder with 100,000 files is rewritten whole on every change. Split big directories into a B-tree in v1.1, or accept it for v1?
[ ] Hardware keys. Add a slot_type 4 for FIDO2 security keys (hmac-secret) in v1.1?
[ ] Hiding slot types. Is the small leak of which unlock methods exist worth the slower unlock that hiding it would cost?
[ ] exFAT timestamps. Test whether macOS, Linux and Android can each reset modified and accessed times on exFAT, and document what still leaks.
[ ] Library choice. dryoc (pure Rust) or libsodium bindings for the core? Pure Rust is easier to build for Android and iOS; libsodium has the longer audit record.
[ ] Recovery phrase language. BIP-39 has word lists in several languages, including no Hindi list. English only for v1?
