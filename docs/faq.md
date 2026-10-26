# FAQ

## Where do I copy my files? Into the TIJORI folder?

No, never into the `TIJORI` folder. That folder is Tijori's encrypted
storage. Add files with `tijori put`, inside `tijori shell`, or by mounting
the vault with `tijori mount` and copying into the mounted volume (named
after your vault, for example `/Volumes/Personal`).
[Where your files go](guide/how-it-works.md) explains why.

## Someone can just delete the TIJORI folder. How is that protected?

It is not, and no encryption tool can prevent it: anyone holding a drive can
erase it. Encryption protects what is in your files, not whether they still
exist. The protection against loss is a second copy, which
[`tijori backup`](guide/backups.md) keeps up to date for you, encrypted.

## What if I forget my password?

Unlock with your 24-word recovery phrase (`tijori --with-recovery ...`) and
set a new password. If you lose both, the files cannot be recovered by
anyone.

## Can Tijori developers open my vault?

No. There is no master password, no key escrow and no server. Tijori never
connects to the network.

## Does it work on Windows?

Not yet. Windows support is planned after the first version for macOS,
Linux and Android. The drive itself is exFAT, which Windows reads, but you
need Tijori to decrypt it.

## Do I need macFUSE?

Only for mounting the vault as a folder on macOS. Every other command works
without it.

## Can I keep other files on the same stick?

Yes. The vault lives in the `TIJORI` folder and leaves everything else on the
drive alone. Those other files are not encrypted.

## Can I have two vaults on one stick?

Not on the same drive root, because a vault is always the `TIJORI` folder at
the top of the drive. You can partition the stick into two exFAT volumes, or
use two sticks.

## Is it safe to unplug the stick without ejecting?

The vault itself is designed for it: every change is committed so that the
vault opens at the old state or the new one, never a broken mix. Changes
from the last couple of seconds can be lost. For other files on the stick,
ejecting first is still a good idea, as with any drive.

## How much space does encryption cost?

Each file grows by 17 bytes per 64 KiB, plus a little for its folder
listing. With padding on (the default), sizes are also rounded up so exact
sizes are hidden, which costs up to about 12% and on average much less. Turn
padding off with `tijori settings --padding off` if space matters more.

## How big can files be?

Far bigger than any USB stick. Files stream through Tijori in 64 KiB pieces,
so size is limited by the drive and exFAT, not by memory. When mounted, a
file can be changed in place up to 1 GiB; bigger ones can still be added and
read.

## Can I put the vault in Dropbox or iCloud?

Use `tijori backup ~/Dropbox/Tijori` to keep an encrypted copy there. The
provider sees only encrypted objects and their rounded sizes. Do not open and
change the same vault from two computers through a sync service at the same
time: sync tools do not respect Tijori's lock.

## Has Tijori been audited?

Not yet. It uses only standard, well studied building blocks (Argon2id,
XChaCha20-Poly1305, BLAKE2b) through a libsodium-compatible library, and its
format is specified and tested against an independent implementation. That
is not the same as an audit. Until it has one, do not rely on Tijori as the
only protection for high-stakes data.

## Why the name?

*Tijori* (तिजोरी) is Hindi for "strongbox", the steel safe many Indian
households keep their valuables in.
