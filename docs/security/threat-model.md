# What Tijori protects

<p class="tj-lead">An honest list of what Tijori is built to stop, what it only detects, and what is outside its reach.</p>

## The situation Tijori is built for

You carry private files on a USB stick. The stick can be lost, stolen,
borrowed, or copied while you are not looking. Tijori's job is to make sure
that whoever ends up with the stick, or a copy of it, learns as little as
possible and cannot change your files without you noticing.

## Protected

**Reading your files.** Without a password, keyfile or recovery phrase, the
content of every file is unreadable. Each file has its own key derived from
the vault's master key, and the master key exists on the drive only in
encrypted form.

**File names and structure.** Names, the folder tree, dates you stored and
exact sizes are inside encrypted folder objects. On the drive every file and
every folder is an object with a random name, and the two kinds look the
same.

**Exact file sizes.** With padding on (the default), each stored size is
rounded up, so a 1,000,000 byte file and a 1,010,000 byte file look the same.

**Guessing the password.** Every guess costs one Argon2id computation with
256 MiB of memory and about a second of work on a normal computer, and
Tijori refuses passwords that are easy to guess. Specialised hardware helps
an attacker less against Argon2id than against older methods, because each
attempt needs that much memory.

**Changing files without you noticing.** Every piece of every object is
authenticated, every folder records the hash of each item in it, and the
header carries a MAC. Flipping a bit, cutting a file short, or swapping two
objects (even two valid ones) is reported as *tampered*, and Tijori never
shows you the altered data.

**A crash or a pulled drive.** Changes are written copy-on-write, so an
interrupted write leaves the previous state intact. This is tested by
simulating a crash at every single write of every operation.

## Detected, within limits

### Old copies of a drive

Someone could copy your stick today and later write that copy back, for
example to bring back a file you deleted, or an old password you changed.
Every copy is perfectly valid, so encryption alone cannot notice.

Tijori remembers on each computer the newest revision of each vault it has
seen. If a drive shows up with an older revision, or with a different
version at the same revision, Tijori warns you and opens it read-only
unless you accept. This only works on computers that saw the newer state:
a computer that never opened the vault cannot know.

## Not protected

**Losing the drive or its contents.** Anyone can delete the `TIJORI` folder
or format the stick. Encryption cannot prevent that.
[Backups](../guide/backups.md) are the protection.

**A compromised computer.** While a vault is unlocked, the computer sees
everything: the password as you type it, and the files as you open them.
Malware, a keylogger, or someone with administrator access can take them.
Only unlock vaults on computers you trust.

**What apps do with open files.** When the vault is mounted, apps that open
a file may keep autosaves, caches, thumbnails or recent-file lists outside
the vault. Tijori turns off Spotlight, Time Machine and Quick Look caches for
the mounted volume, but it cannot control every app.
[Private-only](../guide/mounting.md#private-only-vaults) vaults avoid this
by refusing to mount.

**Old copies opened with an old password.** Changing a password only
re-locks the master key. Anyone holding a copy made before the change can
still open that copy with the old password. Re-keying protects data written
afterwards, but not old copies.

**Leftover data on flash.** USB sticks spread writes across their memory
cells and do not erase old data right away. Deleted (encrypted) objects and
old headers can survive physically for some time. They stay encrypted, but
an old header still opens with the password it had.

**Weak passwords.** Tijori refuses obviously weak ones, but a password you
also use on websites, or one that appears in a leak, can still be guessed.
Use a passphrase of random words that you use nowhere else.

**Being forced to unlock.** Tijori has no hidden volumes and no plausible
deniability. Anyone can see that a drive holds a Tijori vault.

## What someone with the drive can see

Tijori hides a lot, but not everything. Someone holding the drive can learn:

- that it is a Tijori vault;
- how many objects it holds (roughly: the number of files plus folders,
  plus old versions not yet cleaned up);
- each object's size, rounded up when padding is on;
- which kinds of keyslots exist (password, password + keyfile, recovery
  phrase) and their Argon2id settings;
- creation times of the encrypted files as exFAT records them (Tijori sets
  the other timestamps to 1 January 2000);
- on drives written by macOS, small `._` files that name the program that
  wrote them.

## Not audited yet

Tijori uses standard building blocks only and has an independent test
implementation, but nobody outside the project has reviewed it. Until that
happens, treat it as a promising tool, not a proven one.

See [Cryptography](cryptography.md) for how each protection is built.
