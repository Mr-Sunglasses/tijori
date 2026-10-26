# Troubleshooting

<p class="tj-lead">What Tijori's messages mean and what to do about them.</p>

Tijori sorts every failure into a few kinds on purpose. A typo in your
password and a drive that someone has tampered with are very different
situations, and you should never be left guessing which one you are in.

## Wrong password, keyfile or recovery phrase

```text
tijori: wrong password, keyfile or recovery phrase
```

No keyslot opened with what you typed. Check the keyboard layout and Caps
Lock. If the slot needs a keyfile, pass it with `--with-keyfile`. If you
forgot the password, use the [recovery phrase](passwords.md#the-recovery-phrase).

Exit code **2**.

## The vault has been tampered with

```text
tijori: the vault has been tampered with: a file object does not match its hash
```

Your password was right, but a piece of the vault does not match what Tijori
wrote. Someone may have changed the drive on purpose, or the data changed on
a failing stick. Tijori cannot tell the two apart, so it reports the more
serious possibility and never shows you the altered data.

1. Do not write to the vault.
2. Run `tijori verify` to see which files are affected.
3. Copy out what is still fine with `tijori get`, and restore the rest from a
   [backup](backups.md).

Exit code **3**.

## The vault is damaged

```text
tijori: the vault is damaged: a folder object is missing
```

Part of the vault is unreadable or missing, without signs of deliberate
tampering. Common causes are a failing stick, files deleted from inside the
`TIJORI` folder, or a sync tool that copied only part of it. As above:
`tijori verify`, copy out what you can, restore from a backup.

If only one of Tijori's two copies of the header or root pointer was hit (for
example by an interrupted write), Tijori quietly uses the other copy and
tells you:

```text
Note: the main header could not be used; the backup copy opened the vault.
```

That is not a problem by itself, but if it keeps happening the stick may be
failing.

Exit code **4**.

## This vault needs a newer version of Tijori

The vault was created or upgraded by a newer Tijori that uses a feature this
version does not know. Update Tijori. Your data is untouched.

Exit code **5**.

## The vault is in use

```text
tijori: the vault is in use by another Tijori on this computer (lock refreshed 0 minutes ago). If nothing else is using this drive, run `tijori break-lock`.
```

Only one Tijori writes to a vault at a time. While one has it open for
writing (a `shell`, a `mount`, a long `put`), others can still read but not
change it. Commands that only read, like `ls`, `get` and `verify`, keep
working.

If no Tijori is actually running (for example the computer crashed while a
vault was mounted), remove the leftover lock:

```console
$ tijori break-lock
Breaking the lock while another Tijori is writing can lose that writer's latest changes.
Type BREAK to remove the lock:
```

A lock refreshed in the last 10 minutes may still belong to a running
Tijori, so `break-lock` refuses unless you add `--force`.

Exit code **6**.

## The drive is older than this computer has seen

```text
Warning: this drive is at revision 17, older than revision 19 this computer has seen. Someone may have restored an old copy of the drive.
```

The vault on the drive is older than the newest state this computer has seen
before. If you restored a backup yourself, answer `a` (accept). If you did
not, someone may have replaced the drive's contents with an old copy, for
example to bring back a file you deleted. Answer `r` to look around
read-only.

A related warning says the drive "differs from the revision this computer
saw". That means two copies of the same vault were changed separately (for
example the original and a backup), so they have forked.

See [Backups and lost drives](backups.md#this-drive-is-older-than-a-revision-this-computer-has-seen).

## Several drives hold a Tijori vault

```text
tijori: several drives hold a Tijori vault; pick one with --vault:
  /Volumes/KINGSTON
  /Volumes/BACKUPSTICK
```

Say which one you mean: `tijori --vault /Volumes/KINGSTON ls`.

## No mounted drive holds a Tijori vault

Tijori looks for vaults in `/Volumes` on macOS, and in `/media/$USER`,
`/run/media/$USER`, `/media` and `/mnt` on Linux. If your drive is somewhere
else, or the vault is in a folder, pass the path with `--vault`.

## Mounting problems

**"File system extension not enabled" (macOS).** Open System Settings →
General → Login Items & Extensions → File System Extensions and switch on
macFUSE, then try again.

**Tijori says macFUSE or FUSE is missing.** See
[Install](../getting-started/install.md#3-optional-mounting-support). All
other commands work without it.

**The vault refuses to mount.** It is set to private-only:
`tijori settings` shows `Private only: on`. Turn it off with
`tijori settings --private-only off`, or keep using the command line.

**The volume is read-only.** Another Tijori is writing to the vault. See
[The vault is in use](#the-vault-is-in-use).

## A Keychain prompt on macOS

The first time Tijori runs, macOS may ask whether Tijori may use a key in your
login keychain. That key protects the small record Tijori keeps on your
computer to [detect old copies of a drive](../security/threat-model.md#old-copies-of-a-drive).
Choose **Always Allow**. A self-built `tijori` may ask again after each
rebuild, because macOS ties the permission to the exact program.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Any other error (bad arguments, missing paths, cancelled, ...) |
| 2 | Wrong password, keyfile or recovery phrase |
| 3 | The vault has been tampered with |
| 4 | The vault is damaged |
| 5 | The vault needs a newer Tijori |
| 6 | Another Tijori holds the vault's lock |
