# Mounting as a folder

<p class="tj-lead">Mounting makes the unlocked vault appear as its own volume, so any app can open, edit and save files in it. Everything written there is encrypted onto the stick.</p>

## Before you start

Mounting needs a small helper from your operating system's FUSE project:
[macFUSE](https://macfuse.github.io) 5 on macOS, FUSE 3 on Linux. The
[install page](../getting-started/install.md#3-optional-mounting-support)
has the steps. Everything else in Tijori works without it.

!!! note "Why macFUSE on macOS?"
    macOS has no built-in way for an app to show its own encrypted volume.
    macFUSE provides one, and its FSKit backend needs no kernel extension and
    no lowering of your Mac's security. A later version of Tijori is planned
    to ship its own FSKit extension so this extra install goes away.

## Mount

```console
$ tijori mount
Password:
Mounted at /Volumes/Personal. Press Ctrl+C (or eject the volume) to lock.
```

The volume is named after the vault's label. Leave the terminal open: the
vault stays unlocked for as long as the command runs.

| System | Where the vault appears |
|---|---|
| macOS | `/Volumes/<label>`, and in the Finder sidebar under Locations |
| Linux | `$XDG_RUNTIME_DIR/tijori/<label>`, usually `/run/user/1000/tijori/<label>` |

To choose the place yourself, give it after the drive:
`tijori mount /Volumes/KINGSTON ~/Vault`. On macOS the mount point has to be
under `/Volumes`.

## Use it

Copy files into the mounted volume, open them in any app, save, rename,
delete. Changes are encrypted in memory and written to the stick within a
couple of seconds, and once more when the vault locks.

Remember the difference between the two volumes you now see:

- `Personal` (the mounted vault) is where your files go.
- `KINGSTON` (the stick) holds the encrypted `TIJORI` folder. Leave it alone.

See [Where your files go](how-it-works.md) if this is new.

## Lock it again

Any of these unmounts the volume, writes the last changes and wipes the keys
from memory:

- press ++ctrl+c++ in the terminal running `tijori mount`;
- eject the volume (`Personal`) in Finder or your file manager;
- unplug the stick;
- leave it untouched for 15 minutes.

```console
Unmounted on request; the vault is locked.
```

The idle timeout is `--idle-minutes`. Use `--idle-minutes 0` to turn it off.

!!! tip "Pulling the stick out"
    It is fine to unplug the drive while the vault is mounted. Changes that
    were already committed are safe, and the vault opens at a complete state
    next time. Anything written in the last second or two before you pulled
    it may be lost, the same as with any drive.

## What Tijori does to keep the mounted files private

While mounted, the decrypted files exist only in memory and are passed to
apps on request. Tijori also:

- **turns off Spotlight** for the volume and checks that it really is off,
  so file names and contents never enter the search index;
- **keeps the volume out of Time Machine** and checks the exclusion;
- **clears the Quick Look thumbnail cache** after unmounting on macOS;
- makes the volume **readable only by you**: other users on the computer
  cannot open it;
- **refuses to store** `.DS_Store`, `._*` and similar metadata files that
  macOS likes to create, so they do not travel to other computers inside the
  vault.

!!! warning "Apps can still keep copies"
    Once an app opens a file, Tijori cannot control what the app does with
    it. Editors may write autosave or recovery copies to your home folder,
    and some apps keep "recent files" lists with names. If that matters to
    you, use [Private only](#private-only-vaults) mode and work with
    `tijori get` / `cat` into places you control.

## Read-only mounts

If another Tijori (on this computer or another one) is already writing to the
vault, `tijori mount` mounts it **read-only** and says why. You can open
files but not change them until the other writer finishes.

## Private-only vaults

```console
$ tijori settings --private-only on
```

A private-only vault refuses to be mounted anywhere. Its files can only be
reached through Tijori's own commands. This is useful for a vault you never
want to show to other apps by accident.

## Limits

- A file opened for writing is edited in memory, up to **1 GiB** per file.
  Larger files can be added with `tijori put` and read from the mount, but
  not changed in place.
- Reading files bigger than 16 MiB streams them. Apps that jump backwards
  inside very large files work, just more slowly.
- Extended attributes (Finder tags, comments) are accepted but not stored.
- On macOS, every file a program writes on the exFAT stick gets a small
  `._` companion file holding a "provenance" tag that names the writing app.
  Tijori deletes these inside the `TIJORI` folder when it tidies up, but it
  cannot stop macOS from creating them.
