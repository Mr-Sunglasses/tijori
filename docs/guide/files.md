# Working with files

<p class="tj-lead">Adding, finding, moving and taking out files from the command line. If you prefer Finder or a file manager, see <a href="../mounting/">Mounting as a folder</a>.</p>

## Paths inside the vault

Paths inside the vault always start at `/`, the top folder of the vault, and
use `/` between folders: `/Taxes/2025.pdf`. They have nothing to do with
paths on your computer or on the stick.

- Names are case sensitive: `/Notes` and `/notes` are two different folders.
- A name can be up to 255 bytes long and cannot contain `/`.
- Quote paths that contain spaces: `tijori ls "/Holiday 2026"`.

## Adding files: `put`

```console
$ tijori put ~/Documents/Taxes ~/Pictures/scan.png /Paperwork
Added 3 files (2.1 MiB) and 1 folder to /Paperwork.
```

Everything except the last argument comes from your computer. The last
argument is the folder in the vault, which is created if it does not exist.

- Folders are copied with everything in them.
- Each file keeps its modification time and, on macOS and Linux, its
  executable bit. Owners, permissions, extended attributes and creation
  times are not stored.
- Symbolic links and special files (sockets, devices) are skipped with a
  message.
- A file that already exists in the vault under the same name is replaced.

## Listing: `ls`

```console
$ tijori ls /Paperwork
Taxes/
scan.png
$ tijori ls -l /Paperwork
d            -  2026-10-26 18:45  Taxes/
-       482113  2026-10-25 09:12  scan.png
```

With `-l`, the first column is `d` for a folder, `x` for an executable file
and `-` for any other file, followed by the size in bytes and the
modification time in UTC.

## Taking files out: `get`

```console
$ tijori get /Paperwork/Taxes /Paperwork/scan.png ~/Desktop
Copied 3 files (2.1 MiB) and 1 folder to /Users/you/Desktop.
```

The last argument is a folder on your computer. `get` **never overwrites**:
if a name is taken it saves the copy as `scan (1).png` and tells you.

Each file is decrypted into a hidden temporary file first and only gets its
real name once it is complete and checked. If something goes wrong (a
damaged file, a full disk, or you press ++ctrl+c++), the partly decrypted
temporary file is deleted, so no half-finished plain copy is left behind.

## Reading a file: `cat`

```console
$ tijori cat /notes/wifi.txt
$ tijori cat /backups/db.sql | psql mydb
```

`cat` writes the file to standard output without creating any file on your
computer, which makes it handy for pipes.

## Folders, moving and deleting

```console
$ tijori mkdir /Photos             # one folder
$ tijori mkdir -p /Photos/2026/May # with any missing parents
$ tijori mv /scan.png /Paperwork   # into an existing folder
$ tijori mv /Paperwork /Documents  # rename
$ tijori rm /Paperwork/scan.png    # a file
$ tijori rm -r /Old                # a folder and everything in it
```

There is no trash inside the vault: `rm` deletes for good once it finishes.
Deleted data can still physically remain on the flash chip for a while,
encrypted. See [What Tijori protects](../security/threat-model.md).

## Many commands with one password: `shell`

```console
$ tijori shell
Password:
Vault unlocked. Type `help` for commands, `exit` to lock.
tijori> ls
tijori> put ~/Downloads/statement.pdf /Paperwork
tijori> exit
Vault locked.
```

Inside the shell every vault command works without the `tijori` prefix.
`exit` (or ++ctrl+d++) commits any changes, releases the drive and wipes the
keys from memory.

## Pressing Ctrl+C

During a long `put`, `get`, `verify`, `rekey` or `backup`, ++ctrl+c++
cancels cleanly:

- `put` stops after the current file. Files that were completely added stay
  in the vault; the unfinished one is not added.
- `get` deletes the file it was decrypting. Files already copied stay.
- `backup` leaves the backup at the state it had before.
- The vault's lock is released, so the next command does not complain that
  the vault is in use.

## Checking and tidying the vault

| Command | What it does |
|---|---|
| `tijori info` | Shows the label, format version, revision, settings and keyslots. |
| `tijori verify` | Reads every file and folder and checks every piece. Reports anything damaged or tampered with, by path. |
| `tijori gc` | Deletes encrypted objects that the vault no longer uses. Old versions pile up as you change files (especially while mounted), so run it now and then to free space. |

## Settings

```console
$ tijori settings
Label:        Personal
Padding:      on
Private only: off
$ tijori settings --label "Family photos" --padding off
```

| Setting | Meaning |
|---|---|
| `--label` | The vault's name, up to 64 bytes. Used as the volume name when mounting. |
| `--padding on/off` | With padding on (the default), each file's stored size is rounded up so its exact size is hidden. This costs up to about 12% extra space. The change applies to files added afterwards. |
| `--private-only on/off` | When on, the vault refuses to be mounted. Files can then only be reached through Tijori itself, never through Finder or other apps. |

## Using Tijori in scripts

`--password-stdin` reads the password (and any confirmation Tijori would
normally ask for) from standard input, one per line:

```console
$ pass show tijori | tijori --password-stdin --vault /Volumes/KINGSTON ls /
```

Commands exit with a code that says what went wrong; see
[exit codes](../reference/cli.md#exit-codes).
