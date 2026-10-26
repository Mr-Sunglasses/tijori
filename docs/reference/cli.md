# Command line

<p class="tj-lead">Every <code>tijori</code> command and option. Run <code>tijori help &lt;command&gt;</code> for the same information in your terminal.</p>

```text
tijori [GLOBAL OPTIONS] <COMMAND> [ARGS]
```

## Global options

These work with every command that opens a vault.

| Option | Meaning |
|---|---|
| `--vault <PATH>` | The drive, or its `TIJORI` folder. Without it, Tijori uses the only mounted drive that holds a vault. |
| `--with-recovery` | Unlock with the 24-word recovery phrase instead of a password. |
| `--with-keyfile <PATH>` | Unlock a password + keyfile slot with this keyfile. |
| `--password-stdin` | Read passwords, phrases and confirmations from standard input, one per line, instead of prompting on the terminal. Meant for scripts. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

## Creating and opening

### `init`

```text
tijori init [--label <LABEL>] [--keyfile <PATH>] [--no-padding] <DRIVE>
```

Creates a vault on a drive. Asks for a new password, shows the recovery
phrase once and waits for you to type `I UNDERSTAND`. Refuses if the drive
already has a vault.

| Option | Meaning |
|---|---|
| `<DRIVE>` | The drive's mount point, for example `/Volumes/KINGSTON`. |
| `--label <LABEL>` | A name for the vault, up to 64 bytes. |
| `--keyfile <PATH>` | Also require this keyfile, together with the password. |
| `--no-padding` | Store exact file sizes instead of padding them. |

### `shell`

```text
tijori shell [DRIVE]
```

Unlocks once and reads commands until `exit` (or ++ctrl+d++), then locks.
Every command in [Files](#files) and [Vault upkeep](#vault-upkeep) works
inside it, without the `tijori` prefix. Opens read-only, with a note, if
another Tijori is writing.

### `mount`

```text
tijori mount [--idle-minutes <N>] [DRIVE] [MOUNTPOINT]
```

Shows the vault as a volume until you press ++ctrl+c++, eject it, unplug the
drive, or leave it idle. See [Mounting as a folder](../guide/mounting.md).

| Option | Meaning |
|---|---|
| `[MOUNTPOINT]` | Where to mount. Default: `/Volumes/<label>` on macOS, `$XDG_RUNTIME_DIR/tijori/<label>` on Linux. |
| `--idle-minutes <N>` | Lock after this many idle minutes; `0` never locks for idleness. Default `15`. |

## Files

### `ls`

```text
tijori ls [-l] [PATH]
```

Lists a folder in the vault (default `/`). With `-l`, shows kind (`d`
folder, `x` executable, `-` file), size in bytes and modification time in
UTC.

### `put`

```text
tijori put <LOCAL>... <VAULT_DIR>
```

Adds local files and folders (recursively) to a vault folder, creating it if
needed. Replaces files of the same name. Skips symbolic links and special
files.

### `get`

```text
tijori get <VAULT_PATH>... <LOCAL_DIR>
```

Copies files and folders out of the vault into a local folder. Never
overwrites: a clashing name gets a ` (1)` suffix.

### `cat`

```text
tijori cat <PATH>
```

Writes a file's contents to standard output.

### `mkdir`

```text
tijori mkdir [-p] <PATH>
```

Creates a folder. `-p` also creates missing parent folders.

### `mv`

```text
tijori mv <FROM> <TO>
```

Moves or renames a file or folder. If `<TO>` is an existing folder, the item
is moved into it.

### `rm`

```text
tijori rm [-r] <PATH>
```

Deletes a file. `-r` deletes a folder and everything in it.

## Keys

### `passwd`

```text
tijori passwd [--slot <N>]
```

Changes the password of a password slot: by default the one you unlocked
with, or else the first password slot. For a password + keyfile slot, pass
the keyfile with `--with-keyfile`.

### `keyslot list`

Shows the keyslots in use, their type and Argon2id settings, and which one
you unlocked with.

### `keyslot add`

```text
tijori keyslot add [--keyfile <PATH> | --recovery]
```

Adds a password slot, a password + keyfile slot (`--keyfile`), or a new
24-word recovery phrase (`--recovery`). A vault holds at most 8 slots.

### `keyslot remove`

```text
tijori keyslot remove <INDEX>
```

Removes a keyslot. The last one can never be removed.

### `rekey`

Re-encrypts everything under a new master key. Afterwards the vault has
exactly one password and one new recovery phrase. See
[Re-key](../guide/passwords.md#re-key).

## Vault upkeep

### `info`

Shows the drive, format version, vault ID, revision, last write time,
settings, keyslots and whether the vault was opened read-only.

### `settings`

```text
tijori settings [--label <LABEL>] [--padding on|off] [--private-only on|off]
```

Shows the settings, or changes them. Padding applies to files added after
the change. Private-only refuses mounting.

### `verify`

Checks every hash and decrypts every piece of every file and folder.
Reports problems by path and exits with code 3 (tampered) or 4 (damaged) if
it finds any.

### `gc`

Deletes encrypted objects nothing refers to any more, and leftovers of
interrupted writes.

### `backup`

```text
tijori backup [--force] <DEST>
```

Copies the whole vault, still encrypted, to another folder or drive, creating
the folder if needed. Run again to update the copy; only changes are copied.
`--force` overwrites a copy that has changes this vault does not have. See
[Backups](../guide/backups.md).

### `restore`

```text
tijori restore [--force] <BACKUP> <DRIVE>
```

Copies a backup onto a drive, so the drive holds the backup's state. Only
what differs is copied. `--force` overwrites the drive's vault even if it has
changes the backup does not have.

### `break-lock`

```text
tijori break-lock [--force]
```

Removes a lock left behind by a Tijori that is no longer running, after you
type `BREAK`. Without `--force` it refuses locks refreshed in the last 10
minutes.

### `completions`

```text
tijori completions <bash|zsh|fish|elvish|powershell>
```

Prints a shell completion script. See
[Install](../getting-started/install.md#4-optional-tab-completion).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Any other error |
| 2 | Wrong password, keyfile or recovery phrase |
| 3 | The vault has been tampered with |
| 4 | The vault is damaged |
| 5 | The vault needs a newer Tijori |
| 6 | Another Tijori holds the vault's lock |

In `tijori shell` reading commands from a script (not a terminal), the exit
code reports the last command that failed.
