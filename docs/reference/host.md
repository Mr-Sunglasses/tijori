# On your computer

<p class="tj-lead">What Tijori keeps on each computer it runs on, and the environment variables that change its behaviour.</p>

## The data folder

Tijori keeps a small private folder on every computer:

| System | Location |
|---|---|
| macOS | `~/Library/Application Support/Tijori` |
| Linux | `$XDG_DATA_HOME/tijori`, usually `~/.local/share/tijori` |

It holds:

- **a device ID**, a random number that tells this computer's writes apart
  from other computers' (it shows up in lock messages such as "Tijori on
  another device");
- **one rollback record per vault** you have opened here: the newest revision
  seen and a fingerprint of it, encrypted. This is how Tijori notices when a
  drive is replaced by an older copy. See
  [Old copies of a drive](../security/threat-model.md#old-copies-of-a-drive).

It never holds passwords, keys to your vaults, file names or file contents.
Deleting the folder is harmless: Tijori creates a new one, and only loses
the ability to warn about older copies of drives it saw before.

## The keychain

The rollback records are encrypted with a key kept in the system keychain:
the **macOS Keychain**, or the **Secret Service** (GNOME Keyring, KWallet) on
Linux. When no keychain is available, the key is stored in the data folder,
readable only by you, and Tijori prints a warning.

## Environment variables

| Variable | Effect |
|---|---|
| `TIJORI_DATA_DIR` | Use this folder instead of the default data folder. |
| `TIJORI_NO_KEYRING=1` | Do not use the system keychain; keep the rollback key in the data folder. Useful on headless machines. |
| `TIJORI_TEST_FAST_KDF=1` | **For automated tests only.** New passwords use the weakest allowed Argon2id settings. Tijori prints a warning every time it is set. Never use it for real vaults. |

## Network

Tijori makes no network connections: no updates check, no telemetry, no
crash reports. Its build configuration bans HTTP client libraries outright.
