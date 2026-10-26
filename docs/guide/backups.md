# Backups and lost drives

<p class="tj-lead">Encryption stops other people from reading your files. It cannot stop a drive from being lost, broken, wiped or having its <code>TIJORI</code> folder deleted. Only a second copy protects against that, and Tijori makes that copy easy.</p>

## What can go wrong

| What happens | Can someone read your files? | Are your files gone? |
|---|---|---|
| The stick is lost or stolen | No | Yes, unless you have a backup |
| The stick stops working (flash memory does wear out) | No | Yes, unless you have a backup |
| Someone deletes the `TIJORI` folder or formats the stick | No | Yes, unless you have a backup |
| You delete a file inside the vault by mistake | No | Yes, unless you have a backup |

A vault is a folder of ordinary files on a removable drive. Anyone who can
plug the drive in can delete that folder, with or without your password, and
no amount of encryption changes that. The answer is the same one that
applies to any important data: **keep at least one more copy, somewhere
else.**

## Make a backup

```console
$ tijori backup /Volumes/BACKUPSTICK
Password:
Backed up revision 14 to /Volumes/BACKUPSTICK: 212 objects copied (812.6 MiB).
```

The backup is a complete vault of its own, **still encrypted**, with the same
passwords, keyfiles and recovery phrase. It can live:

- on a **second USB stick** or an external disk (best: kept at a different
  place than the first stick);
- in a **folder on your computer**, such as `~/Backups/Personal`;
- in a **cloud-synced folder** (iCloud Drive, Dropbox, a Nextcloud folder).
  The files are encrypted before they leave Tijori, so the cloud provider
  only sees a number of encrypted files and their rounded sizes.

Run the same command again whenever you want to bring the backup up to date.
Only what changed is copied, and objects the vault no longer uses are removed
from the backup:

```console
$ tijori backup /Volumes/BACKUPSTICK
Backed up revision 17 to /Volumes/BACKUPSTICK: 3 objects copied (1.2 MiB), 209 already there, 2 no longer needed and removed.
```

!!! tip "Make it a habit"
    Run `tijori backup` at the end of every session in which you added
    something important. It only takes as long as copying the new files.

### What `backup` takes care of

- **Checks as it copies.** Every object is verified against its hash while it
  is copied. A damaged object in the vault is never copied over a good one in
  the backup.
- **Safe to interrupt.** New objects go first and the pointer to the new
  state last, so if you press ++ctrl+c++, unplug a stick or lose power, the
  backup still opens at its previous state. Running the command again
  finishes the job.
- **Will not overwrite the wrong thing.** It refuses to copy over a different
  Tijori vault, over a `TIJORI` folder it cannot identify, and over a backup
  that has changes your vault does not have (see below).
- **Tells you when the copy is not really a backup.** If the destination is
  on the same drive as the vault, it says so, since that copy would not
  survive losing the drive.

## Restore

If the stick is lost, broken or its vault was deleted, put the backup on a
drive with `restore`:

```console
$ tijori restore /Volumes/BACKUPSTICK /Volumes/NEWSTICK
Password:
Restored revision 17 onto /Volumes/NEWSTICK: 212 objects copied (812.6 MiB).
```

The first path is the backup, the second is the drive to restore onto. The
new drive should be exFAT ([preparing a drive](../getting-started/install.md#preparing-a-drive)).
Its other files are left alone. If the drive still has an older copy of the
same vault, only what differs is copied.

### "This drive is older than a revision this computer has seen"

Every computer remembers the newest revision of each vault it has opened.
After restoring an older backup, Tijori notices that the vault went back in
time and asks what to do:

```text
Warning: this drive is at revision 17, older than revision 19 this computer has seen. Someone may have restored an old copy of the drive.
Continue [r]ead-only, [a]ccept this state as current, or [c]ancel? [r/a/c]
```

When you restored the backup yourself, answer `a`. The warning exists so
that nobody can quietly swap your stick for an older copy (for example to
bring back a file you deleted) without you noticing.

## Looking inside a backup

A backup is a vault, so every command works on it with `--vault`:

```console
$ tijori --vault /Volumes/BACKUPSTICK ls /
$ tijori --vault ~/Backups/Personal get /Taxes/2025.pdf ~/Desktop
$ tijori --vault /Volumes/BACKUPSTICK verify
```

Run `verify` on a backup now and then. It reads everything and catches a
dying drive before you need the backup.

!!! warning "Treat backups as read-only"
    If you change files in the backup itself, it now has changes that the
    vault on your stick does not. The next `tijori backup` refuses to
    overwrite them:

    ```text
    tijori: the destination has changes this vault does not have (revision 18 there, 17 here); copying would lose them. To overwrite it anyway, run again with --force.
    ```

    Copy anything you need out of the backup first, then use `--force`.

## Backups and passwords

A backup holds the keyslots the vault had when the backup was made.

- **After changing a password,** an older backup still opens with the old
  password until you run `tijori backup` again. Do that right away.
- **After a re-key,** the next backup copies everything again, because every
  object was re-encrypted. Once it finishes, the backup only opens with the
  new secrets. A backup that you do not update keeps opening with the old
  ones, so update or delete every copy you have.

## Deleted by accident in Finder or a file manager?

If someone moved the `TIJORI` folder to the Trash with Finder or a desktop
file manager, it is usually still on the stick, in a hidden trash folder,
until the Trash is emptied:

- **macOS:** open the Trash in the Dock while the stick is plugged in,
  select `TIJORI`, and choose **Put Back**.
- **Linux:** open Trash in your file manager and choose **Restore**.

Once it is back at the top of the stick, run `tijori verify`.

## Copying by hand

The vault is just files, so copying the whole `TIJORI` folder (and
`README-TIJORI.txt`) to another place also makes a working backup, as long as
no Tijori is using the vault at that moment. `tijori backup` is still the
better choice: it copies only changes, verifies what it copies, is safe to
interrupt, and refuses to overwrite a backup that has changes of its own.
