# Your first vault

<p class="tj-lead">Five minutes from a blank USB stick to an encrypted vault you can open anywhere.</p>

The examples use a stick that macOS mounts at `/Volumes/KINGSTON`. On Linux
it is usually something like `/media/you/KINGSTON`. Replace the path with
your own.

## 1. Create the vault

```console
$ tijori init /Volumes/KINGSTON --label Personal
Creating a Tijori vault on /Volumes/KINGSTON.
New password:
Repeat the new password:
Tuning the key derivation to take about a second on this computer...
```

The **label** is the vault's name. It appears in `tijori info` and as the
name of the volume when you mount it. It is stored encrypted.

### Choosing a password

Tijori refuses passwords that are easy to guess and tells you why:

```text
This password is too easy to guess. Sequences like abc or 6543 are easy to guess.
  Add another word or two. Uncommon words are better.
  Avoid sequences.
  Try a passphrase of 6 or more random words, like "orbit lantern cactus velvet mango thunder".
```

The easiest strong password to remember is a **passphrase**: six or more
random words. Pick them at random (dice work well), not from a song or a
quote. Your password is the one thing protecting the drive if you lose it, so
this is worth a minute.

### Write down the recovery phrase

Next, Tijori shows a 24-word recovery phrase, **once**:

```text
Your recovery phrase. Write it down and keep it somewhere safe; it is shown only once:

   1. pretty      2. diesel      3. escape      4. few
   5. glance      6. aerobic     7. elite       8. spare
   9. announce   10. truck      11. pepper     12. toe
  13. danger     14. hurdle     15. fitness    16. drop
  17. zoo        18. media      19. trap       20. affair
  21. derive     22. object     23. merge      24. entry

If you lose both your password and this recovery phrase, your files cannot be recovered by anyone.

Type I UNDERSTAND to continue:
```

(These are example words. Yours will be different.)

The phrase opens the vault on its own, without the password. Write it on
paper and keep it somewhere safe and separate from the drive, like you would
a spare house key. Do not store it in a note on the same laptop, and never on
the drive itself.

Type `I UNDERSTAND` and the vault is ready.

## 2. Look at the drive

```text
KINGSTON/
├── README-TIJORI.txt
└── TIJORI/
    ├── vault.header
    ├── vault.header.bak
    ├── vault.root.a
    ├── vault.root.b
    └── objects/
```

`README-TIJORI.txt` is a short plain-text note telling whoever finds the
drive that it holds a Tijori vault. Everything inside `TIJORI` is encrypted.

!!! warning "Do not copy files into the TIJORI folder"
    The `TIJORI` folder is Tijori's encrypted storage, not a place for your
    files. Anything you drop in there yourself is **not** encrypted and Tijori
    will not see it. Add files with `tijori put`, or mount the vault and copy
    into the mounted volume. [Where your files go](../guide/how-it-works.md)
    explains this in detail.

## 3. Add some files

```console
$ tijori put ~/Documents/Taxes /
Password:
Added 2 files (1.4 MiB) and 1 folder to /.
```

`put` takes one or more files or folders from your computer, then the folder
**inside the vault** to put them in. `/` is the top of the vault. Folders are
copied with everything in them.

When exactly one drive with a vault is plugged in, Tijori finds it on its
own. With more than one, add `--vault /Volumes/KINGSTON`.

## 4. See what is inside

```console
$ tijori ls -l /Taxes
Password:
-            2  2026-10-26 18:45  2025.pdf
-            2  2026-10-26 18:45  receipts.zip
```

## 5. Get files back out

```console
$ tijori get /Taxes/2025.pdf ~/Desktop
Password:
Copied 1 file (1.2 MiB) to /Users/you/Desktop.
```

`get` never overwrites anything. If `~/Desktop/2025.pdf` already exists, the
copy is saved as `2025 (1).pdf`.

## 6. Unlock once, run many commands

Typing the password for every command gets old. `tijori shell` unlocks once
and keeps the vault open until you type `exit`:

```console
$ tijori shell
Password:
Vault unlocked. Type `help` for commands, `exit` to lock.
tijori> mkdir /Photos
Created /Photos
tijori> put ~/Pictures/Holiday /Photos
Added 214 files (812.4 MiB) and 1 folder to /Photos.
tijori> exit
Vault locked.
```

## 7. Or just open it as a folder

With [mounting support](install.md#3-optional-mounting-support) installed:

```console
$ tijori mount
Password:
Mounted at /Volumes/Personal. Press Ctrl+C (or eject the volume) to lock.
```

Now `Personal` shows up in Finder like any other drive. Drag files in, open
them, edit them. When you are done, press ++ctrl+c++ in the terminal, eject
`Personal` in Finder, or simply unplug the stick.

## Next steps

- [Make a backup](../guide/backups.md). A USB stick is easy to lose or break.
- [Add a second password or a keyfile](../guide/passwords.md).
- Read [what Tijori protects against](../security/threat-model.md), and what
  it does not.
