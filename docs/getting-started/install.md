# Install

<p class="tj-lead">Tijori is a single command, <code>tijori</code>. There are no prebuilt downloads yet, so for now you build it from source. It takes a few minutes.</p>

## 1. Get Rust

Install [rustup](https://rustup.rs) if you do not have it. The project pins
its Rust version in `rust-toolchain.toml`, and rustup fetches that version
for you the first time you build.

```console
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 2. Build and install `tijori`

```console
$ git clone https://github.com/Mr-Sunglasses/tijori.git
$ cd tijori
$ cargo install --path cli
```

This puts `tijori` in `~/.cargo/bin`, which rustup already added to your
`PATH`. Check it:

```console
$ tijori --version
tijori 0.0.0
```

!!! tip "Just trying it out?"
    `cargo build --release -p tijori-cli` builds the same program into
    `target/release/tijori` without installing anything.

## 3. Optional: mounting support

Everything works without this step. You only need it if you want the vault to
appear as a folder in Finder or your file manager
([Mounting as a folder](../guide/mounting.md)).

=== "macOS"

    1. Install [macFUSE](https://macfuse.github.io) 5 or newer.
    2. Open **System Settings → General → Login Items & Extensions → File
       System Extensions** and switch on **macFUSE**.

    No kernel extension and no change to your Mac's security settings are
    needed: Tijori uses macFUSE's FSKit backend, which runs as a normal
    system extension. You need macOS 15.4 or newer.

=== "Linux"

    Install FUSE 3. Most desktops already have it.

    ```console
    $ sudo apt install fuse3        # Debian, Ubuntu
    $ sudo dnf install fuse3        # Fedora
    $ sudo pacman -S fuse3          # Arch
    ```

## 4. Optional: tab completion

`tijori completions` prints a completion script for your shell.

=== "zsh"

    ```console
    $ mkdir -p ~/.zfunc
    $ tijori completions zsh > ~/.zfunc/_tijori
    ```

    Then make sure your `~/.zshrc` has `fpath+=~/.zfunc` before `compinit`.

=== "bash"

    ```console
    $ mkdir -p ~/.local/share/bash-completion/completions
    $ tijori completions bash > ~/.local/share/bash-completion/completions/tijori
    ```

=== "fish"

    ```console
    $ tijori completions fish > ~/.config/fish/completions/tijori.fish
    ```

## Preparing a drive

Tijori stores its vault on an **exFAT** drive, because exFAT is the one file
system macOS, Linux and Android can all read and write. Most new USB sticks
come formatted as exFAT already. Tijori never formats a drive for you.

If yours is not exFAT, reformat it with your system's own tools:

=== "macOS"

    Open **Disk Utility**, select the stick, click **Erase**, and choose
    **ExFAT** as the format.

=== "Linux"

    Use **GNOME Disks** (or KDE Partition Manager) and pick exFAT. From a
    terminal, `mkfs.exfat` from the `exfatprogs` package does the same.

!!! danger "Formatting erases the whole drive"
    Copy anything you want to keep off the drive first, and double check that
    you picked the right device.

A vault does not need the drive to itself. The vault lives in one folder,
`TIJORI`, so other files on the stick stay where they are and stay usable.

Next: [create your first vault](first-vault.md).
