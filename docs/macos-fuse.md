# macOS FUSE spike (Milestone 4, task 1)

**Question:** can `fuser` run on FUSE-T (no kernel extension), directly or
through FUSE-T's libfuse-compatible library? If not, what should Tijori use
to mount vaults on macOS?

**Status:** decided and implemented: macFUSE 5 with the FSKit backend, through
libfuse 3's high-level API (see "Outcome" at the end).

## How `fuser` mounts on macOS

From the `fuser` 0.18.0 source (`build.rs`, `src/mnt/fuse2.rs`):

- On macOS it always links libfuse 2 through pkg-config name `fuse` (the
  macFUSE 4.x layout), unless built with `macos-no-mount`.
- It calls `fuse_mount_compat25()` to get a file descriptor, then reads and
  writes raw FUSE kernel-protocol messages on it itself, one message per
  `read`, exactly as `/dev/macfuse` delivers them.
- Its README lists macOS as "untested" and documents macFUSE only.

So `fuser` needs a backend that hands out a FUSE device file descriptor.

## Options

| | macFUSE, kernel backend | macFUSE 5, FSKit backend | FUSE-T (NFS / SMB / FSKit) |
|---|---|---|---|
| Kernel extension | **Yes**. On Apple silicon the user must boot into Recovery, choose "Reduced Security", allow the kext, reboot | No (user space, `-o backend=fskit`) | No |
| macOS | All current | Local volumes on 15.4+, more on 26+ | 12+ (FSKit backend 26+) |
| Works with `fuser` today | **Yes** (its documented setup) | **No**: FSKit gives no device fd; libfuse talks over an XPC channel (`MFMount.framework`) | Unknown, unlikely: `libfuse-t` is a different pkg-config name, and no raw-fd support is documented |
| What we would build on | `fuser` as-is | libfuse 3 low-level API through FFI (`unsafe` with `// SAFETY:` comments in `mount/`) | libfuse-t API through FFI |
| Licence | BSD-style + LGPL libfuse. Bundling with **commercial** software needs permission; Tijori is free, and users install it themselves | Same | Custom, **not open source**. Free for non-commercial use with notice; commercial bundling needs a licence. Bundled libfuse is LGPL |
| Known limits | None relevant | Mount points must be under `/Volumes`; notifications and most kernel mount options not supported yet; slower I/O | NFS backend exposes a **local TCP port without authentication**; another local user may be able to reach the mounted vault. Terminal access needs "Network Volumes" permission. No separate atime/mtime; locks bypass FUSE |

## Assessment against the plan

- Plan §1 wants Mount (hardened, current user only) as the default access mode
  for **non-technical users**. The macFUSE kernel backend fails that test on
  Apple silicon: Recovery-mode security changes are not something we can ask of
  most users.
- FUSE-T's default NFS backend conflicts with Milestone 4 task 3 ("mount only
  for the current user"), because the NFS server is reachable from localhost.
  This needs verifying before it could be considered. Its licence is also not
  open source, which sits awkwardly with a fully free project, even though
  non-commercial use is allowed.
- macFUSE's FSKit backend is the direction macOS is heading (Apple's own
  user-space file system API), needs no kernel extension, and has an open
  licence for a free app. The cost is that `fuser` cannot drive it. On macOS
  we would bind libfuse 3's low-level API instead (a thin FFI layer in
  `mount/`), and keep `fuser`'s pure-Rust mount on Linux.

## Recommendation

1. **Linux:** `fuser` with its pure-Rust mount (no libfuse needed at build
   time; `fusermount3` at run time).
2. **macOS:** macFUSE **5.x with the FSKit backend**, through a small libfuse
   3 low-level FFI layer in `tijori-mount`. Users install macFUSE themselves
   (and enable its file system extension if macOS asks); no kernel extension.
   Mount points under `/Volumes`, which also suits Finder.
3. Keep **Private mode** (no mount) as the fallback whenever macFUSE is
   missing or too old, so the app always works.
4. Revisit FUSE-T only if its local-port exposure turns out to be locked down,
   and only as an optional backend, because of its licence.

## Open points to verify on a real machine (after your go-ahead)

- Whether macFUSE's FSKit extension needs a one-time approval in System
  Settings → General → Login Items & Extensions → File System Extensions.
- Whether `mdutil -i off`, `tmutil addexclusion` and `.metadata_never_index`
  behave the same on FSKit volumes as on kernel ones (Spotlight must find
  nothing; Milestone 4 acceptance).
- Performance of the FSKit backend for large files.

## Sources

- `fuser` 0.18.0 source: `build.rs`, `src/mnt/fuse2.rs`, `README.md`.
- FUSE-T: <https://www.fuse-t.org/>, <https://github.com/macos-fuse-t/fuse-t>,
  its wiki and `License.txt`.
- macFUSE licence: <https://github.com/macfuse/macfuse/blob/master/LICENSE.txt>;
  backends: <https://github.com/macfuse/macfuse/wiki/FUSE-Backends>;
  5.1.0 notes: <https://macfuse.github.io/2025/10/30/macfuse-5.1.0.html>.
- FSKit has no device fd (XPC channel instead):
  <https://github.com/Netatalk/netatalk-client/issues/386>.

## Outcome (2026-10-26)

The user chose the FSKit recommendation. Implemented in `mount/src/macos.rs`
and `mount/src/macos_shim.c`, tested on macOS 27.0.1 with macFUSE 5.4.0:

- One-time setup on the user's side: install macFUSE, open `macfuse.app`
  once, and enable it under System Settings → General → Login Items &
  Extensions → File System Extensions. Without that switch, macOS refuses
  with "File system extension not enabled"; Tijori says how to fix it.
- No kernel extension and no Recovery-mode changes were needed.
- Behaviour differences from the kernel backend that the code handles:
  `fuse_mount` returns before the mount exists; unmounting needs the FUSE
  loop to keep serving; `mdutil`/`tmutil` exit codes are unreliable, so
  their resulting state is checked instead.
- Spotlight found nothing inside a mounted vault; Time Machine reports it
  excluded.

**Users who do not install macFUSE** can still use everything except "show
as a folder in Finder", through Private mode in the app. Proposed for v1.1:
ship our own FSKit extension inside Tijori.app so Mount needs no third-party
install (it still needs the one-time switch, and an Apple Developer ID to
sign it).
