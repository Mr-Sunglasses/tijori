/*
 * Tijori: glue between macFUSE's libfuse 3 high-level API and the Rust
 * file system in macos.rs. All libfuse structures stay on this side, so
 * their layout always matches the installed headers; Rust sees only the
 * simple structs below. Every callback receives the Rust file system
 * through fuse_get_context()->private_data.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <dlfcn.h>
#include <errno.h>
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Must match TjAttr / TjStatfs in macos.rs. */
struct tj_attr {
    uint32_t kind; /* 1 file, 2 directory */
    uint32_t perm;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
};

struct tj_statfs {
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t bsize;
};

typedef int (*tj_add_fn)(void *ctx, const char *name, uint32_t kind);

/* Implemented in Rust. They return 0 or a positive errno; read and write
 * return a byte count or a negative errno. */
extern int tj_rs_getattr(void *fs, const char *path, struct tj_attr *out);
extern int tj_rs_readdir(void *fs, const char *path, void *ctx, tj_add_fn add);
extern int tj_rs_open(void *fs, const char *path, int flags, uint64_t *fh);
extern int tj_rs_create(void *fs, const char *path, uint32_t mode, uint64_t *fh);
extern long tj_rs_read(void *fs, uint64_t fh, char *buf, size_t size, int64_t off);
extern long tj_rs_write(void *fs, uint64_t fh, const char *buf, size_t size, int64_t off);
extern int tj_rs_truncate(void *fs, const char *path, int64_t size, int has_fh, uint64_t fh);
extern int tj_rs_flush(void *fs, uint64_t fh);
extern int tj_rs_release(void *fs, uint64_t fh);
extern int tj_rs_mkdir(void *fs, const char *path);
extern int tj_rs_unlink(void *fs, const char *path);
extern int tj_rs_rmdir(void *fs, const char *path);
extern int tj_rs_rename(void *fs, const char *from, const char *to, int exclusive);
extern int tj_rs_utimens(void *fs, const char *path, int64_t sec, int64_t nsec);
extern int tj_rs_chmod(void *fs, const char *path, uint32_t mode);
extern int tj_rs_statfs(void *fs, struct tj_statfs *out);

/* libfuse3 is loaded at run time, so Tijori starts (and can still open
 * vaults in private mode) on Macs without macFUSE. */
static struct {
    __typeof__(_fuse_new_31) *new_31;
    __typeof__(fuse_mount) *mount;
    __typeof__(fuse_loop) *loop;
    __typeof__(fuse_exit) *exit;
    __typeof__(fuse_unmount) *unmount;
    __typeof__(fuse_destroy) *destroy;
    __typeof__(fuse_get_context) *get_context;
} lib;

static const char *const lib_paths[] = {
    "/usr/local/lib/libfuse3.4.dylib",
    "/usr/local/lib/libfuse3.dylib",
    NULL,
};

static void *fs_ptr(void) { return lib.get_context()->private_data; }

static void fill_stat(const struct tj_attr *a, struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode = (a->kind == 2 ? S_IFDIR : S_IFREG) | (mode_t)a->perm;
    st->st_nlink = a->kind == 2 ? 2 : 1;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_size = (off_t)a->size;
    st->st_blocks = (blkcnt_t)((a->size + 511) / 512);
    st->st_blksize = 65536;
    struct timespec t = {.tv_sec = a->mtime_sec, .tv_nsec = a->mtime_nsec};
    st->st_mtimespec = t;
    st->st_atimespec = t;
    st->st_ctimespec = t;
    st->st_birthtimespec = t;
}

static int sh_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    struct tj_attr a;
    int r = tj_rs_getattr(fs_ptr(), path, &a);
    if (r != 0) return -r;
    fill_stat(&a, st);
    return 0;
}

struct dir_ctx {
    void *buf;
    fuse_fill_dir_t filler;
};

static int add_entry(void *ctx, const char *name, uint32_t kind) {
    (void)kind;
    struct dir_ctx *c = ctx;
    return c->filler(c->buf, name, NULL, 0, (enum fuse_fill_dir_flags)0);
}

static int sh_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
                      struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)off;
    (void)fi;
    (void)flags;
    filler(buf, ".", NULL, 0, (enum fuse_fill_dir_flags)0);
    filler(buf, "..", NULL, 0, (enum fuse_fill_dir_flags)0);
    struct dir_ctx c = {buf, filler};
    return -tj_rs_readdir(fs_ptr(), path, &c, add_entry);
}

static int sh_open(const char *path, struct fuse_file_info *fi) {
    uint64_t fh = 0;
    int r = tj_rs_open(fs_ptr(), path, fi->flags, &fh);
    if (r != 0) return -r;
    fi->fh = fh;
    return 0;
}

static int sh_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    uint64_t fh = 0;
    int r = tj_rs_create(fs_ptr(), path, (uint32_t)mode, &fh);
    if (r != 0) return -r;
    fi->fh = fh;
    return 0;
}

static int sh_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    return (int)tj_rs_read(fs_ptr(), fi->fh, buf, size, (int64_t)off);
}

static int sh_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    return (int)tj_rs_write(fs_ptr(), fi->fh, buf, size, (int64_t)off);
}

static int sh_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    return -tj_rs_truncate(fs_ptr(), path, (int64_t)size, fi != NULL, fi ? fi->fh : 0);
}

static int sh_flush(const char *path, struct fuse_file_info *fi) {
    (void)path;
    return -tj_rs_flush(fs_ptr(), fi->fh);
}

static int sh_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    return -tj_rs_release(fs_ptr(), fi->fh);
}

static int sh_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    (void)path;
    (void)datasync;
    return -tj_rs_flush(fs_ptr(), fi->fh);
}

static int sh_mkdir(const char *path, mode_t mode) {
    (void)mode;
    return -tj_rs_mkdir(fs_ptr(), path);
}

static int sh_unlink(const char *path) { return -tj_rs_unlink(fs_ptr(), path); }

static int sh_rmdir(const char *path) { return -tj_rs_rmdir(fs_ptr(), path); }

static int sh_rename(const char *from, const char *to, unsigned int flags) {
    /* Only "fail if the target exists" is supported; swapping is not. */
#ifdef RENAME_EXCL
    const unsigned int excl = RENAME_EXCL | 1u /* RENAME_NOREPLACE */;
#else
    const unsigned int excl = 1u;
#endif
    if (flags & ~excl) return -EINVAL;
    return -tj_rs_rename(fs_ptr(), from, to, (flags & excl) != 0);
}

static int sh_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    (void)fi;
    if (tv == NULL || tv[1].tv_nsec == UTIME_NOW) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        return -tj_rs_utimens(fs_ptr(), path, now.tv_sec, now.tv_nsec);
    }
    if (tv[1].tv_nsec == UTIME_OMIT) return 0;
    return -tj_rs_utimens(fs_ptr(), path, tv[1].tv_sec, tv[1].tv_nsec);
}

static int sh_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)fi;
    return -tj_rs_chmod(fs_ptr(), path, (uint32_t)mode);
}

static int sh_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void)path;
    (void)uid;
    (void)gid;
    (void)fi;
    /* Ownership is not stored (spec §11); accept and ignore. */
    return 0;
}

/* Extended attributes are not stored (spec §11). Setting one succeeds and is
 * discarded, so copies from Finder and cp do not fail, and metadata such as
 * quarantine or provenance tags never enters the vault. */
static int sh_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    (void)path;
    (void)name;
    (void)value;
    (void)size;
    (void)flags;
    return 0;
}

static int sh_getxattr(const char *path, const char *name, char *value, size_t size) {
    (void)path;
    (void)name;
    (void)value;
    (void)size;
    return -ENOATTR;
}

static int sh_listxattr(const char *path, char *list, size_t size) {
    (void)path;
    (void)list;
    (void)size;
    return 0;
}

static int sh_removexattr(const char *path, const char *name) {
    (void)path;
    (void)name;
    return -ENOATTR;
}

static int sh_statfs(const char *path, struct statvfs *st) {
    (void)path;
    struct tj_statfs s;
    int r = tj_rs_statfs(fs_ptr(), &s);
    if (r != 0) return -r;
    memset(st, 0, sizeof(*st));
    st->f_bsize = (unsigned long)s.bsize;
    st->f_frsize = (unsigned long)s.bsize;
    st->f_blocks = (fsblkcnt_t)s.blocks;
    st->f_bfree = (fsblkcnt_t)s.bfree;
    st->f_bavail = (fsblkcnt_t)s.bavail;
    st->f_namemax = 255;
    return 0;
}

static const struct fuse_operations tj_ops = {
    .getattr = sh_getattr,
    .readdir = sh_readdir,
    .open = sh_open,
    .create = sh_create,
    .read = sh_read,
    .write = sh_write,
    .truncate = sh_truncate,
    .flush = sh_flush,
    .release = sh_release,
    .fsync = sh_fsync,
    .mkdir = sh_mkdir,
    .unlink = sh_unlink,
    .rmdir = sh_rmdir,
    .rename = sh_rename,
    .utimens = sh_utimens,
    .chmod = sh_chmod,
    .chown = sh_chown,
    .statfs = sh_statfs,
    .setxattr = sh_setxattr,
    .getxattr = sh_getxattr,
    .listxattr = sh_listxattr,
    .removexattr = sh_removexattr,
};

/* Loads libfuse3 once; returns 1 when every function was found. */
int tj_fuse_available(void) {
    static int loaded = -1;
    if (loaded >= 0) return loaded;
    void *h = NULL;
    for (int i = 0; h == NULL && lib_paths[i] != NULL; i++) h = dlopen(lib_paths[i], RTLD_NOW | RTLD_LOCAL);
    if (h != NULL) {
        lib.new_31 = dlsym(h, "_fuse_new_31");
        lib.mount = dlsym(h, "fuse_mount");
        lib.loop = dlsym(h, "fuse_loop");
        lib.exit = dlsym(h, "fuse_exit");
        lib.unmount = dlsym(h, "fuse_unmount");
        lib.destroy = dlsym(h, "fuse_destroy");
        lib.get_context = dlsym(h, "fuse_get_context");
    }
    loaded = h != NULL && lib.new_31 && lib.mount && lib.loop && lib.exit && lib.unmount && lib.destroy &&
             lib.get_context;
    return loaded;
}

/* Creates and mounts the file system; NULL on failure. `options` is a
 * comma-separated -o list. */
void *tj_mount(const char *mountpoint, const char *options, void *fs) {
    if (!tj_fuse_available()) return NULL;
    char *argv[] = {"tijori", "-o", (char *)options, NULL};
    struct fuse_args args = FUSE_ARGS_INIT(3, argv);
    /* What the inline fuse_new() does, through the loaded symbol. */
    struct libfuse_version version = {
        .major = FUSE_MAJOR_VERSION,
        .minor = FUSE_MINOR_VERSION,
        .hotfix = FUSE_HOTFIX_VERSION,
        .darwin_extensions_enabled = FUSE_DARWIN_ENABLE_EXTENSIONS,
        .padding = 0,
    };
    struct fuse *f = lib.new_31(&args, &tj_ops, sizeof(tj_ops), &version, fs);
    if (f == NULL) return NULL;
    if (lib.mount(f, mountpoint) != 0) {
        lib.destroy(f);
        return NULL;
    }
    return f;
}

/* Serves requests until the file system is unmounted or tj_exit is called. */
int tj_loop(void *f) { return lib.loop((struct fuse *)f); }

void tj_exit(void *f) { lib.exit((struct fuse *)f); }

void tj_unmount_destroy(void *f) {
    lib.unmount((struct fuse *)f);
    lib.destroy((struct fuse *)f);
}
