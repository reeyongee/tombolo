//! Arch-exact syscall resolution (syscall-typing fix).
//!
//! `auditd-log-parser` classified execve with a flat set
//! `{59, 322, 11, 358, 221, 281}` that unions x86-64, i386 and aarch64 numbers.
//! On x86-64 that set wrongly claims 11 (`munmap`) and 221 (`fadvise64`), so a
//! key-tagged non-exec syscall could be typed `exec` — and once such an event
//! reaches the taint engine it injects a phantom process edge into the tree.
//!
//! The table below is generated from the kernel uapi headers
//! (`tools/gen_syscalls.py`) and contains the *complete* syscall surface for
//! each architecture: 375 (x86-64), 452 (i386), 330 (aarch64). An earlier
//! hand-written revision held 55 entries and silently dropped everything else —
//! which starved the taint engine of the very events it needs.

use crate::syscall_table as table;

/// Audit architecture tokens (`arch=` in an auditd SYSCALL record).
pub const ARCH_X86_64: &str = "c000003e";
pub const ARCH_I386: &str = "40000003";
pub const ARCH_AARCH64: &str = "c00000b7";
pub const ARCH_ARM: &str = "40000028";

/// What an event *is*, for the engine's purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysKind {
    /// execve / execveat
    Exec,
    /// Path-bearing syscall that can read or write file content.
    File,
    /// Path-bearing metadata syscall (stat, access, readlink…). High volume,
    /// low signal: kept only when keyed or on a sensitive path.
    FileMeta,
    NetConnect,
    NetAccept,
    /// Data leaving the process (sendto/sendmsg/sendmmsg).
    NetSend,
    /// Data arriving (recvfrom/recvmsg/recvmmsg).
    NetRecv,
    /// Socket setup (socket, bind, listen, setsockopt…).
    Socket,
    Other,
}

impl SysKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SysKind::Exec => "exec",
            SysKind::File => "file",
            SysKind::FileMeta => "file-meta",
            SysKind::NetConnect => "net-connect",
            SysKind::NetAccept => "net-accept",
            SysKind::NetSend => "net-send",
            SysKind::NetRecv => "net-recv",
            SysKind::Socket => "socket",
            SysKind::Other => "other",
        }
    }
}

fn arch_table(arch: &str) -> Option<&'static [(u32, &'static str)]> {
    match arch {
        ARCH_X86_64 => Some(table::X86_64),
        ARCH_I386 => Some(table::I386),
        ARCH_AARCH64 | ARCH_ARM => Some(table::AARCH64),
        _ => None,
    }
}

/// Human syscall name, arch-exact.
pub fn name(arch: &str, nr: &str) -> Option<&'static str> {
    let n: u32 = nr.parse().ok()?;
    let t = arch_table(arch)?;
    t.binary_search_by_key(&n, |(num, _)| *num)
        .ok()
        .map(|i| t[i].1)
}

/// Classify by name. Separated from the table so it stays readable and
/// testable, and so new syscalls inherit a sane kind automatically.
pub fn classify_name(name: &str) -> SysKind {
    match name {
        "execve" | "execveat" => SysKind::Exec,

        // --- content-bearing file operations -------------------------------
        // These carry a PATH record with a real target, so taint can follow them.
        "open" | "openat" | "openat2" | "creat" | "close" => SysKind::File,
        "read" | "pread64" | "readv" | "preadv" | "preadv2" => SysKind::File,
        "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2" => SysKind::File,
        "truncate" | "ftruncate" | "unlink" | "unlinkat" | "rename" | "renameat"
        | "renameat2" => SysKind::File,
        "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "lchown" | "fchownat" => {
            SysKind::File
        }
        "symlink" | "symlinkat" | "link" | "linkat" | "mkdir" | "mkdirat" | "rmdir" => {
            SysKind::File
        }
        "mknod" | "mknodat" | "setxattr" | "lsetxattr" | "fsetxattr" | "removexattr"
        | "lremovexattr" | "fremovexattr" => SysKind::File,
        "copy_file_range" | "sendfile" | "splice" | "tee" | "vmsplice" | "fallocate" => {
            SysKind::File
        }
        "mmap" | "mmap2" | "msync" | "mremap" | "shmget" | "shmat" => SysKind::File,

        // --- metadata: noisy, low signal -----------------------------------
        "stat" | "lstat" | "fstat" | "fstatat" | "newfstatat" | "statx" | "statfs"
        | "fstatfs" => SysKind::FileMeta,
        "access" | "faccessat" | "faccessat2" | "readlink" | "readlinkat" => SysKind::FileMeta,
        "getdents" | "getdents64" | "getcwd" | "chdir" | "fchdir" => SysKind::FileMeta,
        "lseek" | "dup" | "dup2" | "dup3" | "fcntl" | "fcntl64" | "ioctl" => SysKind::FileMeta,
        "flock" | "fsync" | "fdatasync" | "sync" | "syncfs" | "umask" | "utimensat"
        | "utimes" | "futimesat" => SysKind::FileMeta,

        // --- network --------------------------------------------------------
        "connect" => SysKind::NetConnect,
        "accept" | "accept4" => SysKind::NetAccept,
        "sendto" | "sendmsg" | "sendmmsg" => SysKind::NetSend,
        "recvfrom" | "recvmsg" | "recvmmsg" => SysKind::NetRecv,
        "socket" | "socketpair" | "bind" | "listen" | "shutdown" | "getsockname"
        | "getpeername" | "setsockopt" | "getsockopt" => SysKind::Socket,

        _ => SysKind::Other,
    }
}

/// Engine event kind, arch-exact. `None` when the architecture is unknown.
pub fn classify(arch: &str, nr: &str) -> Option<SysKind> {
    Some(classify_name(name(arch, nr)?))
}

/// True only when `nr` is an execve-family syscall *on this architecture*.
pub fn is_execve(arch: &str, nr: &str) -> bool {
    matches!(classify(arch, nr), Some(SysKind::Exec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_execve_is_exec() {
        assert!(is_execve(ARCH_X86_64, "59"));
        assert!(is_execve(ARCH_X86_64, "322"));
    }

    #[test]
    fn x86_64_munmap_is_not_execve() {
        // the exact bug the flat set had: 11 is munmap on x86-64
        assert!(!is_execve(ARCH_X86_64, "11"));
        assert_eq!(classify(ARCH_X86_64, "11"), Some(SysKind::Other));
        assert_eq!(name(ARCH_X86_64, "11"), Some("munmap"));
    }

    #[test]
    fn x86_64_fadvise_is_not_execve() {
        assert!(!is_execve(ARCH_X86_64, "221"));
        assert_eq!(name(ARCH_X86_64, "221"), Some("fadvise64"));
    }

    #[test]
    fn i386_and_aarch64_execve_are_exec() {
        assert!(is_execve(ARCH_I386, "11"));
        assert!(is_execve(ARCH_AARCH64, "221"));
        assert!(is_execve(ARCH_ARM, "221"));
    }

    #[test]
    fn unknown_arch_never_claims_execve() {
        assert!(!is_execve("deadbeef", "59"));
        assert_eq!(classify("deadbeef", "59"), None);
    }

    /// The old hand-written table held 55 entries and dropped most real
    /// activity. Assert the generated tables are actually complete.
    #[test]
    fn tables_are_complete() {
        assert!(table::X86_64.len() >= 300, "x86_64 table too small: {}", table::X86_64.len());
        assert!(table::I386.len() >= 300, "i386 table too small: {}", table::I386.len());
        assert!(table::AARCH64.len() >= 250, "aarch64 table too small: {}", table::AARCH64.len());
    }

    /// Syscalls that previously fell off the end of the hand-written table and
    /// were silently discarded.
    #[test]
    fn previously_missing_syscalls_resolve() {
        for (arch, nr, want) in [
            (ARCH_X86_64, "20", "writev"),
            (ARCH_X86_64, "44", "sendto"),
            (ARCH_X86_64, "46", "sendmsg"),
            (ARCH_X86_64, "45", "recvfrom"),
            (ARCH_X86_64, "90", "chmod"),
            (ARCH_X86_64, "88", "symlink"),
            (ARCH_X86_64, "83", "mkdir"),
            (ARCH_X86_64, "188", "setxattr"),
            (ARCH_X86_64, "9", "mmap"),
            (ARCH_X86_64, "4", "stat"),
        ] {
            assert_eq!(name(arch, nr), Some(want), "arch={arch} nr={nr}");
        }
    }

    #[test]
    fn kinds_are_sensible() {
        assert_eq!(classify_name("writev"), SysKind::File);
        assert_eq!(classify_name("sendto"), SysKind::NetSend);
        assert_eq!(classify_name("accept4"), SysKind::NetAccept);
        assert_eq!(classify_name("stat"), SysKind::FileMeta);
        assert_eq!(classify_name("bind"), SysKind::Socket);
        assert_eq!(classify_name("munmap"), SysKind::Other);
    }

    /// Every table must be sorted, or `binary_search` silently misses.
    #[test]
    fn tables_are_sorted() {
        for t in [table::X86_64, table::I386, table::AARCH64] {
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "table not sorted");
        }
    }
}
