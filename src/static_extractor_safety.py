"""Trusted Linux compute-only filter, installed before model Python executes.

Loaded into the generated wrapper, never exposed in the model's namespace.
The kernel boundary remains effective even if Python attribute validation fails.
"""

import ctypes
import errno
import sys


def install_compute_filter() -> None:
    """Deny new files, networking, process creation, and executable mappings."""
    if sys.platform != "linux":
        raise RuntimeError("Static extractor execution requires Linux seccomp")
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int

    class Comparison(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                             ctypes.c_int, ctypes.c_uint,
                                             ctypes.POINTER(Comparison)]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    context = library.seccomp_init(0x00050000 | errno.EPERM)  # SCMP_ACT_ERRNO
    if not context:
        raise RuntimeError("Cannot initialize static extractor seccomp filter")
    allowed = (
        "read", "write", "close", "fstat", "fstat64", "lseek", "pread64", "pwrite64",
        "brk", "munmap", "mremap", "madvise", "futex", "futex_time64",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
        "clock_gettime", "clock_gettime64", "gettimeofday", "time", "getrandom",
        "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
        "exit", "exit_group", "sched_yield", "restart_syscall",
    )
    try:
        for name in (*allowed, "mmap", "mmap2", "mprotect"):
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                continue  # Not a syscall on this native architecture.
            comparison = Comparison(2, 7, 4, 0)  # MASKED_EQ: PROT_EXEC must be zero.
            constrained = name in {"mmap", "mmap2", "mprotect"}
            result = library.seccomp_rule_add_array(
                context, 0x7FFF0000, number, int(constrained),
                ctypes.byref(comparison) if constrained else None,
            )
            if result != 0:
                raise RuntimeError("Cannot constrain syscall %s: %s" % (name, result))
        if library.seccomp_load(context) != 0:
            raise RuntimeError("Cannot activate static extractor seccomp filter")
    finally:
        library.seccomp_release(context)
