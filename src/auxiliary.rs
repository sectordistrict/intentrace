pub mod constants {
    pub mod sizes {
        pub const SIGSET_SIZE: usize = size_of::<nix::sys::signal::SigSet>();
        pub const TIMESPEC_SIZE: usize = size_of::<nix::libc::timespec>();
        pub const CLONE3_ARGS_SIZE: usize = size_of::<nix::libc::clone_args>();
        pub const SIGACTION_SIZE: usize = size_of::<nix::libc::sigaction>();
        pub const RLIMIT_SIZE: usize = size_of::<nix::libc::rlimit>();
    }
    pub mod general {
        pub const MAX_KERNEL_ULONG: usize = unsafe { std::mem::transmute::<isize, usize>(-4095) };
        pub const GREEK: [&str; 24] = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigma", "tau", "upsilon", "phi",
            "chi", "psi", "omega",
        ];
        // syscall: arch_prctl
        pub const ARCH_SET_GS: i32 = 0x1001;
        pub const ARCH_SET_FS: i32 = 0x1002;
        pub const ARCH_GET_FS: i32 = 0x1003;
        pub const ARCH_GET_GS: i32 = 0x1004;
        pub const ARCH_GET_CPUID: i32 = 0x1011;
        pub const ARCH_SET_CPUID: i32 = 0x1012;
        // syscall: landlock_add_rule
        pub const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;
    }
}

pub mod kernel_errno {
    // kernel side errnos, not visible to userland
    use nix::libc::c_int;
    pub const ERESTARTSYS: c_int = 512;
    pub const ERESTARTNOINTR: c_int = 513;
    pub const ERESTARTNOHAND: c_int = 514; /* restart if no handler.. */
    pub const ERESTART_RESTARTBLOCK: c_int = 516; /* restart by calling sys_restart_syscall */
    pub const ENOIOCTLCMD: c_int = 515; /* No ioctl command */
    pub const EPROBE_DEFER: c_int = 517; /* Driver requests probe retry */
    pub const EOPENSTALE: c_int = 518; /* open found a stale dentry */
    pub const ENOPARAM: c_int = 519; /* Parameter not supported */
    /* Defined for the NFSv3 protocol */
    pub const EBADHANDLE: c_int = 521; /* Illegal NFS file handle */
    pub const ENOTSYNC: c_int = 522; /* Update synchronization mismatch */
    pub const EBADCOOKIE: c_int = 523; /* Cookie is stale */
    pub const ENOTSUPP: c_int = 524; /* Operation is not supported */
    pub const ETOOSMALL: c_int = 525; /* Buffer or request is too small */
    pub const ESERVERFAULT: c_int = 526; /* An untranslatable error occurred */
    pub const EBADTYPE: c_int = 527; /* Type not supported by server */
    pub const EJUKEBOX: c_int = 528; /* Request initiated, but will not complete before timeout */
    pub const EIOCBQUEUED: c_int = 529; /* iocb queued, will get completion event */
    pub const ERECALLCONFLICT: c_int = 530; /* conflict with recalled state */
    pub const ENOGRACE: c_int = 531; /* NFS file lock reclaim refused */

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i32)]
    pub enum KernelErrno {
        UnknownErrno = 0,
        ERESTARTSYS = ERESTARTSYS,
        ERESTARTNOINTR = ERESTARTNOINTR,
        ERESTARTNOHAND = ERESTARTNOHAND,
        ERESTART_RESTARTBLOCK = ERESTART_RESTARTBLOCK,
        ENOIOCTLCMD = ENOIOCTLCMD,
        EPROBE_DEFER = EPROBE_DEFER,
        EOPENSTALE = EOPENSTALE,
        ENOPARAM = ENOPARAM,
        EBADHANDLE = EBADHANDLE,
        ENOTSYNC = ENOTSYNC,
        EBADCOOKIE = EBADCOOKIE,
        ENOTSUPP = ENOTSUPP,
        ETOOSMALL = ETOOSMALL,
        ESERVERFAULT = ESERVERFAULT,
        EBADTYPE = EBADTYPE,
        EJUKEBOX = EJUKEBOX,
        EIOCBQUEUED = EIOCBQUEUED,
        ERECALLCONFLICT = ERECALLCONFLICT,
        ENOGRACE = ENOGRACE,
    }

    impl std::fmt::Display for KernelErrno {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{:?}: {}", self, self.desc())
        }
    }

    impl KernelErrno {
        pub fn from_i32(errno: i32) -> KernelErrno {
            match errno {
                ERESTARTSYS => KernelErrno::ERESTARTSYS,
                ERESTARTNOINTR => KernelErrno::ERESTARTNOINTR,
                ERESTARTNOHAND => KernelErrno::ERESTARTNOHAND,
                ERESTART_RESTARTBLOCK => KernelErrno::ERESTART_RESTARTBLOCK,
                ENOIOCTLCMD => KernelErrno::ENOIOCTLCMD,
                EPROBE_DEFER => KernelErrno::EPROBE_DEFER,
                EOPENSTALE => KernelErrno::EOPENSTALE,
                ENOPARAM => KernelErrno::ENOPARAM,
                EBADHANDLE => KernelErrno::EBADHANDLE,
                ENOTSYNC => KernelErrno::ENOTSYNC,
                EBADCOOKIE => KernelErrno::EBADCOOKIE,
                ENOTSUPP => KernelErrno::ENOTSUPP,
                ETOOSMALL => KernelErrno::ETOOSMALL,
                ESERVERFAULT => KernelErrno::ESERVERFAULT,
                EBADTYPE => KernelErrno::EBADTYPE,
                EJUKEBOX => KernelErrno::EJUKEBOX,
                EIOCBQUEUED => KernelErrno::EIOCBQUEUED,
                ERECALLCONFLICT => KernelErrno::ERECALLCONFLICT,
                ENOGRACE => KernelErrno::ENOGRACE,
                _ => KernelErrno::UnknownErrno,
            }
        }

        pub fn desc(&self) -> &'static str {
            // TODO!
            // these messages dont communicate EINTR conversion semantics
            match self {
                KernelErrno::UnknownErrno => "Unknown errno",
                // interrupted syscalls

                // ERESTARTSYS
                // always restart
                // except if a handler was registered without SA_RESTART, then convert to EINTR
                KernelErrno::ERESTARTSYS => {
                    "Interrupted by a signal, restart if it has no handler or a SA_RESTART handler exists"
                }

                // ERESTARTNOINTR
                // always restart
                KernelErrno::ERESTARTNOINTR => "Interrupted by a signal, restart always",

                // ERESTARTNOHAND
                // always restart
                // except if a handler was registered, then convert to EINTR
                KernelErrno::ERESTARTNOHAND => {
                    "Interrupted by a signal, restart if it has no handler"
                }

                // ERESTART_RESTARTBLOCK
                // should be restarted using a custom function.
                KernelErrno::ERESTART_RESTARTBLOCK => {
                    "Interrupted by a signal, restart by calling restart_syscall"
                }
                //
                //
                //
                //
                KernelErrno::ENOIOCTLCMD => "No ioctl command",
                // if a driver depends on resources that are not yet available
                KernelErrno::EPROBE_DEFER => "Driver requests probe retry",
                KernelErrno::EOPENSTALE => "Open found a stale dentry",
                KernelErrno::ENOPARAM => "Parameter not supported",
                KernelErrno::EBADHANDLE => "Illegal NFS file handle",
                KernelErrno::ENOTSYNC => "Update synchronization mismatch",
                KernelErrno::EBADCOOKIE => "Cookie is stale",
                KernelErrno::ENOTSUPP => "Operation is not supported",
                KernelErrno::ETOOSMALL => "Buffer or request is too small",
                KernelErrno::ESERVERFAULT => "An untranslatable error occurred",
                KernelErrno::EBADTYPE => "Type not supported by server",
                KernelErrno::EJUKEBOX => "Request initiated, but will not complete before timeout",
                KernelErrno::EIOCBQUEUED => "iocb queued, will get completion event",
                KernelErrno::ERECALLCONFLICT => "conflict with recalled state",
                KernelErrno::ENOGRACE => "NFS file lock reclaim refused",
            }
        }
    }
}
