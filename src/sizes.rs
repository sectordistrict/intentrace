pub const SIGSET_SIZE: usize = size_of::<nix::sys::signal::SigSet>();
pub const TIMESPEC_SIZE: usize = size_of::<nix::libc::timespec>();
pub const CLONE3_ARGS_SIZE: usize = size_of::<nix::libc::clone_args>();
pub const SIGACTION_SIZE: usize = size_of::<nix::libc::sigaction>();
pub const RLIMIT_SIZE: usize = size_of::<nix::libc::rlimit>();
