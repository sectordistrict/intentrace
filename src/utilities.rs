use crate::{
    syscall_annotations_map::initialize_annotations_map,
    syscall_categories::initialize_categories_map,
    syscall_skeleton_map::initialize_skeletons_map,
    types::{Category, SysAnnotations, Syscall_Shape},
};
use colored::{ColoredString, Colorize, CustomColor};
use nix::{errno::Errno, libc::__errno_location, unistd::Pid};
use procfs::process::{MMapPath, MemoryMap};
use std::{
    borrow::BorrowMut,
    cell::{Cell, LazyCell, OnceCell, RefCell},
    collections::HashMap,
    io::{stdout, BufWriter, Stdout, Write},
    mem::MaybeUninit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex, OnceLock,
    },
    time::Duration,
};
use syscalls::Sysno;

pub static mut UNSUPPORTED: Vec<&'static str> = Vec::new();

thread_local! {
    // CLI_ARGS
    //
    //
    //
    // TODO! Time blocks feature
    // pub static TIME_BLOCKS: Cell<bool> = Cell::new(false);
    pub static FOLLOW_FORKS: AtomicBool = AtomicBool::new(false);
    pub static STRING_LIMIT: Cell<usize> = Cell::new(36);
    pub static FAILED_ONLY: Cell<bool> = Cell::new(false);
    pub static QUIET: Cell<bool> = Cell::new(false);
    pub static ANNOT: Cell<bool> = Cell::new(false);
    pub static ATTACH_PID: Cell<Option<usize>> = Cell::new(None);

    // COLORS
    //
    //
    pub static  PAGES_COLOR: OnceCell<CustomColor> = OnceCell::new();
    pub static  GENERAL_TEXT_COLOR: OnceCell<CustomColor> = OnceCell::new();
    pub static  PID_BACKGROUND_COLOR: OnceCell<CustomColor> = OnceCell::new( );
    pub static  PID_NUMBER_COLOR: OnceCell<CustomColor> = OnceCell::new();
    pub static  EXITED_BACKGROUND_COLOR: OnceCell<CustomColor> = OnceCell::new( );
    pub static  OUR_YELLOW: OnceCell<CustomColor> = OnceCell::new();
    pub static  CONTINUED_COLOR: OnceCell<CustomColor> = OnceCell::new();
    pub static  STOPPED_COLOR: OnceCell<CustomColor> = OnceCell::new();


    //
    //
    //
    pub static PRE_CALL_PROGRAM_BREAK_POINT: Cell<usize> = Cell::new(0);
    pub static PAGE_SIZE: Cell<usize> = Cell::new(page_size::get());
    pub static REGISTERS: Cell<[u64;6]> = Cell::new([0;6]);

}
pub static SUMMARY: AtomicBool = AtomicBool::new(false);
pub static HALT_TRACING: AtomicBool = AtomicBool::new(false);

static WRITER_LAZY: LazyLock<Mutex<BufWriter<Stdout>>> = LazyLock::new(|| {
    let stdout = stdout();
    Mutex::new(BufWriter::new(stdout))
});
pub static TABLE: LazyLock<Mutex<HashMap<Sysno, (usize, Duration)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub static TABLE_FOLLOW_FORKS: LazyLock<Mutex<HashMap<Sysno, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static SYSANNOT_MAP: LazyLock<HashMap<Sysno, SysAnnotations>> =
    LazyLock::new(|| initialize_annotations_map());
pub static SYSKELETON_MAP: LazyLock<HashMap<Sysno, Syscall_Shape>> =
    LazyLock::new(|| initialize_skeletons_map());
pub static SYSCATEGORIES_MAP: LazyLock<HashMap<Sysno, Category>> =
    LazyLock::new(|| initialize_categories_map());

pub fn setup(args: IntentraceArgs) -> Vec<String> {
    if args.summary {
        SUMMARY.store(true, Ordering::SeqCst);
    }
    if args.follow_forks {
        FOLLOW_FORKS.with(|ff| ff.store(true, Ordering::SeqCst));
    }
    if args.mute_stdout {
        QUIET.set(true);
    }
    if args.pid.is_some() {
        ATTACH_PID.set(args.pid);
    }
    if args.failed_only {
        FAILED_ONLY.set(true);
    }
    if let Some(Binary::Command(binary_and_args)) = args.binary {
        binary_and_args
    } else {
        vec![]
    }
}

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "intentrace is a strace for everyone.",
    version,
    allow_external_subcommands = true
)]
pub struct IntentraceArgs {
    /// provide a summary table at the end of tracing
    #[arg(short = 'c', long)]
    pub summary: bool,

    /// attach to an already running proceess
    #[arg(short = 'p', long = "attach")]
    pub pid: Option<usize>,

    /// trace child processes when traced programs create them
    #[arg(
        short = 'f',
        long = "follow-forks",
        conflicts_with = "pid",
        conflicts_with = "failed_only"
    )]
    pub follow_forks: bool,

    /// only print failed syscalls
    #[arg(short = 'z', long = "failed-only")]
    pub failed_only: bool,

    /// mute the traced program's std output
    #[arg(short = 'q', long = "mute-stdout")]
    pub mute_stdout: bool,

    #[command(subcommand)]
    pub binary: Option<Binary>,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Binary {
    #[command(external_subcommand)]
    Command(Vec<String>),
}

pub fn terminal_setup() {
    if let Ok(theme) = termbg::theme(std::time::Duration::from_millis(10)) {
        match theme {
            termbg::Theme::Light => {
                GENERAL_TEXT_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 64,
                        g: 64,
                        b: 64,
                    });
                });
                PAGES_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 0,
                        g: 169,
                        b: 223,
                    });
                });

                PID_BACKGROUND_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 146,
                        g: 146,
                        b: 168,
                    });
                });
                PID_NUMBER_COLOR.with(|color| {
                    let _ = color.set(CustomColor { r: 0, g: 0, b: 140 });
                });
                EXITED_BACKGROUND_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 250,
                        g: 160,
                        b: 160,
                    });
                });
                OUR_YELLOW.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 112,
                        g: 127,
                        b: 35,
                    });
                });
                CONTINUED_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 188,
                        g: 210,
                        b: 230,
                    });
                });
                STOPPED_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 82,
                        g: 138,
                        b: 174,
                    });
                });
            }
            termbg::Theme::Dark => {
                GENERAL_TEXT_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 160,
                        g: 160,
                        b: 160,
                    });
                });
                PAGES_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 0,
                        g: 169,
                        b: 223,
                    });
                });

                PID_BACKGROUND_COLOR.with(|color| {
                    let _ = color.set(CustomColor { r: 0, g: 0, b: 0 });
                });
                PID_NUMBER_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 0,
                        g: 173,
                        b: 216,
                    });
                });
                EXITED_BACKGROUND_COLOR.with(|color| {
                    let _ = color.set(CustomColor { r: 100, g: 0, b: 0 });
                });
                OUR_YELLOW.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 187,
                        g: 142,
                        b: 35,
                    });
                });
                CONTINUED_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 17,
                        g: 38,
                        b: 21,
                    });
                });
                STOPPED_COLOR.with(|color| {
                    let _ = color.set(CustomColor {
                        r: 47,
                        g: 86,
                        b: 54,
                    });
                });
            }
        }
    }
}

pub fn buffered_write(data: ColoredString) {
    write!(WRITER_LAZY.lock().unwrap(), "{}", data).unwrap();
}

pub fn flush_buffer() {
    WRITER_LAZY.lock().unwrap().flush().unwrap();
}

#[inline(always)]
pub fn colorize_general_text(arg: &str) {
    let text = arg.custom_color(get_thread_local_color!(GENERAL_TEXT_COLOR));
    buffered_write(text);
}

pub fn colorize_diverse(arg: &str, color: CustomColor) {
    let text = arg.custom_color(color);
    buffered_write(text);
}

pub fn static_handle_path_file(filename: String, vector: &mut Vec<ColoredString>) {
    let mut pathname = String::new();

    let mut file_start = 0;
    for (index, chara) in filename.chars().rev().enumerate() {
        if chara == '/' && index != 0 {
            file_start = filename.len() - index;
            break;
        }
    }
    vector.push(filename[0..file_start].custom_color(get_thread_local_color!(OUR_YELLOW)));

    vector.push(filename[file_start..].custom_color(get_thread_local_color!(PAGES_COLOR)));
}

pub fn lose_relativity_on_path(string: std::borrow::Cow<'_, str>) -> String {
    let mut chars = string.chars().peekable();
    while let Some(&chara) = chars.peek() {
        if chara == '.' || chara == '/' {
            let _ = chars.next().unwrap();
            continue;
        }
        break;
    }
    chars.collect()
}

pub fn get_mem_difference_from_previous(post_call_brk: usize) -> isize {
    post_call_brk as isize - PRE_CALL_PROGRAM_BREAK_POINT.get() as isize
}

pub fn match_enum_with_libc_flag(flags: u64, discriminant: i32) -> bool {
    (flags & (discriminant as u64)) == discriminant as u64
}

pub fn set_memory_break(child: Pid) {
    let ptraced_process = procfs::process::Process::new(i32::from(child)).unwrap();
    let stat = ptraced_process.stat().unwrap();
    let pre_call_brk = stat.start_brk.unwrap() as usize;

    let old_stored_brk = PRE_CALL_PROGRAM_BREAK_POINT.get();
    PRE_CALL_PROGRAM_BREAK_POINT.set(pre_call_brk);
}

pub fn where_in_childs_memory(child: Pid, address: u64) -> Option<MemoryMap> {
    let ptraced_process = procfs::process::Process::new(i32::from(child)).unwrap();
    let maps = ptraced_process.maps().unwrap().0;
    maps.into_iter()
        .find(|x| (address >= x.address.0) && (address <= x.address.1))
}

pub fn get_child_memory_break(child: Pid) -> (usize, (u64, u64)) {
    let ptraced_process = procfs::process::Process::new(i32::from(child)).unwrap();
    let stat = ptraced_process.stat().unwrap();
    let aa = ptraced_process.maps().unwrap().0;
    let c = aa
        .into_iter()
        .find(|x| x.pathname == MMapPath::Stack)
        .map(|x| x.address)
        .unwrap_or((0, 0));
    (PRE_CALL_PROGRAM_BREAK_POINT.get(), c)
}

pub fn errno_check(rax: u64) -> Option<Errno> {
    // TODO! improve on this hack
    let max_errno = 4095;
    // strace does something similar to this
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/negated_errno.h#L17
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/linux/x86_64/get_error.c#L26
    if rax > max_errno {
        let errno = (u32::MAX - rax as u32).saturating_add(1);
        let Errno: Errno = Errno::from_raw(errno as i32);
        let errno_fmt = errno::Errno(errno as i32);
        if matches!(Errno, Errno::UnknownErrno) {
            // p!("Big number but not an error");
            None
        } else {
            // p!(errno_fmt);
            Some(Errno)
        }
    } else {
        // p!("Not an error");
        None
    }
}

pub fn display_unsupported() {
    // unsafe {
    //     UNSUPPORTED.iter().for_each(|uns| println!(" - {}", uns));
    // }
}

pub fn x86_signal_to_string(signum: u64) -> Option<&'static str> {
    match signum {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        6 => Some("SIGABRT/SIGIOT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        9 => Some("SIGKILL"),
        10 => Some("SIGUSR1"),
        11 => Some("SIGSEGV"),
        12 => Some("SIGUSR2"),
        13 => Some("SIGPIPE"),
        14 => Some("SIGALRM"),
        15 => Some("SIGTERM"),
        16 => Some("SIGSTKFLT"),
        17 => Some("SIGCHLD"),
        18 => Some("SIGCONT"),
        19 => Some("SIGSTOP"),
        20 => Some("SIGTSTP"),
        21 => Some("SIGTTIN"),
        22 => Some("SIGTTOU"),
        23 => Some("SIGURG"),
        24 => Some("SIGXCPU"),
        25 => Some("SIGXFSZ"),
        26 => Some("SIGVTALRM"),
        27 => Some("SIGPROF"),
        28 => Some("SIGWINCH"),
        29 => Some("SIGIO/SIGPOLL"),
        30 => Some("SIGPWR"),
        34..=64 => Some("SIGRT"),
        _ => Some("SIGSYS/SIGUNUSED"),
    }
}

pub fn errno_to_string(errno: Errno) -> &'static str {
    match errno {
        Errno::EPERM => "Operation not permitted",
        Errno::ENOENT => "No such file or directory",
        Errno::ESRCH => "No such process",
        Errno::EINTR => "Interrupted system call",
        Errno::EIO => "I/O error",
        Errno::ENXIO => "No such device or address",
        Errno::E2BIG => "Argument list too long",
        Errno::ENOEXEC => "Exec format error",
        Errno::EBADF => "Bad file number",
        Errno::ECHILD => "No child processes",
        Errno::EAGAIN => "Try again",
        Errno::ENOMEM => "Out of memory",
        Errno::EACCES => "Permission denied",
        Errno::EFAULT => "Bad address",
        Errno::ENOTBLK => "Block device required",
        Errno::EBUSY => "Device or resource busy",
        Errno::EEXIST => "File exists",
        Errno::EXDEV => "Cross-device link",
        Errno::ENODEV => "No such device",
        Errno::ENOTDIR => "Not a directory",
        Errno::EISDIR => "Is a directory",
        Errno::EINVAL => "Invalid argument",
        Errno::ENFILE => "File table overflow",
        Errno::EMFILE => "Too many open files",
        Errno::ENOTTY => "Not a typewriter",
        Errno::ETXTBSY => "Text file busy",
        Errno::EFBIG => "File too large",
        Errno::ENOSPC => "No space left on device",
        Errno::ESPIPE => "Illegal seek",
        Errno::EROFS => "Read-only file system",
        Errno::EMLINK => "Too many links",
        Errno::EPIPE => "Broken pipe",
        Errno::EDOM => "Math argument out of domain of func",
        Errno::ERANGE => "Math result not representable",
        Errno::EDEADLK => "Resource deadlock would occur",
        Errno::ENAMETOOLONG => "File name too long",
        Errno::ENOLCK => "No record locks available",
        Errno::ENOSYS => "Function not implemented",
        Errno::ENOTEMPTY => "Directory not empty",
        Errno::ELOOP => "Too many symbolic links encountered",
        Errno::ENOMSG => "No message of desired type",
        Errno::EIDRM => "Identifier removed",
        Errno::ECHRNG => "Channel number out of range",
        Errno::EL2NSYNC => "Level 2 not synchronized",
        Errno::EL3HLT => "Level 3 halted",
        Errno::EL3RST => "Level 3 reset",
        Errno::ELNRNG => "Link number out of range",
        Errno::EUNATCH => "Protocol driver not attached",
        Errno::ENOCSI => "No CSI structure available",
        Errno::EL2HLT => "Level 2 halted",
        Errno::EBADE => "Invalid exchange",
        Errno::EBADR => "Invalid request descriptor",
        Errno::EXFULL => "Exchange full",
        Errno::ENOANO => "No anode",
        Errno::EBADRQC => "Invalid request code",
        Errno::EBADSLT => "Invalid slot",
        Errno::EBFONT => "Bad font file format",
        Errno::ENOSTR => "Device not a stream",
        Errno::ENODATA => "No data available",
        Errno::ETIME => "Timer expired",
        Errno::ENOSR => "Out of streams resources",
        Errno::ENONET => "Machine is not on the network",
        Errno::ENOPKG => "Package not installed",
        Errno::EREMOTE => "Object is remote",
        Errno::ENOLINK => "Link has been severed",
        Errno::EADV => "Advertise error",
        Errno::ESRMNT => "Srmount error",
        Errno::ECOMM => "Communication error on send",
        Errno::EPROTO => "Protocol error",
        Errno::EMULTIHOP => "Multihop attempted",
        Errno::EDOTDOT => "RFS specific error",
        Errno::EBADMSG => "Not a data message",
        Errno::EOVERFLOW => "Value too large for defined data type",
        Errno::ENOTUNIQ => "Name not unique on network",
        Errno::EBADFD => "File descriptor in bad state",
        Errno::EREMCHG => "Remote address changed",
        Errno::ELIBACC => "Can not access a needed shared library",
        Errno::ELIBBAD => "Accessing a corrupted shared library",
        Errno::ELIBSCN => ".lib section in a.out corrupted",
        Errno::ELIBMAX => "Attempting to link in too many shared libraries",
        Errno::ELIBEXEC => "Cannot exec a shared library directly",
        Errno::EILSEQ => "Illegal byte sequence",
        Errno::ERESTART => "Interrupted system call should be restarted",
        Errno::ESTRPIPE => "Streams pipe error",
        Errno::EUSERS => "Too many users",
        Errno::ENOTSOCK => "Socket operation on non-socket",
        Errno::EDESTADDRREQ => "Destination address required",
        Errno::EMSGSIZE => "Message too long",
        Errno::EPROTOTYPE => "Protocol wrong type for socket",
        Errno::ENOPROTOOPT => "Protocol not available",
        Errno::EPROTONOSUPPORT => "Protocol not supported",
        Errno::ESOCKTNOSUPPORT => "Socket type not supported",
        Errno::EOPNOTSUPP => "Operation not supported on transport endpoint",
        Errno::EPFNOSUPPORT => "Protocol family not supported",
        Errno::EAFNOSUPPORT => "Address family not supported by protocol",
        Errno::EADDRINUSE => "Address already in use",
        Errno::EADDRNOTAVAIL => "Cannot assign requested address",
        Errno::ENETDOWN => "Network is down",
        Errno::ENETUNREACH => "Network is unreachable",
        Errno::ENETRESET => "Network dropped connection because of reset",
        Errno::ECONNABORTED => "Software caused connection abort",
        Errno::ECONNRESET => "Connection reset by peer",
        Errno::ENOBUFS => "No buffer space available",
        Errno::EISCONN => "Transport endpoint is already connected",
        Errno::ENOTCONN => "Transport endpoint is not connected",
        Errno::ESHUTDOWN => "Cannot send after transport endpoint shutdown",
        Errno::ETOOMANYREFS => "Too many references: cannot splice",
        Errno::ETIMEDOUT => "Connection timed out",
        Errno::ECONNREFUSED => "Connection refused",
        Errno::EHOSTDOWN => "Host is down",
        Errno::EHOSTUNREACH => "No route to host",
        Errno::EALREADY => "Operation already in progress",
        Errno::EINPROGRESS => "Operation now in progress",
        Errno::ESTALE => "Stale NFS file handle",
        Errno::EUCLEAN => "Structure needs cleaning",
        Errno::ENOTNAM => "Not a XENIX named type file",
        Errno::ENAVAIL => "No XENIX semaphores available",
        Errno::EISNAM => "Is a named type file",
        Errno::EREMOTEIO => "Remote I/O error",
        Errno::EDQUOT => "Quota exceeded",
        Errno::ENOMEDIUM => "No medium found",
        Errno::EMEDIUMTYPE => "Wrong medium type",
        Errno::ECANCELED => "Operation Canceled",
        Errno::ENOKEY => "Required key not available",
        Errno::EKEYEXPIRED => "Key has expired",
        Errno::EKEYREVOKED => "Key has been revoked",
        Errno::EKEYREJECTED => "Key was rejected by service",
        Errno::EOWNERDEAD => "Owner died",
        Errno::ENOTRECOVERABLE => "State not recoverable",
        Errno::ERFKILL => "Operation not possible due to RF-kill",
        // Errno::EWOULDBLOCK => "Operation would block",
        // Errno::EAGAIN => "Operation would block",
        // Errno::EDEADLOCK => "Resource deadlock would occur",
        Errno::EHWPOISON => "Memory page has hardware error",
        Errno::UnknownErrno => unreachable!(),
        _ => unreachable!(),
    }
}

pub fn parse_register_as_address(register: u64) -> String {
    format!("{:p}", register as *const ())
}
