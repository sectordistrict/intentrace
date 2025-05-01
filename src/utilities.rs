use core::sync::atomic::AtomicUsize;
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    os::fd::RawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
    time::Duration,
};

use colored::{ColoredString, Colorize, CustomColor};
use nix::{
    errno::Errno,
    libc::{sysconf, _SC_PAGESIZE},
    sys::signal::Signal,
    unistd::Pid,
};
use procfs::process::{MMapPath, MemoryMap};
use syscalls::Sysno;
use unicode_segmentation::Graphemes;
use uzers::{Groups, Users};

use crate::{
    auxiliary::{constants::general::MAX_KERNEL_ULONG, kernel_errno::KernelErrno},
    colors::{switch_pathlike_color, PARTITION_1_COLOR, PARTITION_2_COLOR, PATHLIKE_ALTERNATOR},
    peeker_poker::{read_bytes_until_null, read_words_until_null},
    syscall_categories::initialize_categories_map,
    syscall_object::{ErrnoVariant, SyscallResult},
    syscall_skeleton_map::initialize_skeletons_map,
    types::{BytesPagesRelevant, Category, Syscall_Shape},
};

pub static PAGE_SIZE: LazyLock<usize> = LazyLock::new(|| unsafe { sysconf(_SC_PAGESIZE) as usize });
pub static PRE_CALL_PROGRAM_BREAK_POINT: AtomicUsize = AtomicUsize::new(0);
pub static REGISTERS: Mutex<[u64; 6]> = Mutex::new([0; 6]);
pub static HALT_TRACING: AtomicBool = AtomicBool::new(false);

pub static TABLE: LazyLock<Mutex<HashMap<Sysno, (usize, Duration)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub static TABLE_FOLLOW_FORKS: LazyLock<Mutex<HashMap<Sysno, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
// pub static SYSANNOT_MAP: LazyLock<HashMap<Sysno, SysAnnotations>> =
//     LazyLock::new(|| initialize_annotations_map());
pub static SYSKELETON_MAP: LazyLock<HashMap<Sysno, Syscall_Shape>> =
    LazyLock::new(initialize_skeletons_map);
pub static SYSCATEGORIES_MAP: LazyLock<HashMap<Sysno, Category>> =
    LazyLock::new(initialize_categories_map);
pub static FUTEXES: LazyLock<Mutex<HashMap<usize, ColoredString>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub static UZERS_CACHE: LazyLock<Mutex<uzers::UsersCache>> =
    LazyLock::new(|| Mutex::new(uzers::UsersCache::new()));
// TODO!
// switch to a string-interner implementation that remembers the last 5 pathlikes
pub static LAST_PATHLIKE: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

pub fn lose_relativity_on_path(string: &str) -> &str {
    let mut chars = string.chars().enumerate().peekable();
    while let Some(&(index, chara)) = chars.peek() {
        if chara == '.' {
            let _ = chars.next().unwrap();
            continue;
        }
        return &string[index..];
    }
    ""
}

pub fn get_mem_difference_from_previous(post_call_brk: usize) -> isize {
    post_call_brk as isize - PRE_CALL_PROGRAM_BREAK_POINT.load(Ordering::SeqCst) as isize
}

pub fn set_memory_break(tracee_pid: Pid) {
    let ptraced_process = procfs::process::Process::new(i32::from(tracee_pid)).unwrap();
    let stat = ptraced_process.stat().unwrap();
    let pre_call_brk = stat.start_brk.unwrap() as usize;

    PRE_CALL_PROGRAM_BREAK_POINT.store(pre_call_brk, Ordering::SeqCst);
}

pub fn where_in_tracee_memory(tracee_pid: Pid, address: u64) -> Option<MemoryMap> {
    let ptraced_process = procfs::process::Process::new(i32::from(tracee_pid)).ok()?;
    let maps = ptraced_process.maps().ok()?.0;
    maps.into_iter()
        .find(|map| (address >= map.address.0) && (address <= map.address.1))
}

pub fn get_tracee_memory_break(tracee_pid: Pid) -> Option<(usize, (u64, u64))> {
    let ptraced_process = procfs::process::Process::new(i32::from(tracee_pid)).ok()?;
    let maps = ptraced_process.maps().ok()?.0;
    let address_range = maps
        .into_iter()
        .find(|map| map.pathname == MMapPath::Stack)
        .map(|map| map.address)
        .unwrap_or((0, 0));
    Some((
        PRE_CALL_PROGRAM_BREAK_POINT.load(Ordering::SeqCst),
        address_range,
    ))
}

pub fn interpret_syscall_result(return_register: u64) -> SyscallResult {
    // TODO!
    // abandon the KernelErrno check and make it manual in restartable syscalls
    use ErrnoVariant::*;
    use SyscallResult::*;

    // strace does something similar to this
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/negated_errno.h#L17
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/linux/x86_64/get_error.c#L26
    if return_register > MAX_KERNEL_ULONG as u64 {
        let errno_positive = parse_as_long(return_register) * -1;
        let userland_errno = Errno::from_raw(errno_positive as i32);
        if matches!(userland_errno, Errno::UnknownErrno) {
            let kernel_errno = KernelErrno::from_i32(errno_positive as i32);
            if matches!(kernel_errno, KernelErrno::UnknownErrno) {
                // Large number but not an error
                return Success(return_register);
            }
            return Fail(Kernel(kernel_errno));
        }
        Fail(Userland(userland_errno))
    } else {
        Success(return_register)
    }
}

pub fn display_unsupported() {
    // unsafe {
    //     UNSUPPORTED.iter().for_each(|uns| println!(" - {}", uns));
    // }
}

// this makes futexes more searchable
pub fn calculate_futex_alias(mut futex_count: i32) -> String {
    let mut collector = String::new();
    while futex_count >= 0 {
        let remainder = futex_count % 26;
        let letter = (b'A' + remainder as u8) as char;
        collector.insert(0, letter);
        futex_count = (futex_count / 26) - 1;
    }
    collector.push_str(" ->");
    collector
}

pub fn parse_as_signal(signum: i32) -> &'static str {
    match Signal::try_from(signum) {
        Ok(signal) => signal.as_str(),
        Err(_e) => match signum {
            32 => "SIGRT_32",
            33 => "SIGRT_33",
            34 => "SIGRT_34",
            35 => "SIGRT_35",
            36 => "SIGRT_36",
            37 => "SIGRT_37",
            38 => "SIGRT_38",
            39 => "SIGRT_39",
            40 => "SIGRT_40",
            41 => "SIGRT_41",
            42 => "SIGRT_42",
            43 => "SIGRT_43",
            44 => "SIGRT_44",
            45 => "SIGRT_45",
            46 => "SIGRT_46",
            47 => "SIGRT_47",
            48 => "SIGRT_48",
            49 => "SIGRT_49",
            50 => "SIGRT_50",
            51 => "SIGRT_51",
            52 => "SIGRT_52",
            53 => "SIGRT_53",
            54 => "SIGRT_54",
            55 => "SIGRT_55",
            56 => "SIGRT_56",
            57 => "SIGRT_57",
            58 => "SIGRT_58",
            59 => "SIGRT_59",
            60 => "SIGRT_60",
            61 => "SIGRT_61",
            62 => "SIGRT_62",
            63 => "SIGRT_63",
            64 => "SIGRT_64",
            _ => "[intentrace: signal not supported]",
        },
    }
}

pub fn parse_as_int(register: u64) -> i32 {
    unsafe { std::mem::transmute::<u32, i32>(lower_32_bits(register)) }
}

pub fn parse_as_long(register: u64) -> i64 {
    unsafe { std::mem::transmute::<u64, i64>(register) }
}

#[inline(always)]
pub fn parse_as_ssize_t(register: usize) -> isize {
    unsafe { std::mem::transmute::<usize, isize>(register) }
}

pub fn lower_32_bits(value: u64) -> u32 {
    (value & 0xFFFFFFFF) as u32
}

pub fn lower_64_bits(value: usize) -> u64 {
    (value & 0xFFFFFFFFFFFFFFFF) as u64
}

// CONVERSION OUTSIDE
pub fn parse_as_address(register_value: usize) -> String {
    let pointer = register_value as *const ();
    if pointer.is_null() {
        "0xNull".to_string()
    } else {
        format!("{:p}", pointer)
    }
}

// Length_Of_Bytes_Specific
// memory and file indexers and seekers where negative is expected
pub fn parse_as_signed_bytes(register_value: u64) -> String {
    let bytes = unsafe { std::mem::transmute::<u64, i64>(register_value) };
    // TODO!
    // phrasing should be checked for lseek and offsets in mmap
    format!("{bytes} Bytes")
}

// Length_Of_Bytes_Specific
// memory and file indexers and seekers where negative is expected
pub fn parse_as_unsigned_bytes(register_value: u64) -> String {
    format!("{register_value} Bytes")
}

// usually a size_t in mem syscalls
pub fn parse_as_bytes_pages_ceil(register_value: usize) -> String {
    let bytes_pages = BytesPagesRelevant::from_ceil(register_value);
    bytes_pages.to_string()
}

// usually a size_t in mem syscalls
fn parse_as_bytes_pages_floor(register_value: usize) -> String {
    let bytes_pages = BytesPagesRelevant::from_floor(register_value);
    bytes_pages.to_string()
}

// Use process_vm_readv(2)
pub fn string_from_pointer(address: usize, tracee_pid: Pid) -> String {
    // TODO!
    // multi-threaded execve fails here for some reason
    match read_bytes_until_null(address, tracee_pid) {
        Some(data) => String::from_utf8_lossy(&data).into_owned(),
        None => "".to_owned(),
    }
}

pub fn get_array_of_strings(address: usize, tracee_pid: Pid) -> Vec<String> {
    // TODO!
    // execve fails this
    let array_of_char_pointers = read_words_until_null(address, tracee_pid).unwrap();
    let mut strings = vec![];
    for char_pointer in array_of_char_pointers {
        strings.push(string_from_pointer(char_pointer, tracee_pid));
    }
    strings
}
fn calculate_hash(t: &str) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub fn get_final_dentry_color_consider_repetition(repetition_dependent: &str) -> CustomColor {
    let last_pathlike = *LAST_PATHLIKE.lock().unwrap();
    if last_pathlike == calculate_hash(repetition_dependent) {
        // dont switch
        let alternator = *PATHLIKE_ALTERNATOR.lock().unwrap();
        PARTITION_2_COLOR[alternator]
    } else {
        *LAST_PATHLIKE.lock().unwrap() = calculate_hash(repetition_dependent);
        // switch
        switch_pathlike_color();
        let alternator = *PATHLIKE_ALTERNATOR.lock().unwrap();
        PARTITION_2_COLOR[alternator]
    }
}

pub fn partition_by_final_dentry(graphemes: Graphemes) -> (Vec<&str>, Vec<&str>) {
    let mut graphemes_revved = graphemes.rev();
    let mut in_final_dentry = true;
    let blue = graphemes_revved
        .by_ref()
        .take_while(|chara| {
            if *chara == "/" {
                in_final_dentry = false
            }
            in_final_dentry
        })
        .collect::<Vec<&str>>();
    let mut yellow = graphemes_revved.rev().collect::<Vec<&str>>();
    yellow.push("/");
    (yellow, blue.into_iter().rev().collect::<_>())
}

pub fn parse_as_file_descriptor(file_descriptor: i32, tracee_pid: Pid) -> String {
    let mut colored_strings = Vec::new();
    if file_descriptor == 0 {
        return "0 -> StdIn".bright_blue().to_string();
    } else if file_descriptor == 1 {
        return "1 -> StdOut".bright_blue().to_string();
    } else if file_descriptor == 2 {
        return "2 -> StdErr".bright_blue().to_string();
    } else {
        let file_info =
            procfs::process::FDInfo::from_raw_fd(tracee_pid.into(), file_descriptor as RawFd);
        match file_info {
            Ok(file) => match file.target {
                procfs::process::FDTarget::Path(path) => {
                    use unicode_segmentation::UnicodeSegmentation;
                    colored_strings.push(format!("{} -> ", file.fd).bright_blue());
                    let graphemes = path.to_str().unwrap().graphemes(true);
                    let (partition1, partition2) = partition_by_final_dentry(graphemes);
                    let yellow = partition1.into_iter().collect::<String>();
                    let repetition_dependent = partition2.into_iter().collect::<String>();
                    let partition_2_color =
                        get_final_dentry_color_consider_repetition(&repetition_dependent);
                    colored_strings.push(yellow.custom_color(*PARTITION_1_COLOR));
                    colored_strings.push(repetition_dependent.custom_color(partition_2_color));
                }
                procfs::process::FDTarget::Socket(socket_number) => {
                    use procfs::net;
                    let mut tcp = net::tcp().unwrap();
                    tcp.extend(net::tcp6().unwrap());
                    let mut udp = net::udp().unwrap();
                    udp.extend(net::udp6().unwrap());
                    let unix = net::unix().unwrap();
                    'lookup: {
                        for entry in &tcp {
                            if entry.inode == socket_number {
                                if entry.remote_address.ip().is_loopback() {
                                    colored_strings.push(
                                        format!(
                                            "{} -> localhost:{}",
                                            file.fd,
                                            entry.remote_address.port()
                                        )
                                        .bright_blue(),
                                    );
                                } else {
                                    colored_strings.push(
                                        format!(
                                            "{} -> {:?}:{}",
                                            file.fd,
                                            entry.remote_address.ip(),
                                            entry.remote_address.port()
                                        )
                                        .bright_blue(),
                                    );
                                }
                                break 'lookup;
                            }
                        }
                        for entry in &udp {
                            if entry.inode == socket_number {
                                // println!("UDP {:?}", entry);
                                break 'lookup;
                            }
                        }
                        for entry in &unix {
                            if entry.inode == socket_number {
                                colored_strings.push(
                                    format!("{} -> Unix Domain Socket", file.fd).bright_blue(),
                                );
                                break 'lookup;
                            }
                        }
                    }
                }
                procfs::process::FDTarget::Net(_net) => {
                    return format!("{} -> NET", file.fd).bright_blue().to_string()
                }
                procfs::process::FDTarget::Pipe(_pipe) => {
                    return format!("{} -> Unix Pipe", file.fd)
                        .bright_blue()
                        .to_string()
                }
                procfs::process::FDTarget::AnonInode(anon_inode) => {
                    // anon_inode is basically a file that has no inode on disk
                    // anon_inode could've been something that was a file that is no longer on the disk
                    // Some syscalls create file descriptors that have no inode
                    // epoll_create, eventfd, inotify_init, signalfd, and timerfd
                    // the entry will be a symbolic link with contents "anon_inode:<file-type>"
                    // An anon_inode shows that there's a file descriptor which has no referencing inode

                    // open syscall can be used to create an anon inode
                    //          int fd = open( "/tmp/file", O_CREAT | O_RDWR, 0666 );
                    //          unlink( "/tmp/file" );
                    return format!("{} -> {anon_inode}", file.fd)
                        .bright_blue()
                        .to_string();
                }
                procfs::process::FDTarget::MemFD(mem_fd) => {
                    return format!("{} -> {mem_fd}", file.fd).bright_blue().to_string()
                }
                procfs::process::FDTarget::Other(target, _inode_number) => {
                    return format!("{} -> {target}", file.fd).bright_blue().to_string()
                }
            },
            Err(_e) => return "ignored".to_owned(),
        }
    }
    String::from_iter(
        colored_strings
            .into_iter()
            .map(|colored_string| colored_string.to_string()),
    )
}

pub fn find_fd_for_tracee(file_descriptor: i32, tracee_pid: Pid) -> Option<String> {
    let mut fds = procfs::process::Process::new(tracee_pid.as_raw())
        .ok()?
        .fd()
        .ok()?;
    let descriptor_found = fds.find(|fd_iter| fd_iter.as_ref().unwrap().fd == file_descriptor)?;
    let descriptor_unwrapped = descriptor_found.ok()?;
    if let procfs::process::FDTarget::Path(path_buf) = descriptor_unwrapped.target {
        Some(path_buf.to_string_lossy().to_string())
    } else {
        None
    }
}

pub fn get_username_from_uid(owner: u32) -> Option<&'static str> {
    let cache = UZERS_CACHE.lock().unwrap();
    let user = cache.get_user_by_uid(owner)?;
    let name_str = user.name().to_str()?;
    Some(name_str.to_owned().leak())
}

pub fn get_groupname_from_uid(group: u32) -> Option<&'static str> {
    let cache = UZERS_CACHE.lock().unwrap();
    let group_retrieved = cache.get_group_by_gid(group)?;
    let group = group_retrieved.name().to_str()?;
    Some(group.to_owned().leak())
}

pub fn new_process() -> ColoredString {
    "

  ╭────────────────╮
  │                │
  │  NEW PROCESS   │
  │                │
  ╰────────────────╯
"
    .custom_color(colored::CustomColor {
        r: 223,
        g: 128,
        b: 8,
    })
}

pub fn new_thread() -> ColoredString {
    "

  ╭────────────────╮
  │                │
  │   NEW THREAD   │
  │                │
  ╰────────────────╯
"
    .green()
}

// TODO!
// consider blinking arrows as replacement
pub fn syscall_is_blocking() -> ColoredString {
    "  ╭─────────────────────╮
  │   SYSCALL BLOCKED   │
  ╰─────────────────────╯
"
    .cyan()
}

// TODO!
// check how strace does this, maybe its better
pub fn colorize_syscall_name(sysno: &Sysno, category: &Category) -> ColoredString {
    match category {
        // green
        Category::Process => sysno.name().bold().green(),
        Category::Thread => sysno.name().bold().green(),
        Category::CPU => sysno.name().bold().green(),

        Category::Network => sysno.name().bold().green(),

        // ram
        Category::Memory => sysno.name().bold().bright_red(),

        // bluish
        Category::FileOp => sysno.name().bold().blue(),
        Category::DiskIO => sysno.name().bold().bright_blue(),
        Category::Security => sysno.name().bold().bright_cyan(),

        // black
        Category::System => sysno.name().bold().cyan(),

        // exotic
        Category::Signals => sysno.name().bold().bright_purple(),
        Category::Device => sysno.name().bold().bright_yellow(),
        Category::AsyncIO => sysno.name().bold().purple(),
    }
}
