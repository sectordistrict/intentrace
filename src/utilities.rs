use core::sync::atomic::AtomicUsize;
use std::{
    collections::HashMap,
    os::fd::RawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
    time::Duration,
};

use colored::{ColoredString, Colorize};
use nix::{errno::Errno, libc::AT_FDCWD, sys::signal::Signal, unistd::Pid};
use procfs::process::{MMapPath, MemoryMap};
use syscalls::Sysno;

use crate::{
    colors::{OUR_YELLOW, PAGES_COLOR},
    peeker_poker::{read_bytes_until_null, read_words_until_null},
    syscall_annotations_map::initialize_annotations_map,
    syscall_categories::initialize_categories_map,
    syscall_object::{SyscallObject, SyscallResult},
    syscall_skeleton_map::initialize_skeletons_map,
    types::{BytesPagesRelevant, Category, SysAnnotations, Syscall_Shape}, write_text, writer::write_general_text,
};

// pub static mut UNSUPPORTED: Vec<&'static str> = Vec::new();

pub static PAGE_SIZE: LazyLock<usize> = LazyLock::new(rustix::param::page_size);
pub static PRE_CALL_PROGRAM_BREAK_POINT: AtomicUsize = AtomicUsize::new(0);
pub static REGISTERS: Mutex<[u64; 6]> = Mutex::new([0; 6]);
pub static HALT_TRACING: AtomicBool = AtomicBool::new(false);

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

pub fn static_handle_path_file(filename: String, vector: &mut Vec<ColoredString>) {
    let mut pathname = String::new();

    let mut file_start = 0;
    for (index, chara) in filename.chars().rev().enumerate() {
        if chara == '/' && index != 0 {
            file_start = filename.len() - index;
            break;
        }
    }
    vector.push(filename[0..file_start].custom_color(*OUR_YELLOW));

    vector.push(filename[file_start..].custom_color(*PAGES_COLOR));
}

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

pub fn match_enum_with_libc_flag(flags: u64, discriminant: i32) -> bool {
    (flags & (discriminant as u64)) == discriminant as u64
}

pub fn set_memory_break(child: Pid) {
    let ptraced_process = procfs::process::Process::new(i32::from(child)).unwrap();
    let stat = ptraced_process.stat().unwrap();
    let pre_call_brk = stat.start_brk.unwrap() as usize;

    let old_stored_brk = PRE_CALL_PROGRAM_BREAK_POINT.load(Ordering::SeqCst);
    PRE_CALL_PROGRAM_BREAK_POINT.store(pre_call_brk, Ordering::SeqCst);
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
    (PRE_CALL_PROGRAM_BREAK_POINT.load(Ordering::SeqCst), c)
}

pub fn get_syscall_result(return_register: u64) -> SyscallResult {
    // When syscalls return errors,
    // libc takes the negative error,        ->  -22
    // negates it to get a positive number,  ->   22
    // and stores it in errno

    let max_errno = 4095;
    // strace does something similar to this
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/negated_errno.h#L17
    // https://github.com/strace/strace/blob/0f9f46096fa8da84e2e6a6646cd1e326bf7e83c7/src/linux/x86_64/get_error.c#L26
    if return_register > max_errno {
        let errno = (u32::MAX - return_register as u32).saturating_add(1);
        let Errno: Errno = Errno::from_raw(errno as i32);
        if matches!(Errno, Errno::UnknownErrno) {
            // p!("Big number but not an error");
            SyscallResult::Success(return_register)
        } else {
            SyscallResult::Fail(Errno)
        }
    } else {
        // p!("Not an error");
        SyscallResult::Success(return_register)
    }
}

pub fn display_unsupported() {
    // unsafe {
    //     UNSUPPORTED.iter().for_each(|uns| println!(" - {}", uns));
    // }
}


pub fn parse_as_signal(signum: i32) -> String {
    match Signal::try_from(signum) {
        Ok(signal) => signal.to_string(),
        Err(_) => "[intentrace: signal not supported]".to_owned(),
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
    if pointer == std::ptr::null() {
        format!("0xNull")
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
    format!("{register_value} Bytes")
}

// Length_Of_Bytes_Specific
// memory and file indexers and seekers where negative is expected
pub fn parse_as_unsigned_bytes(register_value: u64) -> String {
    format!("{register_value} Bytes")
}
// usually a size_t in mem syscalls
//
pub fn parse_as_bytes_pages_ceil(register_value: usize) -> String {
    let bytes_pages = BytesPagesRelevant::from_ceil(register_value as usize);
    bytes_pages.to_string()
}

// Use process_vm_readv(2)
pub fn string_from_pointer(address: usize, child: Pid) -> String {
    // TODO! execve multi-threaded fails here for some reason
    match read_bytes_until_null(address as usize, child) {
        Some(data) => String::from_utf8_lossy(&data).into_owned(),
        None => "".to_owned(),
    }
}

pub fn get_array_of_strings(address: usize, child: Pid) -> Vec<String> {
    // TODO! execve fails this
    let mut array_of_char_pointers = read_words_until_null(address, child).unwrap();
    let mut strings = vec![];
    for char_pointer in array_of_char_pointers {
        strings.push(string_from_pointer(char_pointer, child));
    }
    strings
}

// pub fn read_string_specific_length(
//     addr: usize,
//     child: Pid,
//     size: usize,
// ) -> Option<String> {
//     let bytes_buffer = SyscallObject::read_bytes_specific_length(addr, child, size)?;
//     Some(String::from_utf8_lossy(&bytes_buffer).into_owned())
// }

pub fn parse_as_file_descriptor_possible_dirfd(fd: u64, tracee_pid: Pid) -> String {
    let fd_compare = unsafe { std::mem::transmute::<u64, i64>(fd) } as i32;
    if fd_compare == AT_FDCWD {
        format!("{}", "AT_FDCWD -> Current Working Directory".bright_blue())
    } else {
        parse_as_file_descriptor(fd, tracee_pid)
    }
}

pub fn parse_as_file_descriptor(file_descriptor: u64, tracee_pid: Pid) -> String {
    let mut colored_strings = Vec::new();
    let fd = parse_as_int(file_descriptor);
    if fd == 0 {
        return "0 -> StdIn".bright_blue().to_string();
    } else if fd == 1 {
        return "1 -> StdOut".bright_blue().to_string();
    } else if fd == 2 {
        return "2 -> StdErr".bright_blue().to_string();
    } else {
        let file_info = procfs::process::FDInfo::from_raw_fd(tracee_pid.into(), fd as RawFd);
        match file_info {
            Ok(file) => match file.target {
                procfs::process::FDTarget::Path(path) => {
                    colored_strings.push(format!("{} -> ", file.fd).bright_blue());
                    let mut formatted_path = vec![];
                    static_handle_path_file(
                        path.to_string_lossy().into_owned(),
                        &mut formatted_path,
                    );
                    for path_part in formatted_path {
                        colored_strings.push(path_part);
                    }
                }
                procfs::process::FDTarget::Socket(socket_number) => {
                    use procfs;
                    let mut tcp = procfs::net::tcp().unwrap();
                    tcp.extend(procfs::net::tcp6().unwrap());
                    let mut udp = procfs::net::udp().unwrap();
                    udp.extend(procfs::net::udp6().unwrap());
                    let unix = procfs::net::unix().unwrap();
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
                procfs::process::FDTarget::Net(net) => {
                    return format!("{} -> NET", file.fd).bright_blue().to_string()
                }
                procfs::process::FDTarget::Pipe(pipe) => {
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
                procfs::process::FDTarget::Other(target, inode_number) => {
                    return format!("{} -> {target}", file.fd).bright_blue().to_string()
                }
            },
            Err(e) => return "ignored".to_owned(),
        }
    }
    String::from_iter(colored_strings.into_iter().map(|x| x.to_string()))
}

pub fn find_fd_for_tracee(fd: i32, tracee_pid: Pid) -> Option<String> {
    let mut fds = procfs::process::Process::new(tracee_pid.as_raw())
        .unwrap()
        .fd()
        .unwrap();
    match fds.find(|fdee| {
        if let Ok(fde) = fdee {
            return fde.fd == fd;
        } else {
            return false;
        }
    }) {
        Some(dirfd_found) => match dirfd_found {
            Ok(dirfd_found_unwrapped) => match dirfd_found_unwrapped.target {
                procfs::process::FDTarget::Path(path_buf) => {
                    Some(path_buf.to_string_lossy().to_string())
                }
                _ => None,
            },
            Err(_) => None,
        },
        None => None,
    }
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
