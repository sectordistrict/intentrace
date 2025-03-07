#![allow(unused_variables)]
use crate::{
    syscall_object::SyscallObject,
    types::{
        mlock2, Annotation, Bytes, BytesPagesRelevant, Category, Flag, LandlockCreateFlags,
        LandlockRuleTypeFlags, SysArg, SysReturn, Syscall_Shape,
    },
    utilities::{
        lose_relativity_on_path, static_handle_path_file, FOLLOW_FORKS, PAGES_COLOR, SYSANNOT_MAP,
        SYSCALL_CATEGORIES, SYSKELETON_MAP,
    },
};

use colored::{ColoredString, Colorize};
use core::slice;
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FallocateFlags, OFlag, RenameFlags},
    libc::{
        cpu_set_t, iovec, msghdr, sockaddr, user_regs_struct, AT_FDCWD, CPU_ISSET, CPU_SETSIZE,
        MAP_FAILED, PRIO_PGRP, PRIO_PROCESS, PRIO_USER,
    },
    sys::{
        eventfd,
        mman::{MRemapFlags, MapFlags, MmapAdvise, MsFlags, ProtFlags},
        ptrace,
        resource::{Resource, UsageWho},
        signal::Signal,
        signalfd::SfdFlags,
        socket::{self, SockFlag},
        stat::{FchmodatFlags, Mode},
        uio::{process_vm_readv, RemoteIoVec},
        wait::WaitPidFlag,
    },
    unistd::{AccessFlags, Pid, Whence},
    NixPath,
};
use syscalls::Sysno;

use rustix::{
    fs::StatxFlags, io::ReadWriteFlags, path::Arg, rand::GetRandomFlags, thread::FutexFlags,
};

use std::{
    fmt::Display,
    io::IoSliceMut,
    mem::{self, transmute, zeroed},
    os::{fd::RawFd, raw::c_void},
    path::PathBuf,
    ptr::null,
    sync::atomic::Ordering,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SyscallState {
    Entering,
    Exiting,
}

#[derive(Clone, Debug)]
pub struct SyscallObject_Annotations {
    pub sysno: Sysno,
    description: &'static str,
    pub category: Category,
    pub args: Vec<u64>,
    pub args_types: Vec<SysArg>,
    rich_args: Vec<Annotation>,
    pub result: (Option<u64>, Annotation, SysReturn),
    pub process_pid: Pid,
    pub errno: Option<Errno>,
}
impl Default for SyscallObject_Annotations {
    fn default() -> Self {
        SyscallObject_Annotations {
            sysno: unsafe { mem::zeroed() },
            description: "",
            category: unsafe { mem::zeroed() },
            args: vec![],
            rich_args: vec![],
            args_types: vec![],
            result: unsafe { mem::zeroed() },
            process_pid: unsafe { mem::zeroed() },
            errno: unsafe { mem::zeroed() },
        }
    }
}

impl From<&mut SyscallObject> for SyscallObject_Annotations {
    fn from(
        SyscallObject {
            sysno,
            category,
            args,
            skeleton,
            result,
            process_pid,
            errno,
            state,
            paused,
        }: &mut SyscallObject,
    ) -> Self {
        if let Some(&(description, annotations_arg_containers, return_annotation)) =
            SYSANNOT_MAP.get(&sysno)
        {
            let category = *SYSCALL_CATEGORIES.get(&sysno).unwrap();
            SyscallObject_Annotations {
                sysno: *sysno,
                description,
                category,
                args: args.clone(),
                args_types: skeleton.clone(),
                rich_args: annotations_arg_containers.into_iter().cloned().collect(),
                result: (result.0, return_annotation, result.1),
                process_pid: *process_pid,
                errno: *errno,
            }
        } else {
            SyscallObject_Annotations {
                sysno: *sysno,
                description: "syscall not covered currently",
                category: Category::Process,
                rich_args: vec![],
                result: (Some(0), ["", ""], SysReturn::Always_Succeeds),
                process_pid: *process_pid,
                errno: None,
                args: args.clone(),
                args_types: skeleton.clone(),
            }
        }
    }
}
impl SyscallObject_Annotations {
    pub fn format(&mut self) {
        // multiline arguments
        let mut output = vec![];
        output.push("\n".dimmed());
        let eph_return = self.parse_return_value(1);
        if FOLLOW_FORKS.load(Ordering::SeqCst) {
            output.push(self.process_pid.to_string().bright_blue());
        } else {
            if eph_return.is_ok() {
                output.push(self.process_pid.to_string().blue());
            } else {
                output.push(self.process_pid.to_string().red());
            }
        }
        output.extend(vec![
            " ".dimmed(),
            SyscallObject_Annotations::colorize_syscall_name(&self.sysno, &self.category),
            " - ".dimmed(),
        ]);
        output.push(self.description.dimmed());
        output.push("\n".bright_white());
        output.push("\t(\n".bright_white());
        let len = self.args.len();
        for index in 0..len {
            // self.args.get(index), self.rich_args[index]
            output.push("\t\t".dimmed());
            let parse_output = self.parse_arg_value(index, 1);
            output.extend(parse_output);
            output.push(",\n".dimmed());
        }
        // println!("{}",self.count);
        output.pop();
        output.push(",\n\t".dimmed());
        output.push(") = ".bright_white());
        match eph_return {
            Ok(good) => {
                output.extend(good);
            }
            Err(errno) => {
                output.push(errno);
            }
        }
        let string = String::from_iter(output.into_iter().map(|x| x.to_string()));
        println!("{}", string)
        // write!(f, "{}\n", string)?

        //
        //
        //
        //
        //
        // normal old one line
        // let mut output = vec![];
        // output.push(self.sysno.name().bright_green());
        // output.push(" - ".dimmed());
        // output.push(self.alt_name.dimmed());
        // output.push(" (".bright_white());
        // let len = self.args.len();
        // for index in 0..len {
        //     let parse_output = self.parse_arg_value(index, 0);
        //     output.extend(parse_output);
        //     output.push(", ".dimmed());
        // }
        // output.pop();
        // output.push(") = ".bright_white());
        // let (might_register, (annotation, sys_return)) = self.result;
        // let parse_return_output = match might_register {
        //     Some(register) => self.parse_return_value(0),
        //     None => {
        //         vec![]
        //     }
        // };
        // output.extend(parse_return_output);
        // let string = String::from_iter(output.into_iter().map(|x| x.to_string()));
        // write!(f, "{}", string)
        //
        //
        //
        //
        //
    }
}

impl SyscallObject_Annotations {
    // annotation, arg_container, register_value
    pub(crate) fn build_annotations(registers: &user_regs_struct, child: Pid) -> Self {
        let sysno = Sysno::from(registers.orig_rax as i32);
        match SYSANNOT_MAP.get(&sysno) {
            Some((syscall_description, annotations_arg_containers, return_annotation)) => {
                let Syscall_Shape {
                    types,
                    syscall_return,
                } = SYSKELETON_MAP.get(&sysno).unwrap();
                let category = *SYSCALL_CATEGORIES.get(&sysno).unwrap();
                match annotations_arg_containers.len() {
                    0 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    1 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![annotations_arg_containers[0]],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    2 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![
                            annotations_arg_containers[0],
                            annotations_arg_containers[1],
                        ],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    3 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![
                            annotations_arg_containers[0],
                            annotations_arg_containers[1],
                            annotations_arg_containers[2],
                        ],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    4 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![
                            annotations_arg_containers[0],
                            annotations_arg_containers[1],
                            annotations_arg_containers[2],
                            annotations_arg_containers[3],
                        ],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    5 => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![
                            annotations_arg_containers[0],
                            annotations_arg_containers[1],
                            annotations_arg_containers[2],
                            annotations_arg_containers[3],
                            annotations_arg_containers[4],
                        ],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    _ => SyscallObject_Annotations {
                        sysno,
                        description: syscall_description,
                        category: category,
                        rich_args: vec![
                            annotations_arg_containers[0],
                            annotations_arg_containers[1],
                            annotations_arg_containers[2],
                            annotations_arg_containers[3],
                            annotations_arg_containers[4],
                            annotations_arg_containers[5],
                        ],
                        result: (None, *return_annotation, *syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                }
            }
            None => {
                // unsafe {
                //     if !UNSUPPORTED.contains(&sysno.name()) {
                //         UNSUPPORTED.push(sysno.name());
                //     }
                // }
                SyscallObject_Annotations {
                    sysno,
                    description: "syscall not covered currently",
                    category: Category::Process,
                    rich_args: vec![],
                    result: (None, ["", ""], SysReturn::Always_Succeeds),
                    process_pid: child,
                    errno: None,
                    ..Default::default()
                }
            }
        }
    }
    pub(crate) fn parse_arg_value(&self, index: usize, which: usize) -> Vec<ColoredString> {
        let annotation = self.rich_args[index];
        let register_value = self.args[index];

        let mut output: Vec<ColoredString> = Vec::new();
        use SysArg::*;
        output.push(annotation[which].dimmed());
        output.push(": ".dimmed());
        output.push(match self.args_types[index] {
            // NUMERICS
            Numeric => format!("{}", register_value as isize).yellow(),
            PID => format!("{}", register_value as isize).yellow(),
            User_Group => format!("{}", register_value as isize).yellow(),
            Unsigned_Numeric => format!("{register_value}").yellow(),
            File_Descriptor(fd) => format!("{fd}").yellow(),
            File_Descriptor_openat(fd) => format!("{fd}").yellow(),
            Pointer_To_File_Descriptor_Array([fd1, fd2]) => {
                format!("read end: {fd1}, write end: {fd2}").yellow()
            }

            // FLAG
            General_Flag(flag) => {
                SyscallObject_Annotations::handle_flag(register_value, flag).yellow()
            }

            // BYTES
            Length_Of_Bytes => SyscallObject_Annotations::style_bytes(register_value).yellow(),
            Length_Of_Bytes_Page_Aligned_Ceil => {
                SyscallObject_Annotations::style_bytes_page_aligned_ceil(register_value).yellow()
            }
            Length_Of_Bytes_Page_Aligned_Floor => {
                SyscallObject_Annotations::style_bytes_page_aligned_floor(register_value).yellow()
            }
            // Signed_Length_Of_Bytes_Specific => {
            //     SyscallObject_Annotations::style_bytes_signed(register_value).yellow()
            // }
            Length_Of_Bytes_Specific => format!("{register_value} Bytes").yellow(),

            // can be mined for granular insights
            Pointer_To_Struct => "0x.. -> {..}".yellow(),
            Array_Of_Struct => "[{..}, {..}]".yellow(),
            Array_Of_Strings(array) => {
                let mut string = String::new();
                for text in array {
                    string.push_str(&text);
                    string.push(' ');
                }
                string.yellow()
            }

            Byte_Stream => format!("whatever").yellow(), // }

            Single_Word => {
                let pointer = register_value as *const ();
                format!("{:p}", pointer).blue()
            }

            Pointer_To_Numeric(pid) => {
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    format!("0xNull").magenta()
                } else {
                    let pid = pid.unwrap();
                    format!("{pid}").blue()
                }
            }
            Pointer_To_Numeric_Or_Numeric(numeric) => {
                if numeric.is_none() {
                    format!("").blue()
                } else {
                    let num = numeric.unwrap();
                    format!("{num}").blue()
                }
            }

            Pointer_To_Unsigned_Numeric => {
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    format!("0xNull").magenta()
                } else {
                    format!("{:p}", pointer).blue()
                }
            }

            Pointer_To_Text(text) => {
                if text.len() > 20 {
                    let portion = &text[..20];
                    format!("{:?}", format!("{}...", portion)).purple()
                } else if text.len() == 0 {
                    format!("\"\"").bright_yellow()
                } else {
                    format!("{:?}", format!("{}", text)).purple()
                }
            }

            Pointer_To_Path(text) => {
                if text.len() > 20 {
                    let portion = &text[..];

                    format!("{:?}", format!("{}...", portion)).purple()
                } else if text.len() == 0 {
                    format!("\"\"").bright_yellow()
                } else {
                    format!("{:?}", format!("{}", text)).purple()
                }
            }

            Address => {
                let pointer = register_value as *const ();
                if pointer == std::ptr::null() {
                    format!("0xNull").bright_red()
                } else {
                    format!("{:p}", pointer).yellow()
                }
            }

            Pointer_To_Length_Of_Bytes_Specific => {
                ColoredString::from("did not handle this yet".yellow())
            }
            // should remove
            Multiple_Flags([flag1, flag2]) => {
                SyscallObject_Annotations::handle_flag(register_value, flag1).yellow()
            }
        });
        output
    }

    pub(crate) fn parse_return_value(
        &self,
        which: usize,
    ) -> Result<Vec<ColoredString>, ColoredString> {
        if self.is_exiting() {
            return Ok(vec![]);
        }
        let register_value = self.result.0.unwrap();
        let annotation = self.result.1;
        let sys_return = self.result.2;
        let mut output: Vec<ColoredString> = Vec::new();

        use SysReturn::*;
        let err: syscalls::Errno = unsafe { std::mem::transmute(self.errno) };
        // println!("{:?}", err);
        let value: ColoredString = match sys_return {
            Numeric_Or_Errno => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let numeric_return = register_value as isize;
                if numeric_return == -1 {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{numeric_return}").yellow()
                }
            }
            Always_Successful_Numeric => format!("{}", register_value as isize).yellow(),
            Signal_Or_Errno(signal) => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let signal_num = register_value as isize;
                if signal_num == -1 {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{signal}").yellow()
                }
            }
            // because -1 is a valid priority, we have to check
            Priority_Or_Errno(errored) => {
                let priority = register_value as isize;
                if unsafe { errored.assume_init() } {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    priority.to_string().yellow()
                }
            }

            File_Descriptor_Or_Errno(fd) => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let fd_num = register_value as isize;
                if fd_num == -1 {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{fd}").yellow()
                }
            }

            Length_Of_Bytes_Specific_Or_Errno => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let bytes = register_value as isize;
                if bytes == -1 {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{bytes} Bytes").yellow()
                }
            }
            Address_Or_Errno(address) => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());

                let pointer = register_value as isize;
                if pointer == -1 {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{:p}", pointer as *const ()).yellow()
                }
            }
            Address_Or_MAP_FAILED_Errno(address) => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let pointer = register_value as *mut c_void;
                if pointer == MAP_FAILED {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{:p}", pointer as *const ()).yellow()
                }
            }
            Address_Or_Errno_getcwd(current_working_dir) => {
                output.push(annotation[which].dimmed());
                output.push(": ".dimmed());
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    return Err(self
                        .errno
                        .unwrap_or_else(|| Errno::UnknownErrno)
                        .to_string()
                        .red());
                } else {
                    format!("{current_working_dir}").yellow()
                }
            }
            Always_Successful_User_Group => {
                let result = register_value as isize;
                format!("{result}").yellow()
            }
            Never_Returns => format!("never returns").yellow(),
            Always_Succeeds => format!("").yellow(),
            Does_Not_Return_Anything => {
                // println!("Does_Not_Return_Anything");
                format!("").yellow()
            }
        };
        output.push(value);
        Ok(output)
    }
    pub(crate) fn is_exiting(&self) -> bool {
        self.sysno == Sysno::exit || self.sysno == Sysno::exit_group
    }

    fn style_file_descriptor(register_value: u64, child: Pid) -> Option<String> {
        let fd = register_value as RawFd;
        let mut string = Vec::new();
        if fd < 0 {
            return None;
        } else if fd == 0 {
            string.push("0 -> StdIn".custom_color(PAGES_COLOR.get()));
        } else if fd == 1 {
            string.push("1 -> StdOut".custom_color(PAGES_COLOR.get()));
        } else if fd == 2 {
            string.push("2 -> StdErr".custom_color(PAGES_COLOR.get()));
        } else {
            let file_info = procfs::process::FDInfo::from_raw_fd(child.into(), fd);
            match file_info {
                Ok(file) => match file.target {
                    procfs::process::FDTarget::Path(path) => {
                        string.push(format!("{} -> ", file.fd).custom_color(PAGES_COLOR.get()));
                        let mut formatted_path = vec![];
                        static_handle_path_file(
                            path.to_string_lossy().into_owned(),
                            &mut formatted_path,
                        );
                        for path_part in formatted_path {
                            string.push(path_part);
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
                                        string.push(
                                            format!(
                                                "{} -> localhost:{}",
                                                file.fd,
                                                entry.remote_address.port()
                                            )
                                            .custom_color(PAGES_COLOR.get()),
                                        );
                                    } else {
                                        string.push(
                                            format!(
                                                "{} -> {:?}:{}",
                                                file.fd,
                                                entry.remote_address.ip(),
                                                entry.remote_address.port()
                                            )
                                            .custom_color(PAGES_COLOR.get()),
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
                                    string.push(
                                        format!("{} -> Unix Domain Socket", file.fd)
                                            .custom_color(PAGES_COLOR.get()),
                                    );
                                    break 'lookup;
                                }
                            }
                        }
                    }
                    procfs::process::FDTarget::Net(net) => {
                        // println!("net: {}", net);
                        string.push(format!("NET").bright_magenta())
                    }
                    procfs::process::FDTarget::Pipe(pipe) => {
                        string.push(
                            format!("{} -> Unix Pipe", file.fd).custom_color(PAGES_COLOR.get()),
                        );
                    }
                    procfs::process::FDTarget::AnonInode(anon_inode) => {
                        // anon_inode is basically a file that has no corresponding inode
                        // anon_inode could've been something that was a file but is no longer on the disk
                        // For file descriptors that have no corresponding inode
                        // (e.g., file descriptors produced by
                        // epoll_create(2), eventfd(2), inotify_init(2), signalfd(2), and timerfd(2)),
                        // the entry will be a symbolic link with contents "anon_inode:<file-type>"
                        // An anon_inode shows that there's a file descriptor which has no referencing inode

                        // At least in some contexts, an anonymous inode is
                        // an inode without an attached directory entry.
                        // The easiest way to create such an inode is as such:
                        //          int fd = open( "/tmp/file", O_CREAT | O_RDWR, 0666 );
                        //          unlink( "/tmp/file" );
                        // Note that the descriptor fd now points to an inode that has no filesystem entry; you
                        // can still write to it, fstat() it, etc. but you can't find it in the filesystem.
                        string.push(
                            format!("{} -> Anonymous Inode", file.fd)
                                .custom_color(PAGES_COLOR.get()),
                        );
                    }
                    procfs::process::FDTarget::MemFD(mem_fd) => {
                        string
                            .push(format!("{} -> MemFD", file.fd).custom_color(PAGES_COLOR.get()));
                    }
                    procfs::process::FDTarget::Other(first, second) => {
                        string
                            .push(format!("{} -> Other", file.fd).custom_color(PAGES_COLOR.get()));
                    }
                },
                Err(_) => {}
            }
        }
        Some(String::from_iter(string.into_iter().map(|x| x.to_string())))
    }
    pub(crate) fn style_bytes_page_aligned_ceil(register_value: u64) -> String {
        let bytes = BytesPagesRelevant::from_ceil(register_value as usize);
        bytes.to_string()
    }
    fn style_bytes_page_aligned_floor(register_value: u64) -> String {
        let bytes = BytesPagesRelevant::from_floor(register_value as usize);
        bytes.to_string()
    }

    fn style_bytes(register_value: u64) -> String {
        let bytes_amount = register_value as usize;
        let mut bytes = Bytes::norm(bytes_amount);
        if bytes_amount as f64 / 1_000_000_000.0 > 1.0 {
            bytes = Bytes::giga(bytes_amount as f64 / 1_000_000_000.0)
        } else if bytes_amount as f64 / 1_000_000.0 > 1.0 {
            bytes = Bytes::mega(bytes_amount as f64 / 1_000_000.0)
        } else if bytes_amount as f64 / 1_000.0 > 1.0 {
            bytes = Bytes::kilo(bytes_amount as f64 / 1_000.0)
        }
        bytes.to_string()
    }
    pub(crate) fn style_bytes_length_specific(register_value: u64) -> String {
        let bytes_amount = register_value as usize;
        let mut bytes = Bytes::norm(bytes_amount);
        if bytes_amount / 1_000_000_000 > 1 {
            bytes = Bytes::giga(bytes_amount as f64 / 1_000_000_000.0)
        } else if bytes_amount / 1_000_000 > 1 {
            bytes = Bytes::mega(bytes_amount as f64 / 1_000_000.0)
        } else if bytes_amount / 1_000 > 1 {
            bytes = Bytes::kilo(bytes_amount as f64 / 1_000.0)
        }
        bytes.to_string()
    }

    fn handle_flag(register_value: u64, flag: Flag) -> String {
        use Flag::*;
        match flag {
            Map => {
                let bitmap: MapFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[9..string.len() - 1])
            }
            Prot => {
                let bitmap: ProtFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[10..string.len() - 1])
            }
            Open => {
                let bitmap: OFlag = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[6..string.len() - 1])
            }
            FileMode => {
                let bitmap: Mode = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[5..string.len() - 1])
            }
            ReMap => {
                let bitmap: MRemapFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[12..string.len() - 1])
            }
            MSync => {
                let bitmap: MsFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[8..string.len() - 1])
            }
            Madvise => {
                let bitmap: MmapAdvise = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", string)
            }
            Access => {
                let bitmap: AccessFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[12..string.len() - 1])
            }
            P_RW_V2_Flags => {
                let bitmap: ReadWriteFlags = unsafe { std::mem::transmute(register_value as u32) };
                let string = format!("{:?}", bitmap);
                format!("{}", &string[15..string.len() - 1])
            }
            LSeekWhence => {
                let bitmap: Whence = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            Signal => {
                let a = [
                    2, 3, 4, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 27, 28, 29, 30, 31, 31,
                ];
                if !a.contains(&(register_value as i32)) {
                    format!("unsupported signal")
                } else {
                    let bitmap: nix::sys::signal::Signal =
                        unsafe { std::mem::transmute(register_value as i32) };
                    format!("{:?}", bitmap)
                }
                // for i in a {
                //     let bitmap: nix::sys::signal::Signal = unsafe { std::mem::transmute(i) };
                //     println!("{:?}", bitmap);
                //     println!("fycjubg good");
                // }
            }
            SignalHow => {
                let bitmap: nix::sys::signal::SigmaskHow =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            SignalFDFlags => {
                let bitmap: SfdFlags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            EPollCreate1Flags => {
                #[derive(Debug)]
                #[repr(C)]
                enum epollcreateflags {
                    EPOLL_CLOEXEC,
                }
                let bitmap: epollcreateflags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            EPollCTLOperationFlags => {
                #[derive(Debug)]
                #[repr(C)]
                enum epollctlflags {
                    EPOLL_CTL_ADD,
                    EPOLL_CTL_MOD,
                    EPOLL_CTL_DEL,
                }
                let bitmap: epollctlflags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }

            SocketFamily => {
                let bitmap: nix::sys::socket::AddressFamily =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            SocketType => {
                // Since  Linux  2.6.27,  the type argument serves a second purpose:
                // in addition to specifying a socket type,
                // it may include the bitwise OR of any of the following values,
                // to modify the behavior of socket():

                // SOCK_NONBLOCK   Set the O_NONBLOCK file status flag on the open file description (see open(2)) referred to by the new file descriptor.  Using this flag saves  extra  calls
                //                 to fcntl(2) to achieve the same result.
                // SOCK_CLOEXEC    Set  the close-on-exec (FD_CLOEXEC) flag on the new file descriptor.  See the description of the O_CLOEXEC flag in open(2) for reasons why this may be use‐
                //                 ful.

                // two flags 1 register is crazy
                // so we separate
                let all_flags: u32 = unsafe { std::mem::transmute(SockFlag::all()) };
                let register_sockflag = register_value as u32 & all_flags;

                let register_socktype = register_value as u32 ^ register_sockflag;

                let bitmap_sockflag: nix::sys::socket::SockFlag =
                    unsafe { std::mem::transmute(register_sockflag) };

                let bitmap_socktype: nix::sys::socket::SockType =
                    unsafe { std::mem::transmute(register_socktype) };

                let string_sockflag = format!("{:?}", bitmap_sockflag);
                let string_socktype = format!("{:?}", bitmap_socktype);

                format!(
                    "{}, {}",
                    string_socktype,
                    &string_sockflag[9..string_sockflag.len() - 1],
                    // string_sockflag,
                    // &string_socktype[9..string_socktype.len() - 1]
                )
            }
            SocketFlag => {
                // this is the smaller flag taken in consideration
                // in the above match
                let bitmap: nix::sys::socket::SockFlag =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            SocketOption => {
                // let bitmap: nix::sys::socket::Op =
                //     unsafe { std::mem::transmute(register_value as u32) };
                // format!("{:?}", bitmap)
                format!("")
            }
            SocketLevel => {
                // let bitmap: nix::sys::socket:: =
                //     unsafe { std::mem::transmute(register_value as u32) };
                // format!("{:?}", bitmap)
                format!("")
            }
            SocketProtocol => {
                let bitmap: nix::sys::socket::SockProtocol =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            ReservedForFutureUse => {
                format!("Flag currently ignored, butreserved for future use")
            }
            SocketMessageFlag => {
                // let bitmap:  RecvFlags=
                //     unsafe { std::mem::transmute(register_value as u32) };
                // format!("{:?}", bitmap)
                format!("")
            }
            SocketMessageReceiveFlag => {
                // let bitmap: nix::sys::socket::SockProtocol =
                //     unsafe { std::mem::transmute(register_value as u32) };
                // format!("{:?}", bitmap)
                format!("")
            }
            MLock => {
                let bitmap: mlock2 = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            MLockAll => {
                let bitmap: nix::sys::mman::MlockAllFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            FileAtFlags => {
                let bitmap: AtFlags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            FileStatxFlags => {
                let bitmap: StatxFlags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            FileRenameFlags => {
                let bitmap: RenameFlags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            GetRandomFlags => {
                let bitmap: rustix::rand::GetRandomFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            RusageWhoFlags => {
                let bitmap: UsageWho = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            ResourceFlags => {
                let bitmap: Resource = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            FileChmodAtFlags => {
                let bitmap: FchmodatFlags = unsafe { std::mem::transmute(register_value as u8) };
                format!("{:?}", bitmap)
            }
            RSeqFlag => {
                // TODO! figure this out
                // let bitmap: ?? = unsafe { std::mem::transmute(register_value as u8) };
                format!("{:?}", "unknown flags for rseq")
            }
            FutexOpFlags => {
                let bitmap: FutexFlags = unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            SocketShutdownFlag => {
                let bitmap: rustix::net::Shutdown =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            EventfdFlag => {
                let bitmap: eventfd::EfdFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            FcntlFlags => {
                // TODO!
                // let bitmap: FcntlArg = unsafe { std::mem::transmute(register_value as u32) };
                format!("todo!")
            }
            ArchPrctlFlags => {
                // TODO!
                // let bitmap: FcntlArg = unsafe { std::mem::transmute(register_value as u32) };
                format!("todo!")
            }
            Dup3Flags => {
                let bitmap: rustix::io::DupFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            LandlockCreateFlag => {
                let bitmap: LandlockCreateFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            LandlockRuleTypeFlag => {
                let bitmap: LandlockRuleTypeFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            LandlockAddRuleFlag => {
                // TODO!
                // let bitmap: FcntlArg = unsafe { std::mem::transmute(register_value as u32) };
                format!("todo!")
            }
            LandlockRestrictFlag => {
                // TODO!
                // let bitmap: FcntlArg = unsafe { std::mem::transmute(register_value as u32) };
                format!("todo!")
            }
            FallocFlags => {
                let bitmap: nix::fcntl::FallocateFlags =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            PriorityWhich => {
                // TODO! was this flag nullable? check later
                //
                let which = register_value as u32;
                if (which & PRIO_PROCESS) == PRIO_PROCESS {
                    format!("PRIO_PROCESS")
                } else if (which & PRIO_PGRP) == PRIO_PGRP {
                    format!("PRIO_PGRP")

                // } else if (which & PRIO_USER) == PRIO_USER {
                } else {
                    format!("PRIO_USER")
                }
            }
            WaitIdTypeFlags => {
                let bitmap: nix::sys::wait::Id = unsafe { std::mem::transmute(register_value) };
                format!("{:?}", bitmap)
            }
            WaitEventFlags => {
                let bitmap: nix::sys::wait::WaitPidFlag =
                    unsafe { std::mem::transmute(register_value as u32) };
                format!("{:?}", bitmap)
            }
            CloneFlags => {
                let bitmap: clone3::Flags = unsafe { std::mem::transmute(register_value) };
                format!("{:?}", bitmap)
            }
        }
    }
    pub(crate) fn is_mem_alloc_dealloc(&self) -> bool {
        self.sysno == Sysno::brk || self.sysno == Sysno::mmap
    }
    // TODO! check how strace does this, maybe its better
    pub(crate) fn colorize_syscall_name(sysno: &Sysno, category: &Category) -> ColoredString {
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
            Category::Signals => sysno.name().bold().magenta(),
            Category::Device => sysno.name().bold().bright_yellow(),
            Category::AsyncIO => sysno.name().bold().purple(),
        }
    }
}
