#![allow(unused_variables)]
use crate::utilities::{colorize_general_text, REGISTERS};
use crate::{
    types::{
        mlock2, Bytes, BytesPagesRelevant, Category, Flag, LandlockCreateFlags,
        LandlockRuleTypeFlags, SysArg, SysReturn, Syscall_Shape,
    },
    utilities::{
        buffered_write, lose_relativity_on_path, static_handle_path_file, SYSCATEGORIES_MAP,
        SYSKELETON_MAP,
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

use syscalls::Sysno;
#[derive(Debug)]
pub struct SyscallObject {
    pub sysno: Sysno,
    pub category: Category,
    pub skeleton: Vec<SysArg>,
    pub result: (Option<u64>, SysReturn),
    pub process_pid: Pid,
    pub errno: Option<Errno>,
    pub state: SyscallState,
    pub paused: bool,
}

impl Default for SyscallObject {
    fn default() -> Self {
        SyscallObject {
            sysno: unsafe { mem::zeroed() },
            category: unsafe { mem::zeroed() },
            skeleton: vec![],
            result: unsafe { mem::zeroed() },
            process_pid: unsafe { mem::zeroed() },
            errno: unsafe { mem::zeroed() },
            state: SyscallState::Entering,
            paused: false,
        }
    }
}

impl SyscallObject {
    pub fn format(&mut self) {
        let sysno = self.sysno;

        if let Ok(_) = self.one_line_formatter() {
            // let mut string = String::new();
            // for string_portion in &mut self.one_line {
            //     string.push_str(&format!("{}", string_portion));
            // }
            // print!("{}", string)
        } else {
            // disabled for now
            // switch to syscallobject_annotation formatting
            // let mut annot_variant = SyscallObject_Annotations::from(self);
            // annot_variant.format()
        }
    }

    fn replace_content(&mut self, index: usize, sys_arg: SysArg) {
        self.skeleton[index] = sys_arg
    }

    #[inline(always)]
    pub(crate) fn general_text(&mut self, arg: &str) {
        colorize_general_text(arg);
    }

    pub(crate) fn write_text(&self, text: ColoredString) {
        buffered_write(text);
    }
}

impl SyscallObject {
    pub(crate) fn get_sysno(orig_rax: i32) -> Sysno {
        // println!("{:?}", registers.orig_rax as i32);
        Sysno::from(orig_rax)
    }
    pub(crate) fn build(child: Pid, sysno: Sysno) -> Option<Self> {
        let syscall = match SYSKELETON_MAP.get(&sysno) {
            Some(&Syscall_Shape {
                types,
                syscall_return,
            }) => {
                let category = *SYSCATEGORIES_MAP.get(&sysno).unwrap();
                return Some(match types.len() {
                    0 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    1 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    2 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    3 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    4 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    5 => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                    _ => SyscallObject {
                        sysno,
                        category,
                        skeleton: types.into_iter().cloned().collect(),
                        result: (None, syscall_return),
                        process_pid: child,
                        errno: None,
                        ..Default::default()
                    },
                });
            }
            None => {
                return None;
                // // unsafe {
                // //     if !UNSUPPORTED.contains(&sysno.name()) {
                // //         UNSUPPORTED.push(sysno.name());
                // //     }
                // // }
                // SyscallObject {
                //     sysno,
                //     category: Category::Process,
                //     args: vec![],
                //     result: (None, SysReturn::File_Descriptor_Or_Errno("")),
                //     process_pid: child,
                //     errno: None,
                //     ..Default::default()
                // }
            }
        };
        syscall
    }
    // basically fill up all the parentheses data
    pub(crate) fn get_precall_data(&mut self) {
        // POPULATING ARGUMENTS
        //
        //
        //
        for index in 0..self.skeleton.len() {
            use SysArg::*;
            match self.skeleton[index] {
                File_Descriptor(ref mut file_descriptor) => {
                    let fd = REGISTERS.get()[index] as i32;

                    let styled_fd = SyscallObject::style_file_descriptor(
                        REGISTERS.get()[index],
                        self.process_pid,
                    )
                    .unwrap_or(format!("ignored"));
                    *file_descriptor = styled_fd.leak();
                }
                File_Descriptor_openat(ref mut file_descriptor) => {
                    let mut styled_fd = String::new();
                    let fd = REGISTERS.get()[index] as i32;
                    styled_fd = if fd == AT_FDCWD {
                        format!("{}", "AT_FDCWD -> Current Working Directory".bright_blue())
                    } else {
                        SyscallObject::style_file_descriptor(
                            REGISTERS.get()[index],
                            self.process_pid,
                        )
                        .unwrap_or(format!("ignored"))
                    };
                    *file_descriptor = styled_fd.leak();
                }
                Pointer_To_Text(ref mut text) => {
                    // TODO! fix this
                    let mut styled_fd = String::new();
                    if self.sysno == Sysno::execve {
                        continue;
                    }
                    if self.sysno == Sysno::write || self.sysno == Sysno::pwrite64 {
                        if REGISTERS.get()[2] < 20 {
                            match SyscallObject::read_string_specific_length(
                                REGISTERS.get()[1] as usize,
                                self.process_pid,
                                REGISTERS.get()[2] as usize,
                            ) {
                                Some(styled_fd) => {
                                    *text = styled_fd.leak();
                                }
                                None => (),
                            }
                            continue;
                        }
                    }
                    let styled_fd = SyscallObject::string_from_pointer(
                        REGISTERS.get()[index],
                        self.process_pid,
                    );
                    *text = styled_fd.leak();
                }
                Array_Of_Strings(ref mut text) => {
                    // TODO! fix this
                    if self.sysno == Sysno::execve {
                        continue;
                    }
                    let array_of_texts = SyscallObject::string_from_array_of_strings(
                        REGISTERS.get()[index],
                        self.process_pid,
                    );
                    let mut svec: Vec<&'static str> = vec![];
                    for text in array_of_texts {
                        svec.push(text.leak());
                    }
                    *text = Box::leak(svec.into_boxed_slice());
                }
                _ => {}
            };
        }
    }

    pub(crate) fn get_postcall_data(&mut self) {
        // POPULATING ARGUMENTS
        //
        //
        //
        let len = self.skeleton.len();
        for index in 0..len {
            use SysArg::*;
            match self.skeleton[index] {
                Pointer_To_File_Descriptor_Array(
                    [ref mut file_descriptor1, ref mut file_descriptor2],
                ) => {
                    match SyscallObject::read_two_word(
                        REGISTERS.get()[index] as usize,
                        self.process_pid,
                    ) {
                        Some([ref mut fd1, ref mut fd2]) => {
                            let styled_fd1 =
                                SyscallObject::style_file_descriptor(*fd1 as u64, self.process_pid)
                                    .unwrap_or(format!("ignored"));
                            let styled_fd2 =
                                SyscallObject::style_file_descriptor(*fd2 as u64, self.process_pid)
                                    .unwrap_or(format!("ignored"));
                            *file_descriptor1 = styled_fd1.leak();
                            *file_descriptor2 = styled_fd2.leak();
                        }
                        None => {
                            *file_descriptor1 = "could not get fd";
                            *file_descriptor2 = "could not get fd";
                        }
                    }
                }
                Pointer_To_Numeric(ref mut pid) => {
                    match SyscallObject::read_word(
                        REGISTERS.get()[index] as usize,
                        self.process_pid,
                    ) {
                        Some(pid_at_word) => {
                            if self.sysno == Sysno::wait4 {
                                self.skeleton[1] = Pointer_To_Numeric(Some(pid_at_word))
                                // self.skeleton[1] = Pointer_To_Numeric(Some(pid_at_word));
                            }
                        }
                        None => {
                            // p!("reading numeric failed");
                        }
                    }
                }
                Pointer_To_Numeric_Or_Numeric(ref mut pid) => {
                    // this is only available for arch_prctl
                    let operation = REGISTERS.get()[0];
                    let addr = REGISTERS.get()[0];
                    // workaround values for now
                    let ARCH_SET_GS = 0x1001;
                    let ARCH_SET_FS = 0x1002;
                    let ARCH_GET_FS = 0x1003;
                    let ARCH_GET_GS = 0x1004;
                    let ARCH_GET_CPUID = 0x1011;
                    let ARCH_SET_CPUID = 0x1012;

                    // if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID ||(operation & ARCH_SET_FS) == ARCH_SET_FS ||(operation & ARCH_SET_GS) == ARCH_SET_GS  {
                    // } else

                    if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID
                        || (operation & ARCH_GET_FS) == ARCH_GET_FS
                        || (operation & ARCH_GET_GS) == ARCH_GET_GS
                    {
                        match SyscallObject::read_word(
                            REGISTERS.get()[index] as usize,
                            self.process_pid,
                        ) {
                            Some(pid_at_word) => {
                                if self.sysno == Sysno::wait4 {
                                    self.skeleton[1] =
                                        Pointer_To_Numeric_Or_Numeric(Some(pid_at_word));
                                }
                            }
                            None => {
                                // p!("reading numeric failed");
                            }
                        }
                    }
                }
                Pointer_To_Text(ref mut text) => {
                    // TODO! fix this
                    if self.sysno == Sysno::readlink || self.sysno == Sysno::readlinkat {
                        // let a = nix::errno::Errno::EINVAL
                        if self.errno.is_some() {
                            continue;
                        }
                        let size = self.result.0.unwrap();
                        if size > 0 {
                            if size > 100 {
                                let size = -1 * (size as i32);
                                let error = nix::errno::Errno::from_raw(size);
                            } else {
                                if self.sysno == Sysno::readlink && index == 1 {
                                    match SyscallObject::read_string_specific_length(
                                        REGISTERS.get()[index] as usize,
                                        self.process_pid,
                                        size as usize,
                                    ) {
                                        Some(styled_fd) => self
                                            .replace_content(1, Pointer_To_Text(styled_fd.leak())),
                                        None => (),
                                    }
                                } else if self.sysno == Sysno::readlinkat && index == 2 {
                                    match SyscallObject::read_string_specific_length(
                                        REGISTERS.get()[index] as usize,
                                        self.process_pid,
                                        size as usize,
                                    ) {
                                        Some(styled_fd) => self
                                            .replace_content(1, Pointer_To_Text(styled_fd.leak())),
                                        None => (),
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // POPULATING RETURN
        //
        //
        //
        let (register, ref mut sys_return) = self.result;
        use SysReturn::*;
        match sys_return {
            File_Descriptor_Or_Errno(data) => {
                let fd = register.unwrap();
                let styled_fd = SyscallObject::style_file_descriptor(fd, self.process_pid)
                    .unwrap_or(format!("{:?}", self.errno));
                *data = styled_fd.leak();
            }

            Address_Or_Errno_getcwd(data) => {
                let styled_string =
                    SyscallObject::string_from_pointer(REGISTERS.get()[0], self.process_pid);
                *data = styled_string.leak();
            }
            Priority_Or_Errno(errored) => {
                // TODO!
                // we expect errno to have been set to zero before this syscall ran
                // this means we now just check errno
                // and if its -1, then the syscall errored
                //
                // check if process has errored
                let pointer = REGISTERS.get()[0];
                if errno::errno().0 == -1 {
                    unsafe { errored.as_mut_ptr().write(true) };
                } else {
                    unsafe { errored.as_mut_ptr().write(false) };
                }
            }
            _ => {}
        };
    }
    // previously `parse_arg_value_for_one_line`
    pub(crate) fn displayable_ol(&self, index: usize) -> String {
        let register_value = REGISTERS.get()[index];
        use SysArg::*;
        match self.skeleton[index] {
            // NUMERICS
            Numeric => (register_value as isize).to_string(),
            PID => (register_value as isize).to_string(),
            User_Group => (register_value as isize).to_string(),
            Unsigned_Numeric => format!("{register_value}"),
            File_Descriptor(fd) => (fd).to_string(),
            File_Descriptor_openat(fd) => (fd).to_string(),
            Pointer_To_File_Descriptor_Array([fd1, fd2]) => {
                format!("read end: {fd1}, write end: {fd2}")
            }
            // FLAG
            General_Flag(flag) => SyscallObject::handle_flag(register_value, flag),
            // BYTES
            Length_Of_Bytes => SyscallObject::style_bytes(register_value),
            Length_Of_Bytes_Specific => {
                format!("{register_value} Bytes")
            }
            Length_Of_Bytes_Page_Aligned_Ceil => {
                SyscallObject::style_bytes_page_aligned_ceil(register_value)
            }
            Length_Of_Bytes_Page_Aligned_Floor => {
                SyscallObject::style_bytes_page_aligned_floor(register_value)
            }
            // Signed_Length_Of_Bytes_Specific => {
            //     SyscallObject::style_bytes_signed(register_value)
            // }
            Pointer_To_Struct => "0x.. -> {..}".to_owned(),
            Array_Of_Struct => "[ {..}, {..} , {..} ]".to_owned(),
            Array_Of_Strings(array) => {
                let mut string = String::new();
                for text in array {
                    string.push_str(&text);
                    string.push(' ');
                }
                string
            }
            Byte_Stream => format!("whatever"),
            Single_Word => {
                let pointer = register_value as *const ();
                format!("{:p}", pointer)
            }
            Pointer_To_Numeric(pid) => {
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    format!("0xNull")
                } else {
                    let pid = pid.unwrap();
                    format!("{pid}")
                    // format!("{pointer:p} -> {pid}")
                }
                // let pointer = register_value as *const i64;
                // let reference: &i64 = unsafe { transmute(pointer) };
            }
            Pointer_To_Numeric_Or_Numeric(numeric) => {
                if numeric.is_none() {
                    format!("")
                } else {
                    let num = numeric.unwrap();
                    format!("{num}")
                }
            }
            Pointer_To_Unsigned_Numeric => {
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    format!("0xNull")
                } else {
                    format!("{:p}", pointer)
                }
                // let pointer = register_value as *const u64;
                // let reference: &u64 = unsafe { transmute(pointer) };
            }
            Pointer_To_Text(text) => {
                format!("{}", text)
            }
            Pointer_To_Path(text) => {
                format!("{}", text)
            }
            Address => {
                let pointer = register_value as *const ();
                if pointer == std::ptr::null() {
                    format!("0xNull")
                } else {
                    format!("{:p}", pointer)
                }
            }
            Pointer_To_Length_Of_Bytes_Specific => String::from("did not handle this yet"),
            Multiple_Flags([flag1, flag2]) => {
                SyscallObject::handle_flag(register_value, flag1)
                // SyscallObject::handle_multi_flags(register_value, flag1, flag2)
            }
        }
    }
    pub(crate) fn displayable_return_ol(&self) -> Result<String, ()> {
        if self.is_exiting() {
            return Ok("".to_owned());
        }
        let sys_return = self.result.1;
        let register_value = self.result.0.unwrap();
        use SysReturn::*;

        match sys_return {
            Numeric_Or_Errno => {
                let numeric_return = register_value as isize;
                if numeric_return + 1 == -1 {
                    Err(())
                } else {
                    Ok(format!("{numeric_return}"))
                }
            }
            Always_Successful_Numeric => Ok(format!("{}", register_value as isize)),
            Signal_Or_Errno(signal) => {
                let signal_num = register_value as isize;
                if signal_num + 1 == -1 {
                    Err(())
                } else {
                    Ok(format!("{signal}"))
                }
            }
            File_Descriptor_Or_Errno(fd) => {
                let fd_num = register_value as isize;
                if fd_num + 1 == -1 {
                    Err(())
                } else {
                    Ok(format!("{fd}"))
                }
            }
            Priority_Or_Errno(errored) => {
                let priority = register_value as isize;
                if unsafe { errored.assume_init() } {
                    Err(())
                } else {
                    Ok(format!("{priority}"))
                }
            }
            Length_Of_Bytes_Specific_Or_Errno => {
                let bytes = register_value as isize;
                if self.sysno == Sysno::readlink || self.sysno == Sysno::readlinkat {
                    if self.errno.is_some() {
                        return Err(());
                    }
                }
                if bytes + 1 == -1 {
                    Err(())
                } else {
                    Ok(format!("{bytes} Bytes"))
                }
            }
            Address_Or_Errno(address) => {
                let address_value = register_value as isize;
                if address_value + 1 == -1 {
                    Err(())
                } else {
                    Ok(format!("{:p}", address_value as *const ()))
                }
            }
            Address_Or_MAP_FAILED_Errno(address) => {
                let pointer = register_value as *mut c_void;
                if pointer == MAP_FAILED {
                    Err(())
                } else {
                    Ok(format!("{:p}", pointer as *const ()))
                }
            }
            Address_Or_Errno_getcwd(current_working_dir) => {
                let pointer = register_value as *const ();
                if pointer.is_null() {
                    Err(())
                } else {
                    Ok(format!("{current_working_dir}",))
                }
            }
            Ptrace_Diverse_Or_Errno => {
                // a successful PTRACE_PEEK might return -1 so errno must be cleared before the call
                let ptrace_return = register_value as i64;
                if ptrace_return == -1 {
                    Err(())
                } else {
                    Ok(format!("{ptrace_return}"))
                }
            }
            Always_Successful_User_Group => {
                let result = register_value as isize;
                Ok(format!("{result}"))
            }
            Never_Returns => Ok(format!("never returns")),
            Always_Succeeds => {
                unimplemented!()
            }
            Does_Not_Return_Anything => {
                // println!("Does_Not_Return_Anything");
                Ok(format!(""))
            }
            Always_Errors => Err(()),
        }
    }
    fn style_file_descriptor(register_value: u64, child: Pid) -> Option<String> {
        let fd = register_value as RawFd;
        let mut string = Vec::new();
        if fd < 0 {
            return None;
        } else if fd == 0 {
            string.push("0 -> StdIn".bright_blue());
        } else if fd == 1 {
            string.push("1 -> StdOut".bright_blue());
        } else if fd == 2 {
            string.push("2 -> StdErr".bright_blue());
        } else {
            let file_info = procfs::process::FDInfo::from_raw_fd(child.into(), fd);
            match file_info {
                Ok(file) => match file.target {
                    procfs::process::FDTarget::Path(path) => {
                        string.push(format!("{} -> ", file.fd).bright_blue());
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
                                            .bright_blue(),
                                        );
                                    } else {
                                        string.push(
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
                                    string.push(
                                        format!("{} -> Unix Domain Socket", file.fd).bright_blue(),
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
                        string.push(format!("{} -> Unix Pipe", file.fd).bright_blue());
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
                        string.push(format!("{} -> Anonymous Inode", file.fd).bright_blue());
                    }
                    procfs::process::FDTarget::MemFD(mem_fd) => {
                        string.push(format!("{} -> MemFD", file.fd).bright_blue());
                    }
                    procfs::process::FDTarget::Other(first, second) => {
                        string.push(format!("{} -> Other", file.fd).bright_blue());
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

    // Use process_vm_readv(2)
    fn string_from_pointer(address: u64, child: Pid) -> String {
        // TODO! execve multi-threaded fails here for some reason
        match SyscallObject::read_bytes_until_null(address as usize, child) {
            Some(data) => String::from_utf8_lossy(&data).into_owned(),
            None => "".to_owned(),
        }
    }
    fn string_from_array_of_strings(address: u64, child: Pid) -> Vec<String> {
        // TODO! execve fails this
        let mut array = SyscallObject::read_words_until_null(address as usize, child).unwrap();
        let mut strings = vec![];
        for char_pointer in array {
            let string = SyscallObject::string_from_pointer(char_pointer, child);
            strings.push(string);
        }
        strings
    }

    pub(crate) fn read_word(addr: usize, child: Pid) -> Option<usize> {
        let remote_iov = RemoteIoVec { base: addr, len: 1 };
        let mut bytes_buffer = vec![0u8; 4];
        match process_vm_readv(
            child,
            &mut [IoSliceMut::new(&mut bytes_buffer)],
            &[remote_iov],
        ) {
            Ok(_) => Some(unsafe { mem::transmute(&bytes_buffer) }),
            Err(err) => None,
        }
    }

    pub(crate) fn read_bytes_specific_length(
        base: usize,
        child: Pid,
        len: usize,
    ) -> Option<Vec<u8>> {
        let remote_iov = RemoteIoVec { base, len };
        let mut bytes_buffer = vec![0u8; len];
        // Note, however, that these system calls
        // do not check the memory regions in the remote process
        // until just before doing the read/write.
        // Consequently, a partial read/write (see RETURN VALUE) may result
        // if one of the remote_iov elements points to an invalid memory region in the remote process.
        // No further reads/writes will be attempted beyond that point.
        //
        // Keep this in mind when attempting to read data of unknown length
        // (such as C strings that are null-terminated) from a remote process,
        // by avoiding spanning memory pages (typically 4 KiB)
        // in a single remote iovec element.
        // (Instead, split the remote read into two remote_iov elements
        // and have them merge back into a single write local_iov entry.
        // The first read entry goes up to the page boundary,
        match process_vm_readv(
            child,
            &mut [IoSliceMut::new(&mut bytes_buffer)],
            &[remote_iov],
        ) {
            Ok(_) => Some(bytes_buffer),
            Err(err) => None,
        }
    }

    pub(crate) fn read_string_specific_length(
        addr: usize,
        child: Pid,
        size: usize,
    ) -> Option<String> {
        let bytes_buffer = SyscallObject::read_bytes_specific_length(addr, child, size)?;
        Some(String::from_utf8_lossy(&bytes_buffer).into_owned())
    }

    pub(crate) fn read_bytes<const N: usize>(addr: usize, child: Pid) -> Option<[u8; N]> {
        let mut addr = addr as *mut c_void;
        let mut data: [u8; N] = [0; N];
        let mut i = 0;
        'reading: loop {
            match ptrace::read(child, addr) {
                Ok(word) => {
                    let bytes: [u8; 8] = unsafe { std::mem::transmute(word) };
                    for byte in bytes {
                        if i == N {
                            break 'reading;
                        }
                        data[i] = byte;
                        i += 1
                    }
                    addr = unsafe { addr.byte_add(8) };
                }
                Err(res) => {
                    return None;
                }
            };
        }
        Some(data)
    }
    pub(crate) fn read_words_until_null(address: usize, child: Pid) -> Option<Vec<u64>> {
        let mut addr: *mut std::ffi::c_void = address as *mut c_void;
        let mut data = vec![];
        'read_loop: loop {
            match ptrace::read(child, addr) {
                Ok(word) => {
                    if word == 0 {
                        break 'read_loop;
                    }
                    data.push(word as u64);
                    addr = unsafe { addr.byte_add(8) };
                }
                Err(res) => {
                    return None;
                }
            };
        }
        Some(data)
    }
    pub(crate) fn read_bytes_until_null(address: usize, child: Pid) -> Option<Vec<u8>> {
        let mut addr: *mut std::ffi::c_void = address as *mut c_void;
        let mut data = vec![];
        'read_loop: loop {
            match ptrace::read(child, addr) {
                Ok(word) => {
                    let bytes: [u8; 8] = unsafe { std::mem::transmute(word) };
                    for byte in bytes {
                        if byte == b'\0' {
                            break 'read_loop;
                        }
                        data.push(byte);
                    }
                    addr = unsafe { addr.byte_add(8) };
                }
                Err(res) => {
                    return None;
                }
            };
        }
        Some(data)
    }
    pub(crate) fn read_specific<const N: usize>(addr: usize, child: Pid) -> Option<[u8; N]> {
        let mut addr = addr as *mut c_void;
        let mut data: [u8; N] = [0; N];
        let mut i = 0;
        'read_loop: while i < N {
            match ptrace::read(child, addr) {
                Ok(word) => {
                    let bytes: [u8; 8] = unsafe { std::mem::transmute(word) };
                    for byte in bytes {
                        if i == N {
                            break 'read_loop;
                        }
                        data[i] = byte;
                        i += 1
                    }
                    addr = unsafe { addr.byte_add(8) };
                }
                Err(res) => {
                    return None;
                }
            };
        }
        Some(data)
    }
    pub(crate) fn read_bytes_as_struct<const N: usize, T>(addr: usize, child: Pid) -> Option<T> {
        match SyscallObject::read_bytes_specific_length(addr, child, N) {
            Some(vec) => {
                let arr: [u8; N] = vec.try_into().unwrap();
                Some(unsafe { std::mem::transmute_copy(&arr) })
            }
            None => todo!(),
        }
        // match SyscallObject::read_bytes::<N>(addr, child) {
        //     Some(bytes) => Some(unsafe { std::mem::transmute_copy(&bytes) }),
        //     None => None,
        // }
    }
    pub(crate) fn write_bytes<const N: usize>(
        addr: usize,
        child: Pid,
        data: [u64; N],
    ) -> Result<(), ()> {
        let mut addr = addr as *mut c_void;
        for word in data {
            match ptrace::write(child, addr, word as _) {
                Ok(_void) => {
                    addr = unsafe { addr.byte_add(8) };
                }
                Err(res) => return Err(()),
            };
        }
        Ok(())
    }

    pub(crate) fn read_two_word(addr: usize, child: Pid) -> Option<[i32; 2]> {
        let mut addr = addr as *mut c_void;
        match ptrace::read(child, addr) {
            Ok(word) => Some(unsafe { transmute(word) }),
            Err(res) => None,
        }
    }

    pub(crate) fn read_affinity_from_child(addr: usize, child: Pid) -> Option<Vec<usize>> {
        const CPU_SET_USIZE: usize = (CPU_SETSIZE / 8) as usize;

        let cpu_mask = SyscallObject::read_bytes_specific_length(addr, child, CPU_SET_USIZE)?;

        let a: [u8; CPU_SET_USIZE] = cpu_mask.try_into().ok()?;

        let cpu_set: cpu_set_t = unsafe { transmute(a) };

        let mut vec = Vec::new();
        for cpu_number in 0..num_cpus::get() as usize {
            if unsafe { CPU_ISSET(cpu_number, &cpu_set) } {
                vec.push(cpu_number)
            }
        }
        Some(vec)
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
            PtraceOperation => {
                let bitmap: nix::sys::ptrace::Request =
                    unsafe { std::mem::transmute(register_value as i32) };
                format!("{:?}", bitmap)
            }
        }
    }
    pub(crate) fn is_mem_alloc_dealloc(&self) -> bool {
        self.sysno == Sysno::brk || self.sysno == Sysno::mmap
    }
    pub(crate) fn is_exiting(&self) -> bool {
        self.sysno == Sysno::exit || self.sysno == Sysno::exit_group
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
