use std::{
    env::current_dir,
    io::Write,
    mem,
    os::fd::RawFd,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use crate::{
    syscall_object::SyscallObject,
    types::{Bytes, BytesPagesRelevant, LandlockRuleTypeFlags},
    utilities::{
        buffered_write, colorize_general_text, errno_to_string, get_child_memory_break,
        get_mem_difference_from_previous, lose_relativity_on_path, parse_register_as_address,
        where_in_childs_memory, x86_signal_to_string, CONTINUED_COLOR, FOLLOW_FORKS, OUR_YELLOW,
        PAGES_COLOR, PID_NUMBER_COLOR, REGISTERS,
    },
};
use colored::{Color, ColoredString, Colorize};
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FallocateFlags},
    libc::{
        cpu_set_t, iovec, msghdr, pid_t, rlimit, sigaction, timespec, timeval, AT_EMPTY_PATH,
        AT_FDCWD, AT_NO_AUTOMOUNT, AT_REMOVEDIR, AT_STATX_DONT_SYNC, AT_STATX_FORCE_SYNC,
        AT_STATX_SYNC_AS_STAT, AT_SYMLINK_NOFOLLOW, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL,
        EPOLL_CTL_MOD, FUTEX_CLOCK_REALTIME, FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI, FUTEX_FD,
        FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE, FUTEX_TRYLOCK_PI,
        FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAKE,
        FUTEX_WAKE_BITSET, FUTEX_WAKE_OP, LINUX_REBOOT_CMD_CAD_OFF, MADV_COLD, MADV_COLLAPSE,
        MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE,
        MADV_HUGEPAGE, MADV_HWPOISON, MADV_KEEPONFORK, MADV_MERGEABLE, MADV_NOHUGEPAGE,
        MADV_NORMAL, MADV_PAGEOUT, MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_RANDOM,
        MADV_REMOVE, MADV_SEQUENTIAL, MADV_UNMERGEABLE, MADV_WILLNEED, MADV_WIPEONFORK, MAP_ANON,
        MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_HUGETLB, MAP_HUGE_16GB,
        MAP_HUGE_16MB, MAP_HUGE_1GB, MAP_HUGE_1MB, MAP_HUGE_256MB, MAP_HUGE_2GB, MAP_HUGE_2MB,
        MAP_HUGE_32MB, MAP_HUGE_512KB, MAP_HUGE_512MB, MAP_HUGE_64KB, MAP_HUGE_8MB, MAP_LOCKED,
        MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE,
        MAP_STACK, MAP_SYNC, MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT, O_APPEND, O_ASYNC, O_CLOEXEC,
        O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_LARGEFILE, O_NDELAY, O_NOATIME,
        O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TMPFILE, O_TRUNC, PRIO_PGRP,
        PRIO_PROCESS, PRIO_USER, P_ALL, P_PGID, P_PID, P_PIDFD, RENAME_EXCHANGE, RENAME_NOREPLACE,
        RENAME_WHITEOUT, SA_SIGINFO,
    },
    sys::{
        eventfd,
        mman::{MRemapFlags, MapFlags, MsFlags, ProtFlags},
        ptrace,
        resource::{Resource, UsageWho},
        signalfd::SfdFlags,
        socket,
        stat::FchmodatFlags,
        time::TimeVal,
        wait::WaitPidFlag,
    },
    unistd::{AccessFlags, Pid, Whence},
    NixPath,
};
use rustix::{
    fs::{statx, Access, StatxFlags},
    io::{pwritev2, ReadWriteFlags},
    path::Arg,
    rand::GetRandomFlags,
    thread::{futex, FutexFlags, FutexOperation},
};
use syscalls::Sysno;

impl SyscallObject {
    pub(crate) fn one_line_error(&mut self) {
        // TODO! Deprecate this logic for more granularity
        self.general_text(" |=> ");
        self.write_text(format!("{}", errno_to_string(self.errno.unwrap())).red());
    }
    pub(crate) fn get_syscall_return(&mut self) -> Result<String, ()> {
        self.displayable_return_ol()
    }

    pub(crate) fn handle_pause_continue(&mut self) {
        if self.paused {
            self.write_text(
                " CONTINUED ".on_custom_color(*(CONTINUED_COLOR)),
            );
        }
    }
    pub(crate) fn write_pid_sysname(&mut self) {
        use crate::syscall_object::SyscallState::*;

        if FOLLOW_FORKS.load(Ordering::SeqCst) {
            // multi-threaded: pid always blue
            if self.state == Entering {
                // Colorized PID
                self.write_text(
                    self.process_pid
                        .to_string()
                        .custom_color(*(PID_NUMBER_COLOR)),
                );

                // Colorized Syscall Name
                self.write_text(" ".dimmed());
                self.write_text(SyscallObject::colorize_syscall_name(
                    &self.sysno,
                    &self.category,
                ));
                self.write_text(" - ".dimmed());
            } else {
                if self.paused {
                    // Colorized PID
                    self.write_text(self.process_pid.to_string().bright_blue().dimmed());

                    // Colorized Syscall Name
                    self.write_text(" ".dimmed());
                    self.write_text(
                        SyscallObject::colorize_syscall_name(&self.sysno, &self.category).dimmed(),
                    );
                    self.write_text(" - ".dimmed());
                    self.handle_pause_continue();
                }
            }
        } else {
            if self.state == Entering {
                // Colorized PID
                // single-threaded: pid blue/red
                if self.get_syscall_return().is_ok() {
                    self.write_text(self.process_pid.to_string().blue());
                } else {
                    self.write_text(self.process_pid.to_string().red());
                }

                // Colorized Syscall Name
                self.write_text(" ".dimmed());
                self.write_text(SyscallObject::colorize_syscall_name(
                    &self.sysno,
                    &self.category,
                ));
                self.write_text(" - ".dimmed());
            }
        }
    }

    pub(crate) fn one_line_formatter(&mut self) -> Result<(), ()> {
        use crate::syscall_object::SyscallState::*;
        self.write_pid_sysname();
        //
        //======================
        //
        let registers = *REGISTERS.lock().unwrap();
        match self.sysno {
            // TODO! unimplemented syscalls
            // preferable to always create a syscall entry in `consts.rs` before writing an entry here
            // preadv2
            // pwritev2
            // openat2
            // creat
            // chdir
            // fchdir
            // renameat2
            // rmdir
            // link
            // linkat
            // ustat
            // cachestat
            // socket
            // bind
            // getsockname
            // getpeername
            // socketpair
            // setsockopt
            // getsockopt
            // listen
            // accept
            // accept4
            // connect
            // sendto
            // sendmsg
            // recvfrom
            // recvmsg
            // setuid
            // setgid
            Sysno::brk => {
                let syscall_brk_num = registers[0];
                let syscall_brk = self.displayable_ol(0);
                let getting_current_break = syscall_brk_num == 0;

                match self.state {
                    Entering => {
                        if getting_current_break {
                            self.general_text("get the current program break");
                        } else {
                            self.general_text("change program break to ");
                            self.write_text(
                                syscall_brk.custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            if getting_current_break {
                                self.write_text("current program break: ".green());
                                self.write_text(
                                    eph_return
                                        .unwrap()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                let new_brk_num = self.result.0.unwrap();
                                let new_brk = self.displayable_return_ol();
                                let mem_difference =
                                    get_mem_difference_from_previous(new_brk_num as _);
                                let mem_difference_bytes =
                                    BytesPagesRelevant::from_ceil(mem_difference as usize);
                                if mem_difference == 0 {
                                    self.general_text("no allocation or deallocation occured");
                                } else if mem_difference > 0 {
                                    self.general_text("allocated ");
                                    self.write_text(
                                        mem_difference_bytes
                                            .to_string()
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.general_text("deallocated ");
                                    self.write_text(
                                        mem_difference_bytes
                                            .to_string()
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                                self.write_text(", new program break: ".green());
                                self.write_text(
                                    eph_return
                                        .unwrap()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::close => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("close the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("file closed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::open => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        // TODO! fix open flags granularity
                        // TODO! also fix file mode granularity
                        //
                        self.general_text("open the file ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully opened file".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::openat => {
                let dirfd = registers[0] as i32;
                let filename = self.displayable_ol(1);
                let flags_num = registers[2] as i32;
                let flags = self.displayable_ol(2);
                match self.state {
                    Entering => {
                        // TODO! fix open flags granularity
                        // TODO! also fix file mode granularity
                        // let flags: nix::fcntl::OFlag =
                        //     unsafe { std::mem::transmute(args_vec[2] as u32) };
                        // create a temporary file
                        // pathname is a directory
                        // an unnamed inode will be created in that directory's filesystem.
                        // Anything written to the resulting file will be lost
                        // when the last file descriptor is closed, unless the file is given a name.
                        if (flags_num & O_TMPFILE) > 0 {
                            self.general_text("create an unnamed temporary file in the path: ");
                        } else {
                            self.general_text("open the file: ");
                        }
                        self.possible_dirfd_file(dirfd, filename);

                        let mut directives = vec![];
                        if (flags_num & O_APPEND) == O_APPEND {
                            directives.push(
                                "open the file in append mode"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_ASYNC) == O_ASYNC {
                            directives.push(
                                "enable signal-driven I/O"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_CLOEXEC) == O_CLOEXEC {
                            directives.push(
                                "close the file descriptor on the next exec syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_CREAT) > 0 {
                            directives.push(
                                "create the file if it does not exist"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_DIRECT) > 0 {
                            directives.push(
                                "use direct file I/O"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_DIRECTORY) > 0 {
                            directives.push(
                                "fail if the path is not a directory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_DSYNC) > 0 {
                            directives.push("ensure writes are completely teransferred to hardware before return".custom_color(*(OUR_YELLOW)));
                        }
                        if (flags_num & O_EXCL) > 0 {
                            directives.push("ensure O_CREAT fails if the file already exists or is a symbolic link".custom_color(*(OUR_YELLOW)));
                        }
                        if (flags_num & O_LARGEFILE) > 0 {
                            directives.push(
                                "allow files larger than `off_t` and up to `off64_t`"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_NOATIME) > 0 {
                            directives.push(
                                "do not update the file last access time on read"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_NOCTTY) > 0 {
                            directives
                                .push("do not use the file as the process's controlling terminal if its a terminal device".custom_color(*(OUR_YELLOW)));
                        }
                        if (flags_num & O_NOFOLLOW) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "fail if the base of the file is a symbolic link"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_NONBLOCK) > 0 || (flags_num & O_NDELAY) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "open the file in non-blocking mode"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_PATH) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "return a `shallow` file descriptor"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & O_SYNC) > 0 {
                            directives.push("ensure writes are completely teransferred to hardware before return".custom_color(*(OUR_YELLOW)));
                        }
                        self.directives_handler(directives);

                        if (flags_num & O_TRUNC) > 0 {
                            self.write_text(
                                "truncate the file's length to zero"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully opened file".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::stat => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fstat => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::lstat => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.write_path_file(filename);
                        self.general_text(" and do not recurse symbolic links");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::statfs => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get stats for the filesystem mounted in: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fstatfs => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get stats for the filesystem that contains the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::newfstatat => {
                let dirfd: i32 = registers[0] as i32;
                let filename: String = self.displayable_ol(1);
                let flags: rustix::fs::AtFlags =
                    unsafe { std::mem::transmute(registers[3] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.possible_dirfd_file(dirfd, filename);

                        let mut flag_directive = vec![];
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(rustix::fs::AtFlags::EACCESS) {
                            flag_directive.push(
                                "check using effective user & group ids"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                            flag_directive.push(
                                "recurse symbolic links if found"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(rustix::fs::AtFlags::NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .custom_color(*(OUR_YELLOW)),
                    );
                        }
                        if flags.contains(rustix::fs::AtFlags::EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flag_directive.len() > 0 {
                            self.general_text(" (");
                            let mut flag_directive_iter = flag_directive.into_iter().peekable();
                            if flag_directive_iter.peek().is_some() {
                                self.write_text(flag_directive_iter.next().unwrap());
                            }
                            for entry in flag_directive_iter {
                                self.general_text(", ");
                                self.write_text(entry);
                            }
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::statx => {
                let dirfd = registers[0] as i32;
                let pathname = self.displayable_ol(1);
                // let flags: rustix::fs::AtFlags = unsafe { std::mem::transmute(registers[2] as i32) };
                let flags_num = registers[2] as i32;
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        if pathname.starts_with('/') {
                            // absolute pathname
                            // dirfd is ignored
                            self.write_path_file(pathname);
                        } else {
                            if pathname.is_empty() && (flags_num & AT_EMPTY_PATH) > 0 {
                                // the pathname is empty
                                let dirfd_parsed = self.displayable_ol(0);
                                // if pathname is empty and AT_EMPTY_PATH is given, dirfd is used
                                self.write_path_file(dirfd_parsed);
                            } else {
                                // A relative pathname, dirfd = CWD, or a normal directory
                                self.possible_dirfd_file(dirfd, pathname);
                            }
                        }
                        let mut flag_directive = vec![];
                        if (flags_num & AT_NO_AUTOMOUNT) > 0 {
                            flag_directive.push("don't automount the basename of the path if its an automount directory".custom_color(*(OUR_YELLOW)));
                        }
                        if (flags_num & AT_SYMLINK_NOFOLLOW) > 0 {
                            flag_directive.push(
                                "if the path is a symbolic link, get its stats, do not recurse it"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & AT_STATX_SYNC_AS_STAT) > 0 {
                            flag_directive.push(
                                "behave similar to the `stat` syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & AT_STATX_FORCE_SYNC) > 0 {
                            flag_directive.push(
                                "force synchronization / guarantee up to date information"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags_num & AT_STATX_DONT_SYNC) > 0 {
                            flag_directive.push("don't force synchronization / retrieve whatever information is cached".custom_color(*(OUR_YELLOW)));
                        }
                        // if flags.contains(rustix::fs::AtFlags::EACCESS) {
                        //     flag_directive.push("check using effective user & group ids".custom_color(*(OUR_YELLOW)));
                        // }
                        // if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                        //     flag_directive.push("recurse symbolic links if found".custom_color(*(OUR_YELLOW)));
                        // }
                        self.directives_handler(flag_directive);

                        // TODO!
                        // unnecessary information
                        // statx_mask is currently unhandled because it's unnecessary information
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::chown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = registers[1] as i32;
                let group_given = registers[2] as i32;
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.general_text("change the owner of ");
                            self.write_path_file(filename);
                            self.general_text(" to ");
                            self.write_text(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.write_text(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                self.write_path_file(filename);
                                self.general_text("to ");
                                self.write_text(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("ownership changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = registers[1] as i32;
                let group_given = registers[2] as i32;
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.general_text("change the owner of the file: ");
                            self.write_path_file(filename);
                            self.general_text(" to ");
                            self.write_text(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.write_text(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                self.write_path_file(filename);

                                self.general_text("to ");
                                self.write_text(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("ownership changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::lchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = registers[1] as i32;
                let group_given = registers[2] as i32;
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.general_text("change the owner of ");
                            self.write_path_file(filename);
                            self.general_text(" to ");
                            self.write_text(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.write_text(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                self.write_path_file(filename);
                                self.general_text("to ");
                                self.write_text(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("ownership changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fchownat => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let dirfd = registers[0] as i32;
                let filename = self.displayable_ol(1);
                let owner_given = registers[2] as i32;
                let group_given = registers[3] as i32;
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.general_text("change the owner of ");
                            self.possible_dirfd_file(dirfd, filename);

                            self.general_text(" to ");
                            self.write_text(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.write_text(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                self.write_path_file(filename);
                                self.general_text("to ");
                                self.write_text(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("ownership changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::madvise => {
                // addr, len, adv
                let len = self.displayable_ol(1);
                let addr = self.displayable_ol(0);
                let advice = registers[2] as i32;
                match self.state {
                    Entering => {
                        if (advice & MADV_NORMAL) == MADV_NORMAL {
                            self.general_text("provide default treatment for ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_RANDOM) == MADV_RANDOM {
                            self.general_text("expect ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be referenced in random order");
                        } else if (advice & MADV_SEQUENTIAL) == MADV_SEQUENTIAL {
                            self.general_text("expect ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be referenced in sequential order");
                        } else if (advice & MADV_WILLNEED) == MADV_WILLNEED {
                            self.general_text("expect ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be accessed in the future");
                        } else if (advice & MADV_DONTNEED) == MADV_DONTNEED {
                            self.write_text(
                                "do not expect the"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be accessed in the future");
                        } else if (advice & MADV_REMOVE) == MADV_REMOVE {
                            // equivalent to punching a hole in the corresponding range
                            self.general_text("free");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_DONTFORK) == MADV_DONTFORK {
                            self.general_text("do not allow ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be available to children from ");
                            self.write_text("fork()".blue());
                        } else if (advice & MADV_DOFORK) == MADV_DOFORK {
                            self.general_text("allow ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to be available to children from ");
                            self.write_text("fork()".blue());
                            self.general_text(" ");
                            self.write_text(
                                "(Undo MADV_DONTFORK)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (advice & MADV_HWPOISON) == MADV_HWPOISON {
                            // treat subsequent references to those pages like a hardware memory corruption
                            self.general_text("poison ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_MERGEABLE) == MADV_MERGEABLE {
                            // KSM merges only private anonymous pages
                            self.general_text("enable KSM (Kernel Samepage Merging) for ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_UNMERGEABLE) == MADV_UNMERGEABLE {
                            self.general_text(
                                "unmerge all previous KSM merges from MADV_MERGEABLE in ",
                            );
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_HUGEPAGE) == MADV_HUGEPAGE {
                            self.write_text(
                                "enable".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" transparent huge pages (THP) on ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_NOHUGEPAGE) == MADV_NOHUGEPAGE {
                            self.write_text(
                                "disable".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" transparent huge pages (THP) on ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_COLLAPSE) == MADV_COLLAPSE {
                            // TODO! citation needed
                            self.general_text("perform a synchronous collapse of ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" that's mapped into transparent huge pages (THP)");
                        } else if (advice & MADV_DONTDUMP) == MADV_DONTDUMP {
                            self.general_text("exclude ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" from core dumps");
                        } else if (advice & MADV_DODUMP) == MADV_DODUMP {
                            self.general_text("include ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" in core dumps ");
                            self.write_text(
                                "(Undo MADV_DONTDUMP)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (advice & MADV_FREE) == MADV_FREE {
                            self.general_text("the range of ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" is no longer required and is ok to free");
                        } else if (advice & MADV_WIPEONFORK) == MADV_WIPEONFORK {
                            self.general_text("zero-fill the range of ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to any child from ");
                            self.write_text("fork()".blue());
                        } else if (advice & MADV_KEEPONFORK) == MADV_KEEPONFORK {
                            self.general_text("keep the range of ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" to any child from ");
                            self.write_text("fork()".blue());
                            self.general_text(" ");
                            self.write_text(
                                "(Undo MADV_WIPEONFORK)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (advice & MADV_COLD) == MADV_COLD {
                            // This makes the pages a more probable reclaim target during memory pressure
                            self.general_text("deactivate ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text("  (make more probable to reclaim)");
                        } else if (advice & MADV_PAGEOUT) == MADV_PAGEOUT {
                            // This is done to free up memory occupied by these pages.
                            // If a page is anonymous, it will be swapped out.
                            // If a page  is  file-backed and dirty, it will be written back to the backing storage
                            self.general_text("page out ");
                            // "page out" is more intuitive, "reclaim"sleading
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                        } else if (advice & MADV_POPULATE_READ) == MADV_POPULATE_READ {
                            self.general_text("prefault ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" while avoiding memory access ");
                            self.write_text(
                                "(simulate reading)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (advice & MADV_POPULATE_WRITE) == MADV_POPULATE_WRITE {
                            self.general_text("prefault ");
                            self.write_text(len.custom_color(*(OUR_YELLOW)));
                            self.general_text(" of memory starting from ");
                            self.write_text(addr.custom_color(*(OUR_YELLOW)));
                            self.general_text(" while avoiding memory access ");
                            self.write_text(
                                "(simulate writing)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory advice registered".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mmap => {
                // MMAP ARGS
                //
                //
                //
                let flags_num = registers[3] as i32;

                let shared = (flags_num & MAP_SHARED) == MAP_SHARED;
                let private = (flags_num & MAP_PRIVATE) == MAP_PRIVATE;

                let shared_validate = (flags_num as i32 & MAP_SHARED_VALIDATE) > 0;

                let anonymous = ((flags_num & MAP_ANON) == MAP_ANON)
                    || ((flags_num & MAP_ANONYMOUS) == MAP_ANONYMOUS);

                let huge_pages_used = (flags_num & MAP_HUGETLB) == MAP_HUGETLB;
                let populate = (flags_num & MAP_POPULATE) == MAP_POPULATE;
                let lock = (flags_num & MAP_LOCKED) == MAP_LOCKED;

                let fixed = (flags_num & MAP_FIXED) == MAP_FIXED;
                let non_blocking = (flags_num & MAP_NONBLOCK) == MAP_NONBLOCK;
                let no_reserve = (flags_num & MAP_NORESERVE) == MAP_NORESERVE;
                let stack = (flags_num & MAP_STACK) == MAP_STACK;

                let sync = (flags_num as i32 & MAP_SYNC) > 0;

                let prot_flags: ProtFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let bytes = self.displayable_ol(1);
                let fd = registers[4] as RawFd;
                let addr = registers[0] as *const ();
                let address = self.displayable_ol(0);
                let offset_num = registers[5];
                let offset = self.displayable_ol(5);
                match self.state {
                    Entering => {
                        // AMOUNT OF BYTES
                        //
                        //
                        //
                        if !anonymous {
                            self.general_text("map ");
                        } else {
                            self.general_text("allocate ");
                        }
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        // BACKED BY FILE
                        //
                        //
                        //
                        if !anonymous {
                            self.general_text(" of the file: ");
                            let filename = self.displayable_ol(4);
                            self.write_path_file(filename);
                            if offset_num > 0 {
                                self.general_text(" at an offset of ");
                                self.write_text(
                                    offset
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }

                        self.general_text(" as ");
                        // PRIVATE VS SHARED
                        //
                        //
                        //
                        // check shared_validate first because its 0x3 (shared and private are 0x1, and 0x2)
                        if shared_validate || shared {
                            self.write_text(
                                "shared memory".custom_color(*(OUR_YELLOW)),
                            );
                        // no need to check MAP_PRIVATE,
                        // its the last option at this point
                        // and mmap will fail if its not provided
                        } else if private {
                            self.write_text(
                                "private copy-on-write memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // HUGE PAGES
                        //
                        //
                        //
                        if huge_pages_used {
                            self.general_text(" using ");
                            if (flags_num & MAP_HUGE_64KB) == MAP_HUGE_64KB {
                                self.write_text(
                                    "64 KB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_512KB) == MAP_HUGE_512KB {
                                self.write_text(
                                    "512 KB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_1MB) == MAP_HUGE_1MB {
                                self.write_text(
                                    "1 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_2MB) == MAP_HUGE_2MB {
                                self.write_text(
                                    "2 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_8MB) == MAP_HUGE_8MB {
                                self.write_text(
                                    "8 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_16MB) == MAP_HUGE_16MB {
                                self.write_text(
                                    "16 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_32MB) == MAP_HUGE_32MB {
                                self.write_text(
                                    "32 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_256MB) == MAP_HUGE_256MB {
                                self.write_text(
                                    "256 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_512MB) == MAP_HUGE_512MB {
                                self.write_text(
                                    "512 MB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_1GB) == MAP_HUGE_1GB {
                                self.write_text(
                                    "1 GB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_2GB) == MAP_HUGE_2GB {
                                self.write_text(
                                    "2 GB ".custom_color(*(OUR_YELLOW)),
                                );
                            } else if (flags_num & MAP_HUGE_16GB) == MAP_HUGE_16GB {
                                self.write_text(
                                    "16 GB ".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            self.write_text(
                                "hugepages".custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // POPULATE
                        //
                        //
                        //
                        if populate && !non_blocking {
                            self.general_text(" ");
                            self.write_text(
                                "and prefault it".custom_color(*(OUR_YELLOW)),
                            );
                            // MAP_NON_BLOCK disables MAP_POPULATE since 2.5.46
                        }

                        let mut others = vec![];
                        if lock {
                            others.push(
                                "don't swap memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if no_reserve {
                            // we trust that there will be enough swap space at any time in the future
                            // Swap space is shared by all the processes, so there can never be a guarantee that there is enough of it
                            // preallocating it (more or less) gives a guaranty that the calling process will always have enough of it
                            others.push(
                                "don't reserve swap space"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if stack {
                            others.push(
                                "choose an address suitable for a stack"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if sync && shared_validate {
                            others.push(
                                "use Direct Access (DAX) for file writes"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if others.len() > 0 {
                            self.general_text(" (");
                            self.vanilla_commas_handler(others);
                            self.general_text(")");
                        }

                        // ADDRESS
                        //
                        //
                        //
                        if addr.is_null() {
                            self.general_text(" at ");
                            self.write_text(
                                "an appropiate kernel chosen address"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (flags_num & MAP_FIXED) == MAP_FIXED {
                            self.general_text(" starting ");
                            self.write_text(
                                "exactly at ".custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                address.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (flags_num & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE {
                            self.general_text(" starting ");
                            self.write_text(
                                "exactly at ".custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                address.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                " and fail if a mapping already exists "
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.general_text(" starting ");
                            self.write_text(
                                "around ".custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                address.custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // MEMORY DIRECTION
                        //
                        //
                        //
                        if (flags_num & MAP_GROWSDOWN) == MAP_GROWSDOWN {
                            self.write_text(
                                " growing down,".custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // PROTECTION
                        //
                        //
                        //
                        let all_flags =
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
                        if prot_flags.intersects(all_flags) {
                            let mut flags = vec![];
                            if prot_flags.contains(ProtFlags::PROT_READ) {
                                flags.push(
                                    "reading".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if prot_flags.contains(ProtFlags::PROT_WRITE) {
                                flags.push(
                                    "writing".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if prot_flags.contains(ProtFlags::PROT_EXEC) {
                                flags.push(
                                    "execution".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if !flags.is_empty() {
                                self.general_text(" and allow ");
                                self.vanilla_commas_handler(flags);
                            }
                        } else {
                            // TODO! guard pages note should be improved
                            self.write_text(
                                " without protection (Guard Pages)"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("new mapping address: ".green());
                            let address = eph_return.unwrap();
                            // p!(where_in_childs_memory(self.child, self.result.0.unwrap())
                            //     .unwrap()
                            //     .pathname);
                            self.write_text(
                                address.custom_color(*(OUR_YELLOW)),
                            );
                            // if anonymous {
                            //     let k = get_child_memory_break(self.child);
                            //     let res = self.result.0.unwrap();
                            //     if (res >= k.1 .0) & (res <= k.1 .1) {
                            //         p!(mapping_flags);
                            //         p!("mmap address inside stack");
                            //         println!(
                            //             "stack range: 0x{:x} - 0x{:x}, mmap: 0x{:x}, mmap return: {}",
                            //             k.1 .0, k.1 .1, registers[0], address
                            //         );
                            //     } else if res >= k.1 .0 {
                            //         println!(
                            //             "beneath of current stack by: {}",
                            //             BytesPagesRelevant::from_ceil((res - k.1 .0) as usize)
                            //         );
                            //     } else if res <= k.1 .1 {
                            //         println!(
                            //             "over current stack by: {}",
                            //             BytesPagesRelevant::from_ceil((k.1 .1 - res) as usize)
                            //         );
                            //     } else if res as usize == k.0 {
                            //         p!("mmap address is current brk");
                            //         println!(
                            //             "brk: 0x{:x}, mmap: 0x{:x}, mmap return: {}",
                            //             k.0, registers[0], address
                            //         );
                            //     } else {
                            //         p!("..")
                            //     }
                            // }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::munmap => {
                let address = self.displayable_ol(0);
                let bytes = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("unmap ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" from memory starting at ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully unmapped region".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::msync => {
                let address = self.displayable_ol(0);
                let bytes = self.displayable_ol(1);
                let msync_flags: MsFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("flush all changes made on ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" of memory starting from ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                        self.general_text(" back to the filesystem");
                        if msync_flags.contains(MsFlags::MS_ASYNC) {
                            self.general_text(" (");
                            self.write_text(
                                "schedule the update, but return immediately"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(")");
                        } else if msync_flags.contains(MsFlags::MS_INVALIDATE) {
                            self.general_text(" (");
                            self.write_text(
                                "block until completion"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(")");
                        } else if msync_flags.contains(MsFlags::MS_SYNC) {
                            // this is used to propagate
                            self.general_text(" (");
                            self.write_text(
                                "invalidate other mappings of the file to propagate these changes"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mprotect => {
                let address = self.displayable_ol(0);
                let bytes = self.displayable_ol(1);
                let prot_flags: ProtFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let all_prots = ProtFlags::all();
                match self.state {
                    Entering => {
                        // PROTECTION
                        //
                        //
                        //
                        if prot_flags.contains(ProtFlags::PROT_NONE) {
                            // Guard pages for buffer overflows
                            // ... allocation of additional inaccessible memory during memory allocation operations
                            // is a technique for mitigating against exploitation of heap buffer overflows.
                            // These guard pages are unmapped pages placed between all memory allocations
                            // of one page or larger. The guard page causes a segmentation fault upon any access.
                            self.general_text("prevent ");
                            self.write_text(
                                "all access".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            if all_prots.intersects(prot_flags) {
                                self.general_text("allow ");
                                let mut flags = vec![];
                                if prot_flags.contains(ProtFlags::PROT_READ) {
                                    flags.push(ProtFlags::PROT_READ)
                                }
                                if prot_flags.contains(ProtFlags::PROT_WRITE) {
                                    flags.push(ProtFlags::PROT_WRITE)
                                }
                                if prot_flags.contains(ProtFlags::PROT_EXEC) {
                                    flags.push(ProtFlags::PROT_EXEC)
                                }
                                let len = flags.len();
                                for (index, flag) in flags.iter().enumerate() {
                                    match *flag {
                                        ProtFlags::PROT_READ => {
                                            self.write_text(
                                                "reading".custom_color(*(
                                                    OUR_YELLOW
                                                )),
                                            );
                                        }
                                        ProtFlags::PROT_WRITE => {
                                            self.write_text(
                                                "writing".custom_color(*(
                                                    OUR_YELLOW
                                                )),
                                            );
                                        }
                                        ProtFlags::PROT_EXEC => {
                                            self.write_text(
                                                "execution".custom_color(*(
                                                    OUR_YELLOW
                                                )),
                                            );
                                        }
                                        _ => unreachable!(),
                                    }
                                    if index != len - 1 {
                                        self.write_text(
                                            ", ".custom_color(*(OUR_YELLOW)),
                                        );
                                    }
                                }
                            }
                        }
                        // AMOUNT OF BYTES
                        //
                        //
                        //
                        self.general_text(" on ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" of memory ");
                        // ADDRESS
                        //
                        //
                        //
                        self.general_text("starting from ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory protection modified".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::lseek => {
                let filename = self.displayable_ol(0);
                let offset_num = registers[1] as i64;
                let offset = self.displayable_ol(1);

                let whence: Whence = unsafe { std::mem::transmute(registers[2] as u32) };
                match self.state {
                    Entering => {
                        match whence {
                            Whence::SeekSet => {
                                if offset_num == 0 {
                                    self.general_text("move the file pointer of the file: ");
                                    self.write_path_file(filename);
                                    self.general_text(" to ");
                                    self.write_text(
                                        "the beginning of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                    self.write_text(
                                        "from the beginning of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                            }
                            Whence::SeekCur => {
                                self.general_text("move the file pointer of the file: ");
                                self.write_path_file(filename);
                                self.general_text(" ");
                                if offset_num == 0 {
                                    // self.general_text.push("[intentrace: redundant syscall (won't do anything)]");

                                    self.general_text("to ");
                                    self.write_text(
                                        "the current file pointer"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else if offset_num > 0 {
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                    self.write_text(
                                        " forwards"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.write_text(
                                        (&offset[1..])
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                    self.write_text(
                                        " backwards"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                            }
                            Whence::SeekEnd => {
                                self.general_text("move the file pointer of the file: ");
                                self.write_path_file(filename);
                                self.general_text(" ");

                                if offset_num == 0 {
                                    self.general_text("to ");
                                    self.write_text(
                                        "the end of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else if offset_num > 0 {
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                    self.general_text(" after ");
                                    self.write_text(
                                        "the end of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.write_text(
                                        (&offset[1..])
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                    self.general_text(" before ");
                                    self.write_text(
                                        "the end of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                            }
                            Whence::SeekData => {
                                self.general_text("move the file pointer of the file: ");
                                self.write_path_file(filename);
                                self.general_text(" to ");
                                self.write_text(
                                    "the nearest data block"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" you find ");
                                if offset_num == 0 {
                                    self.write_text(
                                        "at the beginning of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else if offset_num > 0 {
                                    self.write_text(
                                        "after ".custom_color(*(OUR_YELLOW)),
                                    );
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                    // this should be an error
                                    self.write_text(
                                        " before the beginning of the file "
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                            }
                            Whence::SeekHole => {
                                self.general_text("move the file pointer of the file: ");
                                self.write_path_file(filename);
                                self.general_text(" to ");
                                self.write_text(
                                    "the nearest data hole"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" you find ");
                                if offset_num == 0 {
                                    self.write_text(
                                        "at the beginning of the file"
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                } else if offset_num > 0 {
                                    self.write_text(
                                        "after ".custom_color(*(OUR_YELLOW)),
                                    );
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                } else {
                                    self.write_text(
                                        offset.custom_color(*(OUR_YELLOW)),
                                    );
                                    // TODO! test this
                                    self.write_text(
                                        " before the beginning of the file "
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                }
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("new offset location: ".green());
                            self.write_text(eph_return.unwrap().green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mlock => {
                let address = self.displayable_ol(0);
                let bytes_num = registers[1];
                let bytes = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("prevent swapping of memory on ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" starting from: ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mlock2 => {
                let address = self.displayable_ol(0);
                let bytes_num = registers[1];
                let bytes = self.displayable_ol(1);
                let flags = registers[2] as u32;
                match self.state {
                    Entering => {
                        self.general_text("prevent swapping of memory on ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" starting from: ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));

                        // if flags.contains(crate::utilities::mlock2::MLOCK_ONFAULT) {
                        // 1 = MLOCK_ONFAULT
                        if (flags & 1) == 1 {
                            self.general_text(" (");
                            // this allow non-resident pages to get locked later when they are faulted
                            self.general_text("only lock resident-pages, only lock non-resident pages once they're faulted");
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::munlock => {
                let address = self.displayable_ol(0);
                let bytes_num = registers[1];
                let bytes = self.displayable_ol(1);

                match self.state {
                    Entering => {
                        self.general_text("allow swapping of memory on ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" starting from: ");
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory range is now swappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::munlockall => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "allow the entire memory of the calling process to be swappable",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory range is now swappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mremap => {
                // TODO! current mremap logic is not good and needs rewriting
                let old_address_num = registers[0];
                let old_address = self.displayable_ol(0);
                let old_len_num = registers[1];
                let old_len = self.displayable_ol(1);
                let new_len_num = registers[2];
                let new_len = self.displayable_ol(2);
                let flags: MRemapFlags = unsafe { std::mem::transmute(registers[3] as u32) };
                let new_address_num = registers[4];
                let new_address = self.displayable_ol(4);
                match self.state {
                    Entering => {
                        if new_len_num > old_len_num {
                            self.general_text("expand the memory region of ");
                            self.write_text(
                                old_len.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                " starting from: "
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                old_address.custom_color(*(OUR_YELLOW)),
                            );
                        } else if new_len_num < old_len_num {
                            self.general_text("shrink the memory region of ");
                            self.write_text(
                                old_len.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                " starting from: "
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                old_address.custom_color(*(OUR_YELLOW)),
                            );
                        } else if new_len_num == old_len_num {
                            if old_address_num == new_address_num {
                                self.write_text("[intentrace Notice: syscall no-op]".blink());
                            } else {
                                self.general_text("move the memory region of ");
                                self.write_text(
                                    old_len.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    " starting from: "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    old_address.custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }
                        if flags.contains(MRemapFlags::MREMAP_FIXED)
                            && flags.contains(MRemapFlags::MREMAP_MAYMOVE)
                        {
                            self.general_text(" (");
                            self.write_text(                        "move the mapping to a different address if you can not expand at current address"
                            .custom_color(*(OUR_YELLOW)),
                    );
                            self.general_text(")");
                        } else if flags.contains(MRemapFlags::MREMAP_MAYMOVE) {
                            self.general_text(" (");
                            self.write_text(                        "move the mapping to a different address if you can not expand at current address"
                            .custom_color(*(OUR_YELLOW)),
                    );
                            self.general_text(")");
                        } // else if flags.contains( MRemapFlags::MREMAP_DONTUNMAP) {
                          // unsupported at rustix atm
                          // }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mincore => {
                // TODO! current mremap logic is not good and needs rewriting
                let address_num = registers[0];
                let address = self.displayable_ol(0);
                let length_num = registers[1];
                let length = self.displayable_ol(1);

                match self.state {
                    Entering => {
                        self.general_text("populate a vector of bytes representing ");
                        self.write_text(length.custom_color(*(OUR_YELLOW)));
                        self.write_text(
                            " of the process's memory starting from: "
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                        self.general_text(
                            " indicating resident and non-resident pages in each byte",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mlockall => {
                let flags_num = registers[0] as i32;
                let flags: rustix::mm::MlockAllFlags =
                    unsafe { std::mem::transmute(registers[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("prevent swapping of ");

                        match (
                            (flags_num & MCL_CURRENT) == MCL_CURRENT,
                            (flags_num & MCL_FUTURE) == MCL_FUTURE,
                        ) {
                            (true, true) => {
                                self.write_text(
                                    "all current and future mapped pages"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.general_text(" (only lock resident-pages for current and future mappings, lock non-resident pages whenever they're faulted)");
                                }
                            }
                            (true, false) => {
                                self.write_text(
                                    "all currently mapped pages"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.general_text(" (only lock currently resident-pages, only lock non-resident pages once they're faulted)");
                                }
                            }
                            (false, true) => {
                                self.write_text(
                                    "all future mapped pages "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.general_text(" (do not lock future pages the moment they're mapped, only lock whenever they're faulted)");
                                }
                            }
                            (false, false) => {
                                // println!("{flags:?}");
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::read => {
                let filename = self.displayable_ol(0);
                let bytes_to_read = registers[2];
                let bytes = self.displayable_ol(2);
                match self.state {
                    Entering => {
                        self.general_text("read ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" from the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if bytes_num == 0 {
                                self.write_text("read ".green());
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (end of file)".green());
                            } else if bytes_num < bytes_to_read {
                                self.write_text("read ".green());
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (fewer than requested)".green());
                            } else {
                                self.write_text("read all ".green());
                                self.write_text(
                                    bytes_to_read
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    " Bytes".custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::write => {
                let bytes_to_write = registers[2];
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("write ");
                        if bytes_to_write < 20 {
                            self.write_text(
                                self.displayable_ol(1)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.write_text(
                                self.displayable_ol(2)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" into the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if bytes_num < bytes_to_write {
                                self.write_text("wrote ".green());
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (fewer than requested)".green());
                            } else {
                                self.write_text("wrote all ".green());
                                self.write_text(
                                    bytes_to_write
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    " Bytes".custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pread64 => {
                let bytes_to_read = registers[2];
                let bytes = self.displayable_ol(2);
                let filename = self.displayable_ol(0);
                let offset = self.displayable_ol(3);
                match self.state {
                    Entering => {
                        self.general_text("read ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" from the file: ");
                        self.write_path_file(filename);
                        self.general_text(" at an offset of ");
                        self.write_text(offset.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num: u64 = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if bytes_num == 0 {
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (end of file)".green());
                            } else if bytes_num < bytes_to_read {
                                self.write_text("read ".green());
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (fewer than requested)".green());
                            } else {
                                self.write_text("read all ".green());
                                self.write_text(
                                    bytes_to_read
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    " Bytes".custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pwrite64 => {
                let bytes_to_write = registers[2];
                let filename = self.displayable_ol(0);
                let offset = self.displayable_ol(3);

                match self.state {
                    Entering => {
                        self.general_text("write ");
                        if bytes_to_write < 20 {
                            self.write_text(
                                format!("{:?}", self.displayable_ol(1))
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.write_text(
                                self.displayable_ol(2)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" into the file: ");
                        self.write_path_file(filename);
                        self.general_text(" at an offset of ");
                        self.write_text(offset.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if bytes_num < bytes_to_write {
                                self.write_text("wrote ".green());
                                self.write_text(
                                    bytes_string.custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(" (fewer than requested)".green());
                            } else {
                                self.write_text("wrote all ".green());
                                self.write_text(
                                    bytes_to_write
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    " Bytes".custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readv => {
                let number_of_iovecs = registers[2];
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("read from ");
                        self.write_text(
                            number_of_iovecs
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory from the file: ");
                        } else {
                            self.general_text(" scattered regions of memory from the file: ");
                        }
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("read ".green());
                            self.write_text(
                                bytes_string.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::writev => {
                let filename = self.displayable_ol(0);
                let number_of_iovecs = registers[2];

                match self.state {
                    Entering => {
                        self.general_text("write into ");
                        self.write_text(
                            number_of_iovecs
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory of the file: ");
                        } else {
                            self.general_text(" scattered regions of memory of the file: ");
                        }
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("wrote ".green());
                            self.write_text(
                                bytes_string.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::preadv => {
                let number_of_iovecs = registers[2];
                let filename = self.displayable_ol(0);
                let offset = self.displayable_ol(3);
                match self.state {
                    Entering => {
                        self.general_text("read from ");
                        self.write_text(
                            number_of_iovecs
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory from the file: ");
                        } else {
                            self.general_text(" scattered regions of memory from the file: ");
                        }
                        self.write_path_file(filename);
                        self.general_text(" at an offset of ");
                        self.write_text(offset.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("read ".green());
                            self.write_text(
                                bytes_string.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pwritev => {
                let number_of_iovecs = registers[2];
                let filename = self.displayable_ol(0);
                let offset = self.displayable_ol(3);

                match self.state {
                    Entering => {
                        self.general_text("write into ");
                        self.write_text(
                            number_of_iovecs
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory of the file: ");
                        } else {
                            self.general_text(" scattered regions of memory of the file: ");
                        }
                        self.write_path_file(filename);
                        self.general_text(" at an offset of ");
                        self.write_text(offset.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("wrote ".green());
                            self.write_text(
                                bytes_string.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }

            Sysno::sync => {
                match self.state {
                    Entering => {
                        self.general_text("flush all pending filesystem data and metadata writes");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("all writes flushed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            // TODO! granular
            // check if the file was moved only or renamed only or moved and renamed at the same time
            Sysno::rename => {
                let old_path = self.displayable_ol(0);
                let new_path = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("move the file: ");
                        self.write_path_file(old_path);
                        self.general_text(" to: ");
                        self.write_path_file(new_path);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::renameat => {
                let old_dirfd = registers[0] as i32;
                let old_filename = self.displayable_ol(1);
                let new_dirfd = registers[2] as i32;
                let new_filename = self.displayable_ol(3);
                match self.state {
                    Entering => {
                        self.general_text("move the file: ");
                        self.possible_dirfd_file(old_dirfd, old_filename);

                        self.general_text(" to: ");
                        self.possible_dirfd_file(new_dirfd, new_filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::renameat2 => {
                let old_dirfd = registers[0] as i32;
                let old_filename = self.displayable_ol(1);
                let new_dirfd = registers[2] as i32;
                let new_filename = self.displayable_ol(3);
                let flags = registers[2] as u32;
                match self.state {
                    Entering => {
                        self.general_text("move the file: ");
                        self.possible_dirfd_file(old_dirfd, old_filename);

                        self.general_text(" to: ");
                        self.possible_dirfd_file(new_dirfd, new_filename);

                        let mut directives = vec![];
                        if (flags & RENAME_EXCHANGE) > 0 {
                            directives.push(
                                "exchange the paths atomically"
                                    .custom_color(*(OUR_YELLOW)),
                            )
                        }
                        if (flags & RENAME_NOREPLACE) > 0 {
                            directives.push(
                                "error if the new path exists"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (flags & RENAME_WHITEOUT) > 0 {
                            directives.push(
                                "white-out the original file"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mkdir => {
                let path = self.displayable_ol(0);
                let path_rust = PathBuf::from(path);
                match self.state {
                    Entering => match path_rust.canonicalize() {
                        Ok(abs_path) => {
                            let canon_path: PathBuf = abs_path.canonicalize().unwrap();
                            self.general_text("create a new directory ");
                            self.write_text(
                                canon_path
                                    .file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" inside: ");
                            self.write_text(
                                canon_path
                                    .parent()
                                    .unwrap()
                                    .to_string_lossy()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        Err(_) => {
                            self.write_text("[intentrace Error: path error]".blink());
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("directory created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mkdirat => {
                let dirfd = registers[0] as i32;
                let filename: String = self.displayable_ol(1);

                match self.state {
                    Entering => {
                        let path = self.possible_dirfd_file_output(dirfd, filename);
                        let path_rust = PathBuf::from(path);

                        self.general_text("create a new directory ");
                        self.write_text(
                            path_rust
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .to_owned()
                                .blue(),
                        );
                        self.general_text(" inside: ");
                        self.write_text(
                            path_rust
                                .parent()
                                .unwrap()
                                .to_string_lossy()
                                .to_owned()
                                .custom_color(*(OUR_YELLOW)),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("directory created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getcwd => {
                match self.state {
                    Entering => {
                        self.general_text("get the current working directory");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("cwd: ".green());
                            self.write_text(
                                eph_return
                                    .unwrap()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::symlink => {
                let target = self.displayable_ol(0);
                let symlink = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("create the symlink: ");
                        self.write_path_file(symlink);

                        self.general_text(" and link it with: ");
                        self.write_path_file(target);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("symlink created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::symlinkat => {
                let target = self.displayable_ol(0);
                let dirfd = registers[1] as i32;
                let symlink = self.displayable_ol(2);

                match self.state {
                    Entering => {
                        self.general_text("create the symlink: ");
                        self.possible_dirfd_file(dirfd, symlink);
                        self.general_text(" and link it with: ");
                        self.write_path_file(target);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("symlink created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    } // the file does not exist at this point
                }
            }
            Sysno::unlink => {
                let path = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("unlink and possibly delete the file: ");
                        self.write_path_file(path);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("unlinking successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    } // caution: the file is deleted at this point
                }
            }
            Sysno::unlinkat => {
                let dirfd = registers[0] as i32;
                let path = self.displayable_ol(1);
                let flag = registers[2] as i32;
                match self.state {
                    Entering => {
                        self.general_text("unlink and possibly delete the file: ");
                        self.possible_dirfd_file(dirfd, path);

                        if (flag & AT_REMOVEDIR) > 0 {
                            self.general_text(" (");
                            self.write_text(
                                "perform the same operation as "
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text("`rmdir`".blue());
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("unlinking successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::access => {
                let filename: String = self.displayable_ol(0);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(registers[1] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.general_text("check if the file: ");
                            self.write_path_file(filename);
                            self.write_text(
                                " exists".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks
                                    .push("read".custom_color(*(OUR_YELLOW)));
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push(
                                    "write".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push(
                                    "execute".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if !checks.is_empty() {
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file: ");
                                self.write_path_file(filename);
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::faccessat => {
                let dirfd = registers[0] as i32;
                let filename = self.displayable_ol(1);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let flags: nix::fcntl::AtFlags =
                    unsafe { std::mem::transmute(registers[3] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.general_text("check if the file: ");
                            self.possible_dirfd_file(dirfd, filename);

                            self.general_text(" ");
                            self.write_text(
                                "exists".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks
                                    .push("read".custom_color(*(OUR_YELLOW)));
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push(
                                    "write".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push(
                                    "execute".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if !checks.is_empty() {
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file: ");
                                self.possible_dirfd_file(dirfd, filename);
                            }
                        }
                        let mut flag_directive = vec![];
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EACCESS) {
                            flag_directive.push(
                                "check using effective user & group ids"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW) {
                            flag_directive.push(
                                "recurse symbolic links if found"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .custom_color(*(OUR_YELLOW)),
                    );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(flag_directive);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::faccessat2 => {
                let dirfd = registers[0] as i32;
                let dirfd_parsed = self.displayable_ol(0);
                let filename = self.displayable_ol(1);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let flags: nix::fcntl::AtFlags =
                    unsafe { std::mem::transmute(registers[3] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.general_text("check if the file: ");
                            self.possible_dirfd_file(dirfd, filename);
                            self.general_text(" ");
                            self.write_text(
                                "exists".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks
                                    .push("read".custom_color(*(OUR_YELLOW)));
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push(
                                    "write".custom_color(*(OUR_YELLOW)),
                                );
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push(
                                    "execute".custom_color(*(OUR_YELLOW)),
                                );
                            }

                            if !checks.is_empty() {
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file ");
                                self.possible_dirfd_file(dirfd, filename);
                            }
                        }
                        let mut flag_directive = vec![];
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EACCESS) {
                            flag_directive.push(
                                "check using effective user & group ids"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW) {
                            flag_directive.push(
                                "recurse symbolic links if found"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .custom_color(*(OUR_YELLOW)),
                    );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(flag_directive);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readlink => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the target path of the symbolic link: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("target retrieved: ".green());
                            let target = self.displayable_ol(1);
                            self.write_path_file(target);
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readlinkat => {
                let dirfd = registers[0] as i32;
                let filename = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("get the target path of the symbolic link: ");
                        self.possible_dirfd_file(dirfd, filename)
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("target retrieved: ".green());
                            let target = self.displayable_ol(2);
                            self.write_path_file(target);
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::chmod => {
                let filename: String = self.displayable_ol(0);
                let mode: rustix::fs::Mode =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("change the mode of the file: ");
                        self.write_path_file(filename);
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fchmod => {
                let filename: String = self.displayable_ol(0);
                let mode: rustix::fs::Mode =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("change the mode of the file: ");
                        self.write_path_file(filename);
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fchmodat => {
                let dirfd = registers[0] as i32;
                let dirfd_parsed = self.displayable_ol(0);
                let filename: String = self.displayable_ol(1);
                let mode: rustix::fs::Mode =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let flag: FchmodatFlags = unsafe { std::mem::transmute(registers[3] as u8) };
                match self.state {
                    Entering => {
                        self.general_text("change the mode of the file: ");
                        self.possible_dirfd_file(dirfd, filename);
                        self.mode_matcher(mode);
                        self.general_text("and ");
                        match flag {
                            FchmodatFlags::FollowSymlink => {
                                self.write_text(
                                    "recurse symlinks"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                            FchmodatFlags::NoFollowSymlink => {
                                self.write_text(
                                    "do not recurse symlinks"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::syncfs => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("flush all pending filesystem data and metadata writes for the filesystem that contains the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pipe => {
                let file_descriptors = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("create a pipe for inter-process communication");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("created the pipe: ".green());
                            self.write_text(
                                file_descriptors.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pipe2 => {
                let file_descriptors = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("create a pipe for inter-process communication");
                        // flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("created the pipe: ".green());
                            self.write_text(
                                file_descriptors.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::dup => {
                let file_descriptor = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("duplicate the file descriptor: ");
                        self.write_path_file(file_descriptor);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("created a new duplicate file descriptor: ".green());
                            self.write_path_file(eph_return.unwrap());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::dup2 => {
                let file_to_be_duplicated = self.displayable_ol(0);
                let file_duplicate = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("duplicate the file descriptor: ");
                        self.write_path_file(file_to_be_duplicated);
                        self.general_text(" using the descriptor: ");
                        self.write_path_file(file_duplicate);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::dup3 => {
                let file_to_be_duplicated = self.displayable_ol(0);
                let file_duplicate = self.displayable_ol(1);
                let dup_flag_num = registers[2] as i32;
                match self.state {
                    Entering => {
                        self.general_text("duplicate the file descriptor: ");
                        self.write_path_file(file_to_be_duplicated);
                        self.general_text(" using the descriptor: ");
                        self.write_path_file(file_duplicate);
                        if (dup_flag_num & O_CLOEXEC) == O_CLOEXEC {
                            self.write_text(
                                " and close the file on the next exec syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fsync => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text(
                            "flush all pending data and metadata writes for the file: ",
                        );
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("all writes flushed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fdatasync => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("flush all pending data and critical metadata writes (ignore non-critical metadata) for the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("all writes flushed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::truncate => {
                let filename = self.displayable_ol(0);
                let length = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("change the size of the file: ");
                        self.write_path_file(filename);
                        self.general_text(" to precisely ");
                        self.write_text(length.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::ftruncate => {
                let filename = self.displayable_ol(0);
                let length = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("change the size of the file: ");
                        self.write_path_file(filename);
                        self.general_text(" to precisely ");
                        self.write_text(length.custom_color(*(OUR_YELLOW)));
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::select => {
                let highest_fd = registers[0];
                let readfds = registers[1];
                let writefds = registers[2];
                let exceptfds = registers[3];
                let timeout = registers[4];
                match self.state {
                    Entering => {
                        self.general_text("block all ");
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push(
                                "read-waiting".custom_color(*(OUR_YELLOW)),
                            );

                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     SyscallObject::read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         registers[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push(
                                "write-waiting".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if exceptfds != 0 {
                            blockers.push(
                                "error-waiting".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.anding_handler(blockers);
                        self.general_text(" file descriptors lower than ");
                        self.write_text(highest_fd.to_string().blue());

                        if timeout > 0 {
                            let timeval = SyscallObject::read_bytes_as_struct::<16, timeval>(
                                registers[4] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timeval(timeval.tv_sec, timeval.tv_usec);
                        } else {
                            self.general_text(", and ");
                            self.write_text(
                                "wait forever".custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if res == 0 {
                                self.write_text("timed out before any events".green());
                            } else if res > 0 {
                                self.write_text(res.to_string().blue());
                                self.write_text(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pselect6 => {
                let highest_fd = registers[0];
                let readfds = registers[1];
                let writefds = registers[2];
                let exceptfds = registers[3];
                let timeout = registers[4];
                let signal_mask = registers[5];
                match self.state {
                    Entering => {
                        self.general_text("block for events on all ");
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push(
                                "read-waiting".custom_color(*(OUR_YELLOW)),
                            );

                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     SyscallObject::read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         registers[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push(
                                "write-waiting".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if exceptfds != 0 {
                            blockers.push(
                                "error-waiting".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.anding_handler(blockers);
                        self.general_text(" file descriptors lower than ");
                        self.write_text(highest_fd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", and ");
                            self.write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if timeout > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                registers[4] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                        } else {
                            self.general_text(", and ");
                            self.write_text(
                                "wait forever".custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if res == 0 {
                                self.write_text("timed out before any events".green());
                            } else if res > 0 {
                                self.write_text(res.to_string().blue());
                                self.write_text(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::poll => {
                let nfds = registers[1];
                let timeout = registers[2];
                match self.state {
                    Entering => {
                        self.general_text("block for new events on the ");
                        self.write_text(nfds.to_string().blue());
                        self.general_text(" provided file descriptors, ");
                        self.general_text("and timeout after ");
                        self.write_text(timeout.to_string().blue());
                        self.general_text(" milliseconds");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if num_fds == 0 {
                                self.write_text("timed out before any events".green());
                            } else {
                                self.write_text(num_fds.to_string().blue());
                                self.write_text(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::ppoll => {
                let nfds = registers[1];
                let timeout = registers[2];
                let signal_mask = registers[3];

                match self.state {
                    Entering => {
                        self.general_text("block for new events on the ");
                        self.write_text(nfds.to_string().blue());
                        self.general_text(" provided file descriptors");

                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if timeout > 0 {
                            self.general_text(", and timeout ");
                            if let Some(timespec) =
                                SyscallObject::read_bytes_as_struct::<16, timespec>(
                                    registers[2] as usize,
                                    self.process_pid as _,
                                )
                            {
                                self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                            } else {
                                self.write_text(
                                    "[intentrace: could not get timeout]".blink().bright_black(),
                                );
                            }
                        } else {
                            self.general_text(", and ");
                            self.write_text(
                                "wait forever".custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();

                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if num_fds == 0 {
                                self.write_text("timed out before any events".green());
                            } else {
                                self.write_text(num_fds.to_string().blue());
                                self.write_text(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_create => {
                let nfds = registers[0];
                match self.state {
                    Entering => {
                        self.general_text("create an epoll instance with a capacity of ");
                        self.write_text(
                            nfds.to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" file descriptors");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_create1 => {
                let flags = registers[0];
                match self.state {
                    Entering => {
                        self.general_text("create an epoll instance ");

                        if flags as i32 == EPOLL_CLOEXEC {
                            self.general_text("(");
                            self.write_text(
                                "close file descriptors on the next exec syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_wait => {
                let epfd = registers[0];
                let max_events = registers[2];
                let time = registers[3];
                match self.state {
                    Entering => {
                        self.general_text("block until a maximum of ");
                        self.write_text(
                            max_events
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" events occur on epoll instance ");
                        self.write_text(epfd.to_string().blue());
                        if time > 0 {
                            self.general_text(" and wait for ");
                            self.write_text(time.to_string().blue());
                            self.write_text(
                                " milliseconds".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.write_text(
                                " and wait forever"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_pwait => {
                let epfd = registers[0];
                let max_events = registers[2];
                let time = registers[3];
                let signal_mask = registers[4];
                match self.state {
                    Entering => {
                        self.general_text("block until a maximum of ");
                        self.write_text(
                            max_events
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" events occur on epoll instance ");
                        self.write_text(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if time > 0 {
                            self.general_text(" and wait for ");
                            self.write_text(time.to_string().blue());
                            self.write_text(
                                " milliseconds".custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.write_text(
                                " and wait forever"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_pwait2 => {
                let epfd = registers[0];
                let max_events = registers[2];
                let time = registers[3];
                let signal_mask = registers[4];
                match self.state {
                    Entering => {
                        self.general_text("block until a maximum of ");
                        self.write_text(
                            max_events
                                .to_string()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" events occur on epoll instance ");
                        self.write_text(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if time > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                registers[3] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                        } else {
                            self.write_text(
                                " and wait forever"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_ctl => {
                let epfd = registers[0];
                let operation = registers[1];
                let file_descriptor = registers[2];
                match self.state {
                    Entering => {
                        if (operation as i32 & EPOLL_CTL_ADD) == EPOLL_CTL_ADD {
                            self.write_text(
                                "add".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" file descriptor ");
                            self.write_text(file_descriptor.to_string().blue());
                            self.general_text(" to ");
                        } else if (operation as i32 & EPOLL_CTL_DEL) == EPOLL_CTL_DEL {
                            self.write_text(
                                "remove".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" file descriptor ");
                            self.write_text(file_descriptor.to_string().blue());
                            self.general_text(" from ");
                        } else if (operation as i32 & EPOLL_CTL_MOD) == EPOLL_CTL_MOD {
                            self.write_text(
                                "modify the settings of "
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" file descriptor ");
                            self.write_text(file_descriptor.to_string().blue());
                            self.general_text(" in ");
                        }
                        self.general_text("epoll instance ");
                        self.write_text(epfd.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::ioctl => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("perform operation ");
                        self.write_text(
                            format!("#{}", registers[1].to_string())
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" on the device: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("operation successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fcntl => {
                let filename = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("perform operation ");
                        self.write_text(
                            format!("#{}", registers[1].to_string())
                                .custom_color(*(OUR_YELLOW)),
                        );
                        self.general_text(" on the file: ");
                        self.write_path_file(filename);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("operation successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::arch_prctl => {
                // workaround values for now
                let ARCH_SET_GS = 0x1001;
                let ARCH_SET_FS = 0x1002;
                let ARCH_GET_FS = 0x1003;
                let ARCH_GET_GS = 0x1004;
                let ARCH_GET_CPUID = 0x1011;
                let ARCH_SET_CPUID = 0x1012;

                let operation = registers[0];
                let value = registers[1];

                match self.state {
                    Entering => {
                        if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                            if value == 0 {
                                self.general_text(
                                    "disable the `cpuid` instruction for the calling thread",
                                );
                            } else {
                                self.general_text(
                                    "enable the `cpuid` instruction for the calling thread",
                                );
                            }
                        } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                            self.general_text(
                                "check whether the `cpuid` instruction is enabled or disabled",
                            );
                        } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                            self.general_text("Set the 64-bit base for the FS register to ");
                            self.write_text(value.to_string().blue());
                        } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                            self.general_text(
                                "retrieve the calling thread's 64-bit FS register value",
                            );
                        } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                            self.general_text("Set the 64-bit base for the GS register to ");
                            self.write_text(value.to_string().blue());
                        } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                            self.general_text(
                                "retrieve the calling thread's 64-bit GS register value",
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");

                            if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                                if value == 0 {
                                    self.write_text(
                                        "successfully disabled the `cpuid` instruction".green(),
                                    );
                                } else {
                                    self.write_text(
                                        "successfully enabled the `cpuid` instruction".green(),
                                    );
                                }
                            } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                                let value = self.displayable_ol(1).parse::<u64>().unwrap();

                                if value == 0 {
                                    self.write_text("the `cpuid` instruction is disabled".green());
                                } else {
                                    self.write_text("the `cpuid` instruction is enabled".green());
                                }
                            } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                                self.write_text("FS register modified".green());
                            } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                                let value = self.displayable_ol(1);
                                self.write_text("retrieved value of the FS register: ".green());
                                self.write_text(value.blue());
                            } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                                self.write_text("GS register modified".green());
                            } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                                let value = self.displayable_ol(1);
                                self.write_text("value of the GS register ".green());
                                self.write_text(value.blue());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sched_yield => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "relinquish the CPU, and move to the end of the scheduler queue",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully yielded CPU".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigaction => {
                let signal_num = registers[0];
                let signal_action = registers[1] as *const ();
                let old_signal_action = registers[2] as *const ();

                match self.state {
                    Entering => {
                        // syscall must only use one of the first two arguments, never both

                        // struct sigaction {

                        // 3 flags
                        // •  SIG_DFL for the default action.
                        // •  SIG_IGN to ignore this signal.
                        // •  A pointer to a signal handling function. This function receives the signal number as its only argument.
                        // void (*sa_handler)(int);

                        // this argument is used If  SA_SIGINFO  is  specified  in sa_flags,
                        //     void     (*sa_sigaction)(int, siginfo_t *, void *);

                        // mask of signals which should be blocked (process signal mask)
                        //     sigset_t   sa_mask;

                        // set of flags which modify the behavior of the signal. bitwise ORing
                        //     int        sa_flags;

                        //     void     (*sa_restorer)(void);
                        // };

                        // TODO! Granularity
                        // if !signal_action.is_null() {
                        //     let sigaction = SyscallObject::read_bytes_as_struct::<152, sigaction>(
                        //         registers[1] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("sigaction",sigaction);
                        // }

                        // if !old_signal_action.is_null() {
                        //     let old_sigaction = SyscallObject::read_bytes_as_struct::<152, sigaction>(
                        //         registers[2] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("old_sigaction",old_sigaction);
                        // }

                        match x86_signal_to_string(signal_num) {
                            Some(signal_as_string) => {
                                // TODO:
                                // differentiate between SIG_DFL, SIG_IGN, and handlers
                                // this means reading the sigaction struct
                                //
                                //
                                //
                                /* blocked for now
                                let sigaction = SyscallObject::read_bytes_as_struct::<152, sigaction>(
                                    registers[1] as usize,
                                    self.process_pid as _,
                                )
                                .unwrap();
                                */

                                //
                                // there was some confusion here around
                                // the kernel's definition (a union of sa_sigaction and sa_handler)
                                // contradicting rust's libc sigaction definition (not a union)
                                // https://github.com/rust-lang/libc/issues/3269#issuecomment-1589035328
                                //
                                // also rust's libc 1.0 milestone mentions switching to rust unions
                                // https://github.com/rust-lang/libc/issues/1020
                                //
                                //
                                //

                                // second is non-NULL: the new action for signal signum is installed from act.
                                // third is non-NULL: the previous action is saved in oldact.
                                // second is NULL: query the current signal handler
                                // second and third is NULL: check whether a given signal is valid for the current machine
                                if !signal_action.is_null() {
                                    self.general_text("change the process's default handler for ");
                                    self.write_text(
                                        signal_as_string
                                            .custom_color(*(OUR_YELLOW)),
                                    );
                                    self.general_text(" to the provided action");
                                    if !old_signal_action.is_null() {
                                        self.general_text(
                                            ", and retrieve the current signal handler",
                                        );
                                    }
                                } else {
                                    if !old_signal_action.is_null() {
                                        self.general_text("retrieve the current signal handler");
                                    } else {
                                        self.general_text(
                                            "check if the current machine supports: ",
                                        );
                                        self.write_text(
                                            signal_as_string
                                                .custom_color(*(OUR_YELLOW)),
                                        );
                                    }
                                }
                            }
                            None => {
                                self.write_text(
                                    "[intentrace: signal not supported on x86]"
                                        .blink()
                                        .bright_black(),
                                );
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            match x86_signal_to_string(signal_num) {
                                Some(signal_as_string) => {
                                    if !signal_action.is_null() {
                                        self.write_text("default handler changed".green());
                                        if !old_signal_action.is_null() {
                                            self.write_text(
                                                ", and current handler retrieved".green(),
                                            );
                                        }
                                    } else {
                                        if !old_signal_action.is_null() {
                                            self.write_text("current handler retrieved".green());
                                        } else {
                                            // TODO! citation needed, but very safe to assume correct
                                            self.write_text("signal supported".green());
                                        }
                                    }
                                }
                                None => {
                                    self.write_text("successful".green());
                                }
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigprocmask => {
                let how: nix::sys::signal::SigmaskHow =
                    unsafe { std::mem::transmute(registers[0] as u32) };
                let set = registers[1] as *const ();
                let old_set = registers[2] as *const ();
                match self.state {
                    Entering => {
                        if set.is_null() {
                            if !old_set.is_null() {
                                self.general_text(
                                    "retrieve the proccess's current list of blocked signals",
                                );
                            } else {
                                self.write_text("[intentrace Notice: syscall no-op]".blink());
                            }
                        } else {
                            match how {
                                nix::sys::signal::SigmaskHow::SIG_BLOCK => {
                                    self.general_text("add any missing signal from the provided signals to the proccess's list of blocked signals");
                                }
                                nix::sys::signal::SigmaskHow::SIG_UNBLOCK => {
                                    self.general_text("remove the provided signals from the proccess's list of blocked signals");
                                }
                                nix::sys::signal::SigmaskHow::SIG_SETMASK => {
                                    self.general_text("replace the proccess's list of blocked signals with the signals provided");
                                }
                                _ => {}
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            if set.is_null() {
                                if !old_set.is_null() {
                                    self.write_text("retrieved blocked signals".green());
                                } else {
                                    self.write_text("[intentrace Notice: syscall no-op]".blink());
                                }
                            } else {
                                match how {
                                    nix::sys::signal::SigmaskHow::SIG_BLOCK => {
                                        self.write_text("signals added".green());
                                    }
                                    nix::sys::signal::SigmaskHow::SIG_UNBLOCK => {
                                        self.write_text("signals removed".green());
                                    }
                                    nix::sys::signal::SigmaskHow::SIG_SETMASK => {
                                        self.write_text("successfully replaced".green());
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigsuspend => {
                match self.state {
                    Entering => {
                        self.general_text("replace the process' list of blocked signals with the signals provided, then wait until the delivery of either a signal that invokes a signal handler or a signal that terminates the thread");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("list of blocked signals modified".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sigaltstack => {
                let new_stack_null = (registers[0] as u32 as *const ()).is_null();
                let old_stack_null = (registers[1] as u32 as *const ()).is_null();

                match self.state {
                    Entering => match (new_stack_null, old_stack_null) {
                        (true, true) => {
                            self.write_text(
                                "[intentrace: redundant syscall (won't do anything)]".blink(),
                            );
                        }
                        (true, false) => {
                            self.general_text("replace the current signal stack with a new one");
                        }
                        (false, true) => {
                            self.general_text("retrieve the current signal stack");
                        }
                        (false, false) => {
                            self.general_text("retrieve the current signal stack and then replace it with a new one,",
                        );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            match (new_stack_null, old_stack_null) {
                                (true, true) => {
                                    self.write_text("successful".green());
                                }
                                (true, false) => {
                                    self.write_text("successfully replaced".green());
                                }
                                (false, true) => {
                                    self.write_text("signal stack retrieved".green());
                                }
                                (false, false) => {
                                    self.write_text(
                                        "signal stack replaced and old signal stack retrieved"
                                            .green(),
                                    );
                                }
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigreturn => {
                match self.state {
                    Entering => {
                        self.general_text("return from signal handler and cleanup");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigpending => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "return the signals pending for delivery for the calling thread",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("pending signals returned".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigtimedwait => {
                match self.state {
                    Entering => {
                        // TODO! use the timespec struct
                        self.general_text("stop the calling process until one of the signals provided is pending, or the given timeout is exceeded");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_sigqueueinfo => {
                let thread_group = registers[0];
                let signal_num = registers[1];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.general_text("send the data attached and the ");
                            self.write_text(
                                signal_as_string.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" signal to the thread group: ");
                            self.write_text(
                                thread_group
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        None => {
                            self.write_text(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("data and signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rt_tgsigqueueinfo => {
                let thread_group = registers[0];
                let thread = registers[1];
                let signal_num = registers[2];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.general_text("send the data attached and the ");
                            self.write_text(
                                signal_as_string.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" signal to thread: ");
                            self.write_text(
                                thread
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" in thread group: ");
                            self.write_text(
                                thread_group
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        None => {
                            self.write_text(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("data and signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pidfd_send_signal => {
                let process = self.displayable_ol(0);
                let signal_num = registers[1];
                match self.state {
                    Entering => {
                        match x86_signal_to_string(signal_num) {
                            Some(signal_as_string) => {
                                self.general_text("send the ");
                                self.write_text(
                                    signal_as_string
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                // bad wording
                                self.general_text(
                                    " signal to the process identified with the file descriptor: ",
                                );
                                self.write_text(
                                    process.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            None => {
                                self.write_text(
                                    "[intentrace: signal not supported on x86]"
                                        .blink()
                                        .bright_black(),
                                );
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::signalfd => {
                let fd = registers[0] as i32;
                match self.state {
                    Entering => {
                        if fd == -1 {
                            self.general_text("create a new file descriptor for receiving the set of specified signals",
                    );
                        } else {
                            let fd_file = self.displayable_ol(0);
                            self.general_text("use the file: ");
                            self.write_path_file(fd_file);
                            self.general_text(" to receive the provided signals");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::signalfd4 => {
                let fd = registers[0] as i32;
                let flags: SfdFlags = unsafe { std::mem::transmute(registers[2] as u32) };
                match self.state {
                    Entering => {
                        if fd == -1 {
                            self.general_text("create a file descriptor to use for receiving the provided signals",
                            );
                        } else {
                            let fd_file = self.displayable_ol(0);
                            self.general_text("use the file: ");
                            self.write_path_file(fd_file);
                            self.general_text(" to receive the provided signals");
                        }
                        let mut flag_directives = vec![];

                        if flags.contains(SfdFlags::SFD_CLOEXEC) {
                            flag_directives.push(
                                "close the file with the next exec syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(SfdFlags::SFD_NONBLOCK) {
                            flag_directives.push(
                                "use the file on non blocking mode"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(flag_directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("file descriptor created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::gettid => {
                match self.state {
                    Entering => {
                        self.general_text("get the thread id of the calling thread");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let thread = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the thread id: ".green());
                            self.write_text(
                                thread.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getpid => {
                match self.state {
                    Entering => {
                        self.general_text("get the process id of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let process_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the process id: ".green());
                            self.write_text(
                                process_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getppid => {
                match self.state {
                    Entering => {
                        self.general_text("get the process id of the parent process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let process_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the parent process' id: ".green());
                            self.write_text(
                                process_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::get_robust_list => {
                let process_id_num = registers[0];
                match self.state {
                    Entering => {
                        self.general_text("get the list of the robust futexes for ");
                        if process_id_num == 0 {
                            self.write_text(
                                "the calling thread"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.general_text("thread ");
                            self.write_text(process_id_num.to_string().blue());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let address = self.displayable_ol(1);
                            let length_of_list = SyscallObject::read_word(
                                registers[2] as usize,
                                self.process_pid,
                            )
                            .unwrap();
                            self.general_text(" |=> ");
                            self.write_text("head of the retrieved list is stored in ".green());
                            self.write_text(
                                address.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(" with length ".green());
                            self.write_text(length_of_list.to_string().blue());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::set_robust_list => {
                let address = self.displayable_ol(0);
                let length_of_list = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text(
                            "set the calling thread's robust futexes list to the list at ",
                        );
                        self.write_text(address.custom_color(*(OUR_YELLOW)));
                        self.general_text(" with length ");
                        self.write_text(length_of_list.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::setpgid => {
                let process_id_num = registers[0];
                let process_id = self.displayable_ol(0);
                let new_pgid_num = registers[1];
                let new_pgid = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        if process_id_num == 0 {
                            self.general_text("set the process group ID of ");
                            self.write_text(
                                "the calling thread"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.general_text("set the process group ID of process: ");
                            self.write_text(
                                process_id.custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if new_pgid_num == 0 {
                            self.general_text(" to: ");
                            self.write_text(
                                "the calling process' ID"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.general_text(" to: ");
                            self.write_text(
                                new_pgid.custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getpgid => {
                let process_id_num = registers[0];
                let process_id = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        if process_id_num == 0 {
                            self.general_text("get the process group ID of ");
                            self.write_text(
                                "the calling thread"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.general_text("get the process group ID of process: ");
                            self.write_text(
                                process_id.custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let pgid = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the group id: ".green());
                            self.write_text(pgid.custom_color(*(OUR_YELLOW)));
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getpgrp => {
                match self.state {
                    Entering => {
                        self.general_text("get the process group ID of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let pgid = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the group id: ".green());
                            self.write_text(pgid.custom_color(*(OUR_YELLOW)));
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getrandom => {
                let random_flags: GetRandomFlags =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let bytes_num = registers[1];
                let bytes = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text("get ");
                        self.write_text(bytes.custom_color(*(OUR_YELLOW)));
                        self.general_text(" of random bytes from the ");
                        if random_flags.contains(GetRandomFlags::RANDOM) {
                            self.write_text(
                                "random source".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" and ");
                            if random_flags.contains(GetRandomFlags::NONBLOCK) {
                                self.write_text(
                                    "do not block if the random source is empty"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "block if the random source is empty"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            self.write_text(
                                "urandom source".custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" and ");
                            if random_flags.contains(GetRandomFlags::NONBLOCK) {
                                self.write_text(
                                    "do not block if the entropy pool is uninitialized"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "block if the entropy pool is uninitialized"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_retrieved = self.result.0.unwrap();

                            self.general_text(" |=> ");
                            if bytes_retrieved == 0 {
                                self.write_text("retrieved ".green());
                                self.write_text(eph_return.unwrap().green());
                            } else if bytes_retrieved < bytes_num {
                                self.write_text("retrieved ".green());
                                self.write_text(eph_return.unwrap().green());
                                self.write_text(" (fewer than requested)".green());
                            } else {
                                self.write_text("retrieved all ".green());
                                self.write_text(eph_return.unwrap().green());
                                self.write_text(" (complete)".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::setrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(registers[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("set the process's ");
                        self.resource_matcher(resource);
                        self.general_text(" to the soft and hard limits provided");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(registers[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get the soft and hard limits for the process's ");
                        self.resource_matcher(resource);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::prlimit64 => {
                let pid = registers[0] as pid_t;
                let resource: Resource = unsafe { std::mem::transmute(registers[1] as u32) };
                let set_struct = registers[2] as *const ();
                let get_struct = registers[3] as *const ();
                let pid_of_self = pid == 0;
                match self.state {
                    Entering => {
                        if !set_struct.is_null() {
                            self.general_text("set ");
                            if pid_of_self {
                                self.write_text(
                                    "the calling process's"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text("'s");
                            }
                            self.general_text(" ");
                            self.resource_matcher(resource);
                            self.general_text(" to the soft and hard limits provided");
                            if !get_struct.is_null() {
                                self.write_text(
                                    ", and get the old limits"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else if !get_struct.is_null() {
                            self.general_text("get the soft and hard limits for ");
                            if pid_of_self {
                                self.write_text(
                                    "the calling process's"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text("'s");
                            }
                            self.general_text(" ");
                            self.resource_matcher(resource);
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            let rlims = SyscallObject::read_bytes_as_struct::<16, rlimit>(
                                registers[3] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            match resource {
                                Resource::RLIMIT_AS => {
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_CORE => {
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_CPU => {
                                    // maximum time in seconds to use in the CPU
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" seconds".green());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" seconds".green());
                                }
                                Resource::RLIMIT_DATA => {
                                    // maximum data segment size
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_FSIZE => {
                                    // maximum allowed size of files to creates
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_NOFILE => {
                                    // maximum allowed open file descriptors
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" fds".green());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" fds".green());
                                }
                                Resource::RLIMIT_STACK => {
                                    // maximum stack size
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_LOCKS => {
                                    // maximum number of flock() locks and fcntl() leases
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_MEMLOCK => {
                                    // maximum amount of memory that can be locked
                                    // affects mlock
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_MSGQUEUE => {
                                    // maximum number of bytes to use on message queues
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_NICE => {
                                    // maximum nice value
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_NPROC => {
                                    // maximum number of threads
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" threads".green());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" threads".green());
                                }
                                Resource::RLIMIT_RSS => {
                                    // maximum RSS memory
                                    // affects madvise
                                    self.write_text("soft limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.write_text(", hard limit: ".green());
                                    self.write_text(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_RTPRIO => {
                                    // real-time priority
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_RTTIME => {
                                    // Specifies a limit (in microseconds) on the amount of CPU time
                                    // that a process scheduled under a real-time scheduling policy
                                    // may consume without making a blocking system call.

                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" micro-seconds".green());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" micro-seconds".green());
                                }
                                Resource::RLIMIT_SIGPENDING => {
                                    // maximum number of queued pending signals
                                    self.write_text("soft limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" signals".green());
                                    self.write_text(", hard limit: ".green());
                                    self.write_text((rlims.rlim_cur as usize).to_string().blue());
                                    self.write_text(" signals".green());
                                }

                                _ => {}
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getrusage => {
                let resource: UsageWho = unsafe { std::mem::transmute(registers[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get resource usage metrics for ");

                        match resource {
                            UsageWho::RUSAGE_SELF => {
                                self.write_text("the calling process (sum of resource usage for all threads in the process)".custom_color(*(OUR_YELLOW)));
                            }
                            UsageWho::RUSAGE_CHILDREN => {
                                self.write_text("all the terminated children and further descendants of the calling process".custom_color(*(OUR_YELLOW)));
                            }
                            UsageWho::RUSAGE_THREAD => {
                                self.write_text(
                                    "the calling thread"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                            _ => todo!(),
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sysinfo => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "get memory and swap usage metrics for the calling process",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::times => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "get time metrics for the calling process and its children",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sched_setaffinity => {
                let thread_id = registers[0];

                let cpus = SyscallObject::read_affinity_from_child(
                    registers[2] as usize,
                    self.process_pid,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        if !cpus.is_empty() {
                            self.general_text("only allow ");
                            if thread_id == 0 {
                                self.write_text(
                                    "the calling thread"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "thread ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    thread_id
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                            self.general_text(" to run on ");
                            let mut cpu_iter = cpus.into_iter();
                            self.write_text(
                                format!("[CPU {}]", cpu_iter.next().unwrap())
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            for cpu in cpu_iter {
                                self.write_text(
                                    ", ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    format!("[CPU {}]", cpu)
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else {
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("thread successfully locked".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sched_getaffinity => {
                let thread_id = registers[0];
                // let cpu_set: cpu_set_t = unsafe { std::mem::transmute(args_vec[2] as u32) };
                // let num_cpus = num_cpus::get();
                let mut set: cpu_set_t = unsafe { mem::zeroed() };

                let cpus = SyscallObject::read_affinity_from_child(
                    registers[2] as usize,
                    self.process_pid,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        self.general_text("find which CPUs ");
                        if thread_id == 0 {
                            self.write_text(
                                "the calling thread"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            self.write_text(
                                "thread ".custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                thread_id
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" is allowed to run on");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("CPUs allowed: ".green());
                            if cpus.is_empty() {
                                self.general_text("None");
                            } else {
                                let mut cpu_iter = cpus.into_iter();
                                self.write_text(
                                    format!("[CPU {}]", cpu_iter.next().unwrap()).bright_blue(),
                                );
                                for cpu in cpu_iter {
                                    self.write_text(", ".green());
                                    self.write_text(format!("[CPU {}]", cpu).bright_blue());
                                }
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::exit => {
                let status = registers[0] as i32;
                match self.state {
                    Entering => {
                        self.general_text("exit the calling process with status: ");
                        if status < 0 {
                            self.write_text(status.to_string().red());
                        } else {
                            self.write_text(
                                status
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" |=> ");
                        self.write_text("process exited with status ".green());
                        self.write_text(status.to_string().blue());
                    }
                    _ => unreachable!(),
                }
            }
            Sysno::exit_group => {
                let status = registers[0] as i32;
                match self.state {
                    Entering => {
                        self.general_text("exit all threads in the group with status: ");
                        if status < 0 {
                            self.write_text(status.to_string().red());
                        } else {
                            self.write_text(
                                status
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" |=> ");
                        self.write_text("all threads in the group exited with status ".green());
                        self.write_text(status.to_string().blue());
                    }
                    _ => unreachable!(),
                }
            }
            Sysno::kill => {
                let pid = registers[0] as i64;
                let signal_num = registers[1];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            if signal_num == 0 {
                                // this is a way to check if a process is alive or dead, (sending signal 0 -not a real signal-)
                                // TODO!
                                // decide if its better to communicate the intention (checking if a process exists)
                                // or to be explicit and state that a null signal was sent
                                // this needs to be rephrased
                                self.general_text("send a null signal to process: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" (check if the process exists)");
                            } else {
                                self.general_text("send ");
                                self.write_text(
                                    signal_as_string
                                        .custom_color(*(OUR_YELLOW)),
                                );

                                if pid > 0 {
                                    self.general_text(" to process: ");
                                    self.write_text(
                                        pid.to_string()
                                            .custom_color(*(PAGES_COLOR)),
                                    );
                                } else if pid == 0 {
                                    self.general_text(" to all processes in this process group");
                                } else if pid == -1 {
                                    self.general_text(" to all processes that the calling process has permissions to send to");
                                } else if pid < -1 {
                                    self.general_text(" to process group: ");
                                    self.write_text(
                                        (pid * -1)
                                            .to_string()
                                            .custom_color(*(PAGES_COLOR)),
                                    );
                                }
                            }
                        }
                        None => {
                            self.write_text(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::tgkill => {
                let thread_group = registers[0];
                let thread = registers[1];
                let signal_num = registers[2];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.general_text("send ");
                            self.write_text(
                                signal_as_string.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" to thread: ");
                            self.write_text(
                                thread
                                    .to_string()
                                    .custom_color(*(PAGES_COLOR)),
                            );
                            self.general_text(" in thread group: ");
                            self.write_text(
                                thread_group
                                    .to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        None => {
                            self.write_text(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::tkill => {
                let thread = registers[0];
                let signal_num = registers[1];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.general_text("send ");
                            self.write_text(
                                signal_as_string.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" to thread: ");
                            self.write_text(
                                thread
                                    .to_string()
                                    .custom_color(*(PAGES_COLOR)),
                            );
                        }
                        None => {
                            self.write_text(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pause => {
                match self.state {
                    Entering => {
                        self.general_text("pause execution until a signal terminates the process or triggers a handler");
                    }
                    Exiting => {
                        // getting here means a signal handler was triggered
                        // and this path always errors
                        self.one_line_error();
                    }
                }
            }
            Sysno::ptrace => {
                let operation: nix::sys::ptrace::Request =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        match operation {
                            ptrace::Request::PTRACE_TRACEME => self.general_text(
                                "allow this process to be trace by its parent process",
                            ),
                            ptrace::Request::PTRACE_PEEKTEXT => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];

                                self.general_text("read one word at address: ");
                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the TEXT area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_PEEKDATA => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];

                                self.general_text("read one word at address: ");

                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the DATA area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_PEEKUSER => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];

                                self.general_text("read one word at address: ");
                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the USER area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_POKETEXT => {
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];
                                let data = parse_register_as_address(registers[3]);

                                self.general_text("copy the word: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" to the TEXT area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" at the address: ");
                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            ptrace::Request::PTRACE_POKEDATA => {
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];
                                let data = parse_register_as_address(registers[3]);

                                self.general_text("copy the word: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" to the DATA area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" at the address: ");
                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            ptrace::Request::PTRACE_POKEUSER => {
                                let addr = parse_register_as_address(registers[2]);
                                let pid = registers[1];
                                let data = parse_register_as_address(registers[3]);

                                self.general_text("copy the word: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" to the USER area of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" at the address: ");
                                self.write_text(
                                    addr.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            ptrace::Request::PTRACE_GETREGS => {
                                let data = parse_register_as_address(registers[3]);
                                let pid = registers[1];
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                self.general_text("copy the registers of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" into address: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" of this process's memory");
                            }
                            ptrace::Request::PTRACE_GETFPREGS => {
                                let data = parse_register_as_address(registers[3]);
                                let pid = registers[1];
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                self.general_text(
                                    "copy the floating point registers of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" into address: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" of this process's memory");
                            }
                            ptrace::Request::PTRACE_SETREGS => {
                                // Modify the tracee's general-purpose registers, from the address data in the tracer.
                                let data = parse_register_as_address(registers[3]);
                                let pid = registers[1];
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                self.general_text("replace the registers of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" with the registers at: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            ptrace::Request::PTRACE_SETFPREGS => {
                                // Modify the tracee's floating-point registers, from the address data in the tracer.
                                let data = parse_register_as_address(registers[3]);
                                let pid = registers[1];
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                self.general_text(
                                    "replace the floating point registers of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" with the registers at: ");
                                self.write_text(
                                    data.custom_color(*(OUR_YELLOW)),
                                );
                            }
                            ptrace::Request::PTRACE_ATTACH => {
                                let pid = registers[1];
                                // Attach to the process specified in pid, making it a tracee of the calling process.
                                // the tracee is sent a SIGSTOP, but will not necessarily have stopped by the completion of this call
                                self.general_text(
                                    "attach to and start tracing the process with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_SEIZE => {
                                let pid = registers[1];
                                // Attach to the process specified in pid, making it a tracee of the calling process.
                                // Unlike PTRACE_ATTACH, PTRACE_SEIZE does not stop the process.
                                // Only a PTRACE_SEIZEd process can accept PTRACE_INTERRUPT and PTRACE_LISTEN commands.
                                self.general_text(
                                    "attach to and start tracing the process with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" without stopping it");
                            }
                            ptrace::Request::PTRACE_INTERRUPT => {
                                let pid = registers[1];
                                // Stop a tracee.
                                // Currently, there's no way to trap a running ptracee short of sending a
                                // signal which has various side effects.  This patch implements
                                // PTRACE_INTERRUPT which traps ptracee without any signal or job control related side effect.
                                // https://lore.kernel.org/lkml/1308043218-23619-4-git-send-email-tj@kernel.org/
                                // PTRACE_INTERRUPT only works on tracees attached by PTRACE_SEIZE.
                                self.general_text("stop the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" without sending a signal");
                            }
                            ptrace::Request::PTRACE_DETACH => {
                                let pid = registers[1];
                                // Continue the stopped tracee like PTRACE_CONT, but first detach from it.
                                // Under Linux, a tracee can be detached in this way regardless of which  method  was  used  to initiate tracing.
                                self.general_text(
                                    "detach from and continue the execution of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_CONT => {
                                let pid = registers[1];
                                let data = registers[3];
                                self.general_text(
                                    "continue the execution of the stopped tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                if data > 0 {
                                    self.general_text(" and deliver the signal: ");
                                    match x86_signal_to_string(data) {
                                        Some(signal_as_string) => {
                                            self.write_text(
                                                signal_as_string.custom_color(
                                                    *(OUR_YELLOW),
                                                ),
                                            );
                                        }
                                        None => {
                                            self.write_text(
                                                "[intentrace: signal not supported on x86]"
                                                    .blink()
                                                    .bright_black(),
                                            );
                                        }
                                    }
                                }
                            }
                            ptrace::Request::PTRACE_LISTEN => {
                                let pid = registers[1];
                                // continue the stopped tracee, but prevent it from executing.
                                // The resulting state of the tracee is similar to a process which has been stopped by a SIGSTOP (or other stopping signal).
                                // See the "group-stop" subsection for additional information.
                                // PTRACE_LISTEN works only on tracees attached by PTRACE_SEIZE.
                                self.general_text("continue running the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" without resuming execution");
                            }
                            ptrace::Request::PTRACE_KILL => {
                                let pid = registers[1];
                                // requires the tracee to be in signal-delivery-stop
                                // otherwise it may not work (i.e., may complete successfully but won't kill the tracee)
                                // Send the tracee a SIGKILL to terminate it
                                self.general_text("terminate the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" with a ");
                                self.write_text(
                                    "SIGKILL".custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" signal");
                            }
                            ptrace::Request::PTRACE_SINGLESTEP => {
                                let pid = registers[1];
                                // Continue a stopped tracee like PTRACE_CONT, but the tracee now stops after execution of a single instruction
                                self.general_text(
                                    "continue the execution of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" and stop again after one instruction");
                            }
                            ptrace::Request::PTRACE_SYSCALL => {
                                let pid = registers[1];
                                // Continue a stopped tracee like PTRACE_CONT, but the tracee now stops at the next entry to or exit from a system call
                                self.general_text(
                                    "continue the execution of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(
                                    " and stop again after the next syscall entry/exit",
                                );
                            }
                            ptrace::Request::PTRACE_SETOPTIONS => {
                                // TODO!
                                // consider providing more information similar to clone3?
                                let pid = registers[1];
                                self.general_text(
                                    "set the tracing options for the process with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_GETEVENTMSG => {
                                let pid = registers[1];
                                // Retrieve a message about the ptrace event that just happened (as an unsigned long)
                                // For PTRACE_EVENT_EXIT, this is the tracee's exit status
                                // For PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE, and PTRACE_EVENT_CLONE, this is the PID of the new process
                                // For PTRACE_EVENT_SECCOMP, this is the seccomp(2) filter's SECCOMP_RET_DATA associated with the triggered rule (addr is ignored)
                                self.general_text(
                                    "retrieve additional information about the most recent event from the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_GETREGSET => {
                                let pid = registers[1];
                                // Read  the  tracee's  registers.  addr specifies the type of registers to be read.
                                // NT_PRSTATUS (with numerical value 1) usually results in reading of general-purpose registers.
                                // If the CPU has, for example, floating-point and/or vector registers,
                                // they can be retrieved by setting addr to the corresponding NT_foo constant.
                                // data points to a struct iovec, which describes the destination buffer's location and length.
                                // On return, the kernel modifies  iov.len  to indicate the actual number of bytes returned.
                                //
                                // TODO!
                                // granular
                                //
                                //
                                self.general_text(
                                    "retrieve the registers of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_SETREGSET => {
                                let pid = registers[1];
                                // Modify the tracee's registers
                                // The meaning of addr and data is analogous to PTRACE_GETREGSET
                                self.general_text("modify the registers of the tracee with pid: ");
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_GETSIGINFO => {
                                let pid = registers[1];
                                // PTRACE_GETSIGINFO
                                // get information about the signal that caused the stop.
                                // Copies a siginfo_t structure (see sigaction(2)) from the tracee to the address data in the tracer.
                                //  	(addr is ignored.)
                                //   PTRACE_GETSIGINFO
                                // can be used to retrieve a siginfo_t structure which corresponds to the delivered signal.

                                self.general_text(
                                    "retrieve information about the signal that stopped the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_SETSIGINFO => {
                                let pid = registers[1];
                                // PTRACE_SETSIGINFO
                                // Set signal information: copy a siginfo_t structure from the address data in the tracer to the tracee. This will affect only signals that would normally be delivered to the tracee and were caught by the tracer. It may be difficult to tell these normal signals from synthetic signals generated by ptrace() itself (addr is ignored)

                                //  PTRACE_SETSIGINFO may be used to modify it.
                                //  If PTRACE_SETSIGINFO has been used to alter siginfo_t,
                                //  the si_signo field and the sig parameter in the restarting command must match, otherwise the result is undefined.

                                self.general_text(
                                    "modify information about the signal to be delivered to the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                            }
                            ptrace::Request::PTRACE_PEEKSIGINFO => {
                                let pid = registers[1];
                                // Retrieve siginfo_t structures without removing signals from a queue
                                // struct ptrace_peeksiginfo_args {
                                //  	u64 off; 	/* Ordinal position in queue at which to start copying signals */
                                //  	u32 flags; /* PTRACE_PEEKSIGINFO_SHARED or 0 */
                                //  	s32 nr; 	 /* Number of signals to copy */
                                // };

                                // by default signals are read from the specific thread's own queue
                                // but if PTRACE_PEEKSIGINFO_SHARED is used then process-wide signal queue is read
                                self.general_text(
                                    "retrieve information about a signal from the signal queue of the tracee with pid: ",
                                );
                                self.write_text(
                                    pid.to_string()
                                        .custom_color(*(PAGES_COLOR)),
                                );
                                self.general_text(" without removing it from the queue");
                            }
                            //
                            ptrace::Request::PTRACE_SYSEMU => unimplemented!(),
                            ptrace::Request::PTRACE_SYSEMU_SINGLESTEP => unimplemented!(),
                            ptrace::Request::PTRACE_GETFPXREGS => unimplemented!(),
                            ptrace::Request::PTRACE_SETFPXREGS => unimplemented!(),
                            _ => todo!(),
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            match operation {
                                ptrace::Request::PTRACE_TRACEME => {
                                    self.write_text(
                                        "process can be traced by its parent now".green(),
                                    );
                                }
                                ptrace::Request::PTRACE_PEEKTEXT => {
                                    self.write_text("successfully read one word".green());
                                }
                                ptrace::Request::PTRACE_PEEKDATA => {
                                    self.write_text("successfully read one word".green());
                                }
                                ptrace::Request::PTRACE_PEEKUSER => {
                                    self.write_text("successfully read one word".green());
                                }
                                ptrace::Request::PTRACE_POKETEXT => {
                                    self.write_text("successfully copied one word".green());
                                }
                                ptrace::Request::PTRACE_POKEDATA => {
                                    self.write_text("successfully copied one word".green());
                                }
                                ptrace::Request::PTRACE_POKEUSER => {
                                    self.write_text("successfully copied one word".green());
                                }
                                ptrace::Request::PTRACE_GETREGS => {
                                    self.write_text("registers copied".green());
                                }
                                ptrace::Request::PTRACE_GETFPREGS => {
                                    self.write_text("registers copied".green());
                                }
                                ptrace::Request::PTRACE_SETREGS => {
                                    self.write_text("registers modifed".green());
                                }
                                ptrace::Request::PTRACE_SETFPREGS => {
                                    self.write_text("registers modifed".green());
                                }
                                ptrace::Request::PTRACE_ATTACH => {
                                    self.write_text("process attached".green());
                                }
                                ptrace::Request::PTRACE_SEIZE => {
                                    self.write_text("process seized".green());
                                }
                                ptrace::Request::PTRACE_INTERRUPT => {
                                    self.write_text("tracee stopped".green());
                                }
                                ptrace::Request::PTRACE_DETACH => {
                                    self.write_text(
                                        "detached from the process and execution continued".green(),
                                    );
                                }
                                ptrace::Request::PTRACE_CONT => {
                                    self.write_text("execution continued".green());
                                }
                                ptrace::Request::PTRACE_LISTEN => {
                                    self.write_text("tracee continued".green());
                                }
                                ptrace::Request::PTRACE_KILL => {
                                    self.write_text("tracee terminated".green());
                                }
                                ptrace::Request::PTRACE_SINGLESTEP => {
                                    self.write_text("execution continued".green());
                                }
                                ptrace::Request::PTRACE_SYSCALL => {
                                    self.write_text("execution continued".green());
                                }
                                ptrace::Request::PTRACE_SETOPTIONS => {
                                    self.write_text("options set".green());
                                }
                                ptrace::Request::PTRACE_GETEVENTMSG => {
                                    self.write_text("information retrieved".green());
                                }
                                ptrace::Request::PTRACE_GETREGSET => {
                                    self.write_text("registers retrieved".green());
                                }
                                ptrace::Request::PTRACE_SETREGSET => {
                                    self.write_text("registers modified".green());
                                }
                                ptrace::Request::PTRACE_GETSIGINFO => {
                                    self.write_text("signal information retrieved".green());
                                }
                                ptrace::Request::PTRACE_SETSIGINFO => {
                                    self.write_text("signal information modified".green());
                                }
                                ptrace::Request::PTRACE_PEEKSIGINFO => {
                                    self.write_text("signal information retrieved".green());
                                }
                                //
                                ptrace::Request::PTRACE_SYSEMU => unimplemented!(),
                                ptrace::Request::PTRACE_SYSEMU_SINGLESTEP => unimplemented!(),
                                ptrace::Request::PTRACE_GETFPXREGS => unimplemented!(),
                                ptrace::Request::PTRACE_SETFPXREGS => unimplemented!(),
                                _ => todo!(),
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::rseq => {
                let rseq_flag = registers[2];
                let registering = rseq_flag == 0;
                match self.state {
                    Entering => {
                        if registering {
                            self.general_text("register a per-thread shared data structure between kernel and user-space",
                    );
                        } else {
                            self.general_text("unregister a previously registered per-thread shared data structure",
                    );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            if registering {
                                self.write_text("successfully registered".green());
                            } else {
                                self.write_text("successfully unregistered".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::uname => {
                match self.state {
                    Entering => {
                        self.general_text("retrieve general system information");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("information retrieved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getuid => {
                match self.state {
                    Entering => {
                        self.general_text("get the real user ID of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let user_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the real user ID: ".green());
                            self.write_text(
                                user_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::geteuid => {
                match self.state {
                    Entering => {
                        self.general_text("get the effective user ID of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let user_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the effective user ID: ".green());
                            self.write_text(
                                user_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getgid => {
                match self.state {
                    Entering => {
                        self.general_text("get the real group ID of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let group_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the real group ID: ".green());
                            self.write_text(
                                group_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getegid => {
                match self.state {
                    Entering => {
                        self.general_text("get the effective group ID of the calling process");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let group_id = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("got the effective group ID: ".green());
                            self.write_text(
                                group_id.custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::shutdown => {
                let socket = self.displayable_ol(0);
                let shutdown_how_num = registers[1] as u32;
                let shutdown_how: rustix::net::Shutdown =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        if (shutdown_how_num & 0) == 0 {
                            // SHUT_RD = 0
                            self.general_text("stop incoming reception of data into the socket: ");
                            self.write_text(
                                socket.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (shutdown_how_num & 1) == 1 {
                            // SHUT_WR = 1
                            self.general_text(
                                "stop outgoing transmission of data from the socket: ",
                            );
                            self.write_text(
                                socket.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (shutdown_how_num & 2) == 2 {
                            // SHUT_RDWR = 2
                            self.general_text("terminate incoming and outgoing data communication with the socket: ");
                            self.write_text(
                                socket.custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::futex => {
                let futex1_addr = self.displayable_ol(0);
                let futex2_addr = self.displayable_ol(4);
                let futex_flags_num = registers[1] as i32;
                // let futex_flags: FutexFlags =
                //     unsafe { std::mem::transmute(self.arguments[1] as u32) };
                let futex_ops_num = registers[1] as i32;
                // let futex_ops: FutexOperation =
                //     unsafe { std::mem::transmute(self.arguments[1] as u32) };
                let val = registers[2];
                let val2 = registers[3];
                let timeout = registers[3] as *const ();
                // OPERATION
                match self.state {
                    Entering => {
                        if (futex_ops_num & FUTEX_WAIT) == FUTEX_WAIT {
                            self.write_text(
                                "block and wait for FUTEX_WAKE if comparison succeeds"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (futex_ops_num & FUTEX_WAKE) == FUTEX_WAKE {
                            self.general_text("wake a maximum of ");
                            self.write_text(
                                val.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" waiters waiting on the futex at ");
                            self.write_text(
                                futex1_addr.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (futex_ops_num & FUTEX_FD) == FUTEX_FD {
                            self.general_text("create a file descriptor for the futex at ");
                            self.write_text(
                                futex1_addr.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" to use with asynchronous syscalls");
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE) == FUTEX_CMP_REQUEUE {
                            self.general_text("if comparison succeeds wake a maximum of ");
                            self.write_text(
                                val.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" waiters waiting on the futex at ");
                            self.write_text(
                                futex1_addr.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" and requeue a maximum of ");
                            self.write_text(
                                val2.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" from the remaining waiters to the futex at ");
                            self.write_text(
                                futex2_addr.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (futex_ops_num & FUTEX_REQUEUE) == FUTEX_REQUEUE {
                            self.general_text("without comparing wake a maximum of ");
                            self.write_text(
                                val.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" waiters waiting on the futex at ");
                            self.write_text(
                                futex1_addr.custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" and requeue a maximum of ");
                            self.write_text(
                                val2.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" from the remaining waiters to the futex at ");
                            self.write_text(
                                futex2_addr.custom_color(*(OUR_YELLOW)),
                            );
                        } else if (futex_ops_num & FUTEX_WAKE_OP) == FUTEX_WAKE_OP {
                            self.general_text("operate on 2 futexes at the same time");
                        } else if (futex_ops_num & FUTEX_WAIT_BITSET) == FUTEX_WAIT_BITSET {
                            self.general_text("if comparison succeeds block and wait for FUTEX_WAKE and register a bitmask for selective waiting");
                        } else if (futex_ops_num & FUTEX_WAKE_BITSET) == FUTEX_WAKE_BITSET {
                            self.general_text("wake a maximum of ");
                            self.write_text(
                                val.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" waiters waiting on the futex at ");
                            self.write_text(
                                futex1_addr.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(
                                " from the provided waiters bitmask"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if (futex_ops_num & FUTEX_LOCK_PI) == FUTEX_LOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_LOCK_PI2) == FUTEX_LOCK_PI2 {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_TRYLOCK_PI) == FUTEX_TRYLOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_UNLOCK_PI) == FUTEX_UNLOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE_PI) == FUTEX_CMP_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.write_text("[intentrace: needs granularity]".bright_black());
                        } else {
                            self.write_text("[intentrace: unknown flag]".bright_black());
                        }
                        // workarounds pending rustix deprecation of FutexOperation for Operations
                        // TODO! Priority-inheritance futexes
                        let mut directives = vec![];
                        if (futex_flags_num & FUTEX_PRIVATE_FLAG) == FUTEX_PRIVATE_FLAG {
                            directives.push(
                                "only use futex between threads of the same process"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if (futex_flags_num & FUTEX_CLOCK_REALTIME) == FUTEX_CLOCK_REALTIME {
                            directives.push(
                                "measure timeout using the CLOCK_REALTIME"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            directives.push(
                                "measure timeout using CLOCK_MONOTONIC"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if !directives.is_empty() {
                            self.general_text(" (");
                            let mut directives_iter = directives.into_iter().peekable();
                            if directives_iter.peek().is_some() {
                                self.write_text(directives_iter.next().unwrap());
                            }
                            for entry in directives_iter {
                                self.general_text(", ");
                                self.write_text(entry);
                            }
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::set_tid_address => {
                let thread_id =
                    SyscallObject::read_word(registers[0] as usize, self.process_pid)
                        .unwrap();
                match self.state {
                    Entering => {
                        self.general_text("set `clear_child_tid` for the calling thread to ");
                        self.write_text(thread_id.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("thread id of the calling thread: ".green());
                            self.write_text(
                                eph_return
                                    .unwrap()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fork => {
                match self.state {
                    Entering => {
                        self.general_text(
                            "create a new child process by duplicating the calling process",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let child_process = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("child process created: ".green());
                            self.write_text(
                                child_process.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(new_process());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::vfork => {
                match self.state {
                    Entering => {
                        self.general_text("create a new child process with copy-on-write memory, and suspend execution until child terminates");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let child_process = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("child process created: ".green());
                            self.write_text(
                                child_process.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(new_process());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::eventfd => {
                match self.state {
                    Entering => {
                        self.general_text("create a file to use for event notifications/waiting");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("created the eventfd: ".green());
                            self.write_path_file(file_descriptor);
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::eventfd2 => {
                let flags: eventfd::EfdFlags =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("create a file to use for event notifications/waiting");
                        let mut directives = vec![];
                        if flags.contains(eventfd::EfdFlags::EFD_CLOEXEC) {
                            directives.push(
                                "close the file with the next exec syscall"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(eventfd::EfdFlags::EFD_NONBLOCK) {
                            directives.push(
                                "use the file on non blocking mode"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if flags.contains(eventfd::EfdFlags::EFD_SEMAPHORE) {
                            directives.push(
                                "utilize semaphore-like semantics when reading"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("created the eventfd: ".green());
                            self.write_path_file(file_descriptor);
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::waitid => {
                // let id_type: nix::sys::wait::Id =
                //     unsafe { std::mem::transmute(args_vec[0] as u32) };
                let id_type = registers[0] as u32;
                let id = registers[1];
                let options: WaitPidFlag =
                    unsafe { std::mem::transmute(registers[3] as u32) };
                let rusage = registers[4] as *const ();
                match self.state {
                    Entering => {
                        if id_type == P_ALL {
                            self.general_text("wait until any child ");
                        } else if id_type == P_PGID {
                            if id == 0 {
                                self.general_text(
                                    "wait until any child in the current process group ",
                                );
                            } else {
                                self.general_text("wait until any child process with PGID ");
                                self.write_text(
                                    id.to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else if id_type == P_PID {
                            self.general_text("wait until child process ");
                            self.write_text(
                                id.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if id_type == P_PIDFD {
                            self.general_text("wait until child with PIDFD ");
                            self.write_text(
                                id.to_string()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.general_text(" ");
                        let mut options_ticked = vec![];

                        if options.contains(WaitPidFlag::WEXITED) {
                            options_ticked
                                .push("exits".custom_color(*(OUR_YELLOW)));
                        }
                        if options.contains(WaitPidFlag::WSTOPPED) {
                            options_ticked.push(
                                "is stopped by a signal"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::WCONTINUED) {
                            options_ticked.push(
                                "is resumed by SIGCONT"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.oring_handler(options_ticked);

                        let mut options_directives = vec![];
                        if options.contains(WaitPidFlag::__WNOTHREAD) {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            options_directives.push(
                                "only wait on this thread's children"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::__WALL) {
                            /// Wait on all children, regardless of type
                            options_directives.push(
                                "wait on all children"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::__WCLONE) {
                            /// Wait for "clone" children only.
                            options_directives.push(
                                "wait for clone children only"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::WNOHANG) {
                            options_directives.push(
                                "return immediately if no child exited"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::WNOWAIT) {
                            options_directives.push(
                                "leave the child in a waitable state"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if !rusage.is_null() {
                            options_directives.push(
                                "retrieve child resource usage data"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(options_directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.write_text("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::wait4 => {
                let pid = registers[0] as i32;
                let options: WaitPidFlag =
                    unsafe { std::mem::transmute(registers[2] as u32) };
                let mut options_ticked = vec![];
                let wstatus = registers[1];
                match self.state {
                    Entering => {
                        if options.contains(WaitPidFlag::WEXITED) {
                            options_ticked
                                .push("exits".custom_color(*(OUR_YELLOW)));
                        }
                        if options.contains(WaitPidFlag::WCONTINUED) {
                            options_ticked.push(
                                "is resumed by SIGCONT"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::WSTOPPED) {
                            options_ticked.push(
                                "is stopped by a signal"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options_ticked.is_empty() {
                            if pid < -1 {
                                self.general_text(
                                    "wait for state change in any child with process group ID ",
                                );
                                self.write_text(pid.to_string().blue());
                            } else if pid == -1 {
                                self.general_text("wait for state change in any child");
                            } else if pid == 0 {
                                self.general_text("wait for state change in any child with a similar process group ID",
                                );
                            } else {
                                self.general_text("wait for state change in child process ");
                                self.write_text(pid.to_string().blue());
                            }
                        } else {
                            if pid < -1 {
                                self.general_text("wait until any child with process group ID ");
                                self.write_text(pid.to_string().blue());
                            } else if pid == -1 {
                                self.general_text("wait until any child");
                            } else if pid == 0 {
                                self.general_text(
                                    "wait until any child with a similar process group ID",
                                );
                            } else {
                                self.general_text("wait until child process ");
                                self.write_text(pid.to_string().blue());
                            }

                            self.general_text(" ");
                            self.oring_handler(options_ticked);
                        }

                        let mut directives = vec![];
                        if options.contains(WaitPidFlag::__WNOTHREAD) {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            directives.push(
                                "only wait on this thread's children"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::__WALL) {
                            /// Wait on all children, regardless of type
                            directives.push(
                                "wait on all children"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if options.contains(WaitPidFlag::__WCLONE) {
                            /// Wait for "clone" children only.
                            directives.push(
                                "wait for clone children only"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        self.directives_handler(directives);

                        let mut retrieves = vec![];
                        if wstatus != 0 {
                            retrieves.push(
                                "exit status".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        let rusage = registers[3];
                        if rusage != 0 {
                            retrieves.push(
                                "resource usage metrics"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if !retrieves.is_empty() {
                            self.general_text(" (");
                            self.general_text("retrieve the child's ");
                            self.anding_handler(retrieves);
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            if wstatus == 0 {
                                self.write_text("Successful".green());
                            } else {
                                let wstatus_value = self.displayable_ol(1).parse::<u64>().unwrap();
                                // TODO! this is a workaround because nix's waitstatus resolver errors with EINVAL very often
                                if nix::libc::WIFEXITED(wstatus_value as i32) {
                                    let status = nix::libc::WEXITSTATUS(wstatus_value as i32);
                                    self.write_text("process exited with status code: ".green());
                                    self.write_text(status.to_string().blue());
                                } else if nix::libc::WIFSIGNALED(wstatus_value as i32) {
                                    let signal =
                                        x86_signal_to_string(wstatus_value as u64).unwrap();
                                    self.write_text("process was killed by ".green());
                                    self.write_text(signal.to_string().blue());
                                    if nix::libc::WCOREDUMP(wstatus_value as i32) {
                                        self.general_text(" ");
                                        self.write_text("(core dumped)".green());
                                    }
                                } else if nix::libc::WIFSTOPPED(wstatus_value as i32) {
                                    // TODO! Granularity needed here, this is currently a workaround
                                    self.write_text("process was stopped".green());
                                    // self.write_text("process was stopped by ".green());
                                    // self.write_text(signal.to_string().blue());
                                } else {
                                    self.write_text(
                                        "process was resumed from a stop state by ".green(),
                                    );
                                    self.write_text("SIGCONT".blue());
                                }
                                // let wait_status = nix::sys::wait::WaitStatus::from_raw(
                                //     Pid::from_raw(pid as i32),
                                //     b as i32,
                                // )
                                // .unwrap();
                                // match wait_status {
                                //     /// The process exited normally (as with `exit()` or returning from
                                //     /// `main`) with the given exit code. This case matches the C macro
                                //     /// `WIFEXITED(status)`; the second field is `WEXITSTATUS(status)`.
                                //     nix::sys::wait::WaitStatus::Exited(pid, status_code) => {
                                //         self.one_line
                                //             .push("process exited with status code: ".green());
                                //         self.write_text(status_code.to_string().blue());
                                //     }
                                //     /// The process was killed by the given signal. The third field
                                //     /// indicates whether the signal generated a core dump. This case
                                //     /// matches the C macro `WIFSIGNALED(status)`; the last two fields
                                //     /// correspond to `WTERMSIG(status)` and `WCOREDUMP(status)`.
                                //     nix::sys::wait::WaitStatus::Signaled(
                                //         pid,
                                //         signal,
                                //         core_dump,
                                //     ) => {
                                //         self.write_text("process was killed by ".green());
                                //         self.write_text(signal.to_string().blue());
                                //         if core_dump {
                                //             general_text.push(" ");
                                //             self.write_text("(core dumped)".green());
                                //         }
                                //     }
                                //     /// The process is alive, but was stopped by the given signal. This
                                //     /// is only reported if `WaitPidFlag::WUNTRACED` was passed. This
                                //     /// case matches the C macro `WIFSTOPPED(status)`; the second field
                                //     /// is `WSTOPSIG(status)`.
                                //     nix::sys::wait::WaitStatus::Stopped(pid, signal) => {
                                //         self.write_text("process was stopped by ".green());
                                //         self.write_text(signal.to_string().blue());
                                //     }
                                //     /// The traced process was stopped by a `PTRACE_EVENT_*` event. See
                                //     /// [`nix::sys::ptrace`] and [`ptrace`(2)] for more information. All
                                //     /// currently-defined events use `SIGTRAP` as the signal; the third
                                //     /// field is the `PTRACE_EVENT_*` value of the event.
                                //     ///
                                //     /// [`nix::sys::ptrace`]: ../ptrace/index.html
                                //     /// [`ptrace`(2)]: https://man7.org/linux/man-pages/man2/ptrace.2.html
                                //     nix::sys::wait::WaitStatus::PtraceEvent(
                                //         pid,
                                //         signal,
                                //         ptrace_event,
                                //     ) => {
                                //         self.write_text("process was stopped by a ".green());
                                //         self.write_text(signal.to_string().blue());
                                //         general_text.push(" signal due to ");
                                //         let ptrace: nix::sys::ptrace::Event =
                                //             unsafe { mem::transmute(ptrace_event) };
                                //         self.write_text(format!("{:?}", ptrace).green());
                                //     }
                                //     /// The traced process was stopped by execution of a system call,
                                //     /// and `PTRACE_O_TRACESYSGOOD` is in effect. See [`ptrace`(2)] for
                                //     /// more information.
                                //     ///
                                //     /// [`ptrace`(2)]: https://man7.org/linux/man-pages/man2/ptrace.2.html
                                //     nix::sys::wait::WaitStatus::PtraceSyscall(pid) => {
                                //         self.write_text("process stopped by ".green());
                                //         self.write_text("PTRACE_O_TRACESYSGOOD".blue());
                                //         self.write_text(" while executing a syscall".green());
                                //     }
                                //     /// The process was previously stopped but has resumed execution
                                //     /// after receiving a `SIGCONT` signal. This is only reported if
                                //     /// `WaitPidFlag::WCONTINUED` was passed. This case matches the C
                                //     /// macro `WIFCONTINUED(status)`.
                                //     nix::sys::wait::WaitStatus::Continued(pid) => {
                                //         self.write_text(                                //             "process was resumed from a stop state by ".green(),
                                //         );
                                //         self.write_text("SIGCONT".blue());
                                //     }
                                //     /// There are currently no state changes to report in any awaited
                                //     /// child process. This is only returned if `WaitPidFlag::WNOHANG`
                                //     /// was used (otherwise `wait()` or `waitpid()` would block until
                                //     /// there was something to report).
                                //     nix::sys::wait::WaitStatus::StillAlive => {
                                //         self.write_text("no state changes to report".green());
                                //     }
                                // }
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::clone3 => {
                let size_of_cl_args = registers[1];
                let cl_args = SyscallObject::read_bytes_as_struct::<88, clone3::CloneArgs>(
                    registers[0] as usize,
                    self.process_pid as _,
                )
                .unwrap();
                let clone_flags: clone3::Flags = unsafe { std::mem::transmute(cl_args.flags) };
                let clone_vm = clone_flags.contains(clone3::Flags::VM);

                match self.state {
                    Entering => {
                        if clone_vm {
                            self.general_text("spawn a new thread with a ");

                            self.write_text(
                                SyscallObject::style_bytes_page_aligned_ceil(cl_args.stack_size)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            self.general_text(" stack starting at ");
                            self.write_text(
                                format!("0x{:x}", cl_args.stack)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            // directives.push("run in the same memory space".custom_color(*(OUR_YELLOW)));
                        } else {
                            self.general_text("spawn a new child process");
                            // directives.push("copy the memory space".custom_color(*(OUR_YELLOW)));
                        }

                        // share with parent
                        //
                        //
                        //
                        //

                        let mut shares = vec![];
                        if clone_flags.contains(clone3::Flags::FILES) {
                            shares.push(
                                "the file descriptor table"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        //  else {
                        //     shares.push("copy the file descriptor table".custom_color(*(OUR_YELLOW)));
                        // }

                        if clone_flags.contains(clone3::Flags::FS) {
                            shares.push(
                                "filesystem information"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // else {
                        //     shares.push("copy filesystem information".custom_color(*(OUR_YELLOW)));
                        // }

                        // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                        // }

                        if clone_flags.contains(clone3::Flags::IO) {
                            shares.push(
                                "I/O context".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::SIGHAND) {
                            shares.push(
                                "the table of signal handlers"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        //  else {
                        //     shares.push("copy the signal handlers table".custom_color(*(OUR_YELLOW)));
                        // }
                        if clone_flags.contains(clone3::Flags::SYSVSEM) {
                            shares.push(
                                "sem-adj values".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        //  else {
                        //     shares.push("don't share sem-adj values".custom_color(*(OUR_YELLOW)));
                        // }

                        if !shares.is_empty() {
                            self.general_text(" (");
                            self.general_text("share ");
                            self.anding_handler(shares);
                            self.general_text(")");
                        }

                        // execute in new
                        //
                        //
                        //
                        //
                        let mut executes = vec![];

                        if clone_flags.contains(clone3::Flags::NEWCGROUP) {
                            executes.push(
                                "CGroup namespace"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWIPC) {
                            executes.push(
                                "IPC namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWNET) {
                            executes.push(
                                "network namespace"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWNS) {
                            executes.push(
                                "mount namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWPID) {
                            executes.push(
                                "PID namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        // if clone_flags.contains(clone3::Flags::NEWTIME) {
                        // }
                        if clone_flags.contains(clone3::Flags::NEWUSER) {
                            executes.push(
                                "user namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWUTS) {
                            executes.push(
                                "UTS namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if !executes.is_empty() {
                            self.general_text(" (");
                            self.general_text("execute in a new ");
                            self.anding_handler(executes);
                            self.general_text(")");
                        }

                        let mut directives = vec![];

                        if clone_flags.contains(clone3::Flags::PARENT) {
                            directives.push(
                                "inherit the same parent"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::PARENT_SETTID) {
                            directives.push(
                                "store the child TID in the parent's memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        // It is currently not possible to use this flag together with CLONE_THREAD. This
                        // means that the process identified by the PID file descriptor will always be a
                        // thread group leader.
                        if clone_flags.contains(clone3::Flags::PIDFD) {
                            directives.push(
                                "return a PIDFD for the child"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::PTRACE) {
                            directives.push(
                                "allow ptracing if parent is ptraced"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::SETTLS) {
                            directives.push(
                                "modify the thread local storage descriptor"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::THREAD) {
                            directives.push(
                                "place in the same thread group"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            directives.push(
                                "place in a new thread group"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::UNTRACED) {
                            directives.push(
                                "prevent forcing of CLONE_PTRACE"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::VFORK) {
                            directives.push(
                                "suspend parent execution as with vFork"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_CLEARTID) {
                            // directives.push("set the child's ".custom_color(*(OUR_YELLOW)));
                            // directives.push("clear_child_tid".blue());
                            // directives.push("to ".custom_color(*(OUR_YELLOW)));
                            // directives.push(cl_args.child_tid.to_string().blue());
                            directives.push(
                        "clear TID on the child's memory on exit and wake the associated futex"
                            .custom_color(*(OUR_YELLOW)),
                    );
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_SETTID) {
                            directives.push(
                                "store the child TID in child's memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::CLEAR_SIGHAND) {
                            directives.push(
                                "default all inherited signal handlers"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("thread id of the child: ".green());
                            self.write_text(
                                eph_return
                                    .unwrap()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            if clone_vm {
                                self.write_text(new_thread());
                            } else {
                                self.write_text(new_process());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::clone => {
                let clone_flags: clone3::Flags = unsafe { std::mem::transmute(registers[0]) };
                let clone_vm = clone_flags.contains(clone3::Flags::VM);
                let stack = registers[0];

                match self.state {
                    Entering => {
                        if clone_vm {
                            self.general_text("spawn a new thread at stack address ");
                            self.write_text(
                                format!("0x{:x}", stack)
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            // directives.push("run in the same memory space".custom_color(*(OUR_YELLOW)));
                        } else {
                            self.general_text("spawn a new child process");
                            // directives.push("copy the memory space".custom_color(*(OUR_YELLOW)));
                        }

                        // share with parent
                        //
                        //
                        //
                        //

                        let mut shares = vec![];
                        if clone_flags.contains(clone3::Flags::FILES) {
                            shares.push(
                                "the file descriptor table"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        //  else {
                        //     shares.push("copy the file descriptor table".custom_color(*(OUR_YELLOW)));
                        // }

                        if clone_flags.contains(clone3::Flags::FS) {
                            shares.push(
                                "filesystem information"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        // else {
                        //     shares.push("copy filesystem information".custom_color(*(OUR_YELLOW)));
                        // }

                        // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                        // }

                        if clone_flags.contains(clone3::Flags::IO) {
                            shares.push(
                                "I/O context".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::SIGHAND) {
                            shares.push(
                                "the table of signal handlers"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        //  else {
                        //     shares.push("copy the signal handlers table".custom_color(*(OUR_YELLOW)));
                        // }
                        if clone_flags.contains(clone3::Flags::SYSVSEM) {
                            shares.push(
                                "sem-adj values".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        //  else {
                        //     shares.push("don't share sem-adj values".custom_color(*(OUR_YELLOW)));
                        // }

                        if !shares.is_empty() {
                            self.general_text(" (");
                            self.general_text("share ");
                            self.anding_handler(shares);
                            self.general_text(")");
                        }

                        // execute in new
                        //
                        //
                        //
                        //
                        let mut executes = vec![];

                        if clone_flags.contains(clone3::Flags::NEWCGROUP) {
                            executes.push(
                                "CGroup namespace"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWIPC) {
                            executes.push(
                                "IPC namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWNET) {
                            executes.push(
                                "network namespace"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWNS) {
                            executes.push(
                                "mount namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWPID) {
                            executes.push(
                                "PID namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        // if clone_flags.contains(clone3::Flags::NEWTIME) {
                        // }
                        if clone_flags.contains(clone3::Flags::NEWUSER) {
                            executes.push(
                                "user namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::NEWUTS) {
                            executes.push(
                                "UTS namespace".custom_color(*(OUR_YELLOW)),
                            );
                        }

                        if !executes.is_empty() {
                            self.general_text(" (");
                            self.general_text("execute in a new ");
                            self.anding_handler(executes);
                            self.general_text(")");
                        }

                        let mut directives = vec![];

                        if clone_flags.contains(clone3::Flags::PARENT) {
                            directives.push(
                                "inherit the same parent"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::PARENT_SETTID) {
                            directives.push(
                                "store the child TID in the parent's memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        // It is currently not possible to use this flag together with CLONE_THREAD. This
                        // means that the process identified by the PID file descriptor will always be a
                        // thread group leader.
                        if clone_flags.contains(clone3::Flags::PIDFD) {
                            directives.push(
                                "return a PIDFD for the child"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::PTRACE) {
                            directives.push(
                                "allow ptracing if parent is ptraced"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::SETTLS) {
                            directives.push(
                                "modify the thread local storage descriptor"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::THREAD) {
                            directives.push(
                                "place in the same thread group"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            directives.push(
                                "place in a new thread group"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::UNTRACED) {
                            directives.push(
                                "prevent forcing of CLONE_PTRACE"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::VFORK) {
                            directives.push(
                                "suspend parent execution as with vFork"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        // CLONE_CHILD_CLEARTID, for instance, is designed to support pthread_join.
                        // What it essentially does is zero the value at ctid,
                        // then wake up threads that have called a futex_wait on that address.
                        // Thus, pthread_join can be implemented by simply checking to see if ctid is zero
                        // (and returning immediately with the status if it is),
                        // then doing a futex_wait if necessary (assuming proper synchronization).
                        if clone_flags.contains(clone3::Flags::CHILD_CLEARTID) {
                            directives.push(
                        "clear TID on the child's memory on exit and wake the associated futex"
                            .custom_color(*(OUR_YELLOW)),
                    );
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_SETTID) {
                            directives.push(
                                "store the child TID in child's memory"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                        if clone_flags.contains(clone3::Flags::CLEAR_SIGHAND) {
                            directives.push(
                                "default all inherited signal handlers"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }

                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("thread id of the child: ".green());
                            self.write_text(
                                eph_return
                                    .unwrap()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                            // TODO! fix occasional error (syscall returns -38)
                            if clone_vm {
                                self.write_text(new_thread());
                            } else {
                                self.write_text(new_process());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::execve => {
                let program_name = self.displayable_ol(0);
                let arguments = self.displayable_ol(1);
                match self.state {
                    Entering => {
                        self.general_text(
                            "replace the current program with the following program and arguments",
                        );
                        self.write_path_file(program_name);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::nanosleep => {
                let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                    registers[0] as usize,
                    self.process_pid as _,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        self.general_text("suspend execution for ");
                        self.format_timespec_non_relative(timespec.tv_sec, timespec.tv_nsec);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successful".green());
                        } else {
                            // TODO! granularity
                            // remaining time due to interruption is stored inside
                            // the second syscall argument *rem (which is a timespec struct)
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::landlock_create_ruleset => {
                let attr = registers[0] as *const ();
                let size = registers[1];
                let flags_num = registers[2];
                // LANDLOCK_CREATE_RULESET_VERSION = 1
                let retrieving_abi_version = (flags_num & 1) == 1 && attr.is_null() && size == 0;
                match self.state {
                    Entering => {
                        // let flags: LandlockCreateFlags =
                        //     unsafe { std::mem::transmute(self.arguments[2] as u32) };
                        if retrieving_abi_version {
                            self.general_text(
                                "retrieve the highest supported Landlock ABI version",
                            );
                        } else {
                            self.general_text("create a file descriptor for a landlock ruleset");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            if retrieving_abi_version {
                                let abi_version = self.result.0.unwrap() as f64;
                                self.write_text("got the ABI version: ".green());
                                self.write_text(
                                    abi_version
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                let file_descriptor = eph_return.unwrap();
                                self.write_text("created the ruleset file descriptor: ".green());
                                self.write_path_file(file_descriptor);
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::landlock_add_rule => {
                let ruleset_fd = self.displayable_ol(0);
                let rule_type_num = registers[1];
                let rule_type: LandlockRuleTypeFlags =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                match self.state {
                    Entering => {
                        // LANDLOCK_RULE_PATH_BENEATH = 1
                        if (rule_type_num & 1) == 1 {
                            self.general_text("add a new rule for ");
                            self.write_text(
                                "file system path-beneath access rights"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("rule added".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::landlock_restrict_self => {
                let ruleset_fd = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("enforce the landlock ruleset inside: ");
                        self.general_text(&ruleset_fd);
                        self.general_text(" on the calling process");
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("ruleset is now enforced".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fallocate => {
                let file_descriptor = self.displayable_ol(0);
                let mode_num = registers[1];
                let mode: nix::fcntl::FallocateFlags =
                    unsafe { std::mem::transmute(registers[1] as u32) };
                let offset_num = registers[2];
                let offset = self.displayable_ol(2);
                let bytes = self.displayable_ol(3);
                match self.state {
                    Entering => {
                        if mode_num == 0
                            || mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                            || mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_UNSHARE_RANGE)
                        {
                            self.write_text("allocate ".magenta());
                            self.write_text(
                                bytes.custom_color(*(OUR_YELLOW)),
                            );
                            if offset_num == 0 {
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.write_text(
                                    offset.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.write_path_file(file_descriptor);
                            if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                                && !mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE)
                            {
                                // this improves performance when appeding (makes appending later faster)
                                self.general_text(" (");
                                self.general_text("do not increase the file size if the range is larger, simply zeroize the out of bound bytes)");
                                self.general_text(")");
                            } else if mode
                                .contains(nix::fcntl::FallocateFlags::FALLOC_FL_UNSHARE_RANGE)
                            {
                                // this improves performance when appeding (makes appending later faster)
                                self.general_text(" (");

                                self.write_text(
                                    "modify any shared file data to private copy-on-write"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(")");
                            } else {
                                self.general_text(" (");
                                self.write_text(
                                    "increase file size and zeroize if the range is larger"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(")");
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE)
                            && mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                        {
                            self.write_text("deallocate ".magenta());
                            self.write_text(
                                bytes.custom_color(*(OUR_YELLOW)),
                            );
                            if offset_num == 0 {
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.write_text(
                                    offset.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.write_path_file(file_descriptor);
                        } else if mode
                            .contains(nix::fcntl::FallocateFlags::FALLOC_FL_COLLAPSE_RANGE)
                        {
                            self.write_text("remove ".magenta());
                            self.write_text(
                                bytes.custom_color(*(OUR_YELLOW)),
                            );
                            if offset_num == 0 {
                                self.general_text(" from the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.write_text(
                                    offset.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.write_path_file(file_descriptor);
                            self.write_text(
                                " without leaving a hole"
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.write_text("zeroize ".magenta());
                            self.write_text(
                                bytes.custom_color(*(OUR_YELLOW)),
                            );
                            if offset_num == 0 {
                                self.general_text(" from the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.write_text(
                                    offset.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.write_path_file(file_descriptor);
                            if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE) {
                                self.general_text(" (");
                                self.write_text(
                                    "do not increase the file size if the range is larger"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(")");
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.write_text("insert ".magenta());
                            self.write_text(
                                bytes.custom_color(*(OUR_YELLOW)),
                            );
                            self.write_text(" of holes".magenta());

                            if offset_num == 0 {
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.write_text(
                                    offset.custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.write_path_file(file_descriptor);
                            self.general_text(
                                " without overwriting existing data (displace data instead)",
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.write_text("operation successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getpriority => {
                let which = registers[0] as u32;
                let process = registers[1];

                match self.state {
                    Entering => {
                        self.general_text("get the scheduling priority ");
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.general_text("of ");
                            if process == 0 {
                                self.write_text(
                                    "the calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process: ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.general_text("of ");
                            if process == 0 {
                                self.write_text(
                                    "the process group of calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process group: "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.general_text("for ");
                            if process == 0 {
                                self.write_text(
                                    "the real user id of the calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "the real user id: "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("got the scheduling priority: ".green());
                            self.write_text(
                                eph_return
                                    .unwrap()
                                    .custom_color(*(OUR_YELLOW)),
                            );
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::setpriority => {
                let which = registers[0] as u32;
                let process = registers[1];
                let prio = self.displayable_ol(2);

                match self.state {
                    Entering => {
                        self.general_text("set the scheduling priority ");
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.general_text("of ");
                            if process == 0 {
                                self.write_text(
                                    "the calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process: ".custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                            self.general_text(" to ");
                            self.write_text(prio.custom_color(*(OUR_YELLOW)));
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.general_text("of ");
                            if process == 0 {
                                self.write_text(
                                    "the process group of calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "process group: "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            }
                            self.general_text(" to ");
                            self.write_text(prio.custom_color(*(OUR_YELLOW)));
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.general_text("for ");
                            if process == 0 {
                                self.write_text(
                                    "the real user id of the calling process"
                                        .custom_color(*(OUR_YELLOW)),
                                );
                            } else {
                                self.write_text(
                                    "the real user id: "
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.write_text(
                                    process
                                        .to_string()
                                        .custom_color(*(OUR_YELLOW)),
                                );
                                self.general_text(" to ");
                                self.write_text(
                                    prio.custom_color(*(OUR_YELLOW)),
                                );
                            }
                        }
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully set the scheduling priority".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getdents => {
                let directory = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("retrieve the entries inside the directory ");
                        self.write_path_file(directory);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully retrieved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getdents64 => {
                let directory = self.displayable_ol(0);
                match self.state {
                    Entering => {
                        self.general_text("retrieve the entries inside the directory ");
                        self.write_path_file(directory);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.write_text("successfully retrieved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }

            _ => {
                return Err(());
            }
        }
        Ok(())
    }
}

impl SyscallObject {
    pub fn vanilla_commas_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        // first element
        if vector_iter.peek().is_some() {
            self.write_text(vector_iter.next().unwrap());
        }
        // remaining elements
        for entry in vector_iter {
            self.general_text(", ");
            self.write_text(entry);
        }
    }

    pub fn oring_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        // first element
        if vector_iter.peek().is_some() {
            self.write_text(vector_iter.next().unwrap());
        }
        // second element
        if vector_iter.peek().is_some() {
            self.general_text(", or ");
            self.write_text(vector_iter.next().unwrap());
        }
        // remaining elements
        for entry in vector_iter {
            self.general_text(", or ");
            self.write_text(entry);
        }
    }

    pub fn anding_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        // first element
        if vector_iter.peek().is_some() {
            self.write_text(vector_iter.next().unwrap());
        }
        // second and remaining elements
        if let Some(second_as_last) = vector_iter.next() {
            let third_and_forward = vector_iter;
            for entry in third_and_forward {
                self.general_text(", ");
                self.write_text(entry);
            }
            // last element
            self.general_text(", and ");
            self.write_text(second_as_last);
        }
    }

    pub fn directives_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        // first element
        if vector_iter.peek().is_some() {
            self.general_text(" (");
            self.write_text(vector_iter.next().unwrap());
            // remaining elements
            for entry in vector_iter {
                self.general_text(", ");
                self.write_text(entry);
            }
            self.general_text(")");
        }
    }

    pub fn format_timespec(&mut self, seconds: i64, nanoseconds: i64) {
        if seconds == 0 {
            if nanoseconds == 0 {
                self.write_text("immediately".custom_color(*(OUR_YELLOW)));
            } else {
                self.write_text("after ".custom_color(*(OUR_YELLOW)));
                self.write_text(
                    nanoseconds
                        .to_string()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text(" nanoseconds".custom_color(*(OUR_YELLOW)));
            }
        } else {
            self.write_text("after ".custom_color(*(OUR_YELLOW)));
            self.write_text(
                seconds
                    .to_string()
                    .custom_color(*(OUR_YELLOW)),
            );
            self.write_text(" seconds".custom_color(*(OUR_YELLOW)));
            if nanoseconds != 0 {
                self.general_text(", ");
                self.write_text(
                    nanoseconds
                        .to_string()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text(" nanoseconds".custom_color(*(OUR_YELLOW)));
            }
        }
    }
    pub fn format_timespec_non_relative(&mut self, seconds: i64, nanoseconds: i64) {
        if seconds == 0 {
            if nanoseconds == 0 {
                self.write_text("0".blue());
                self.write_text(" nano-seconds".custom_color(*(OUR_YELLOW)));
            } else {
                self.write_text(nanoseconds.to_string().blue());
                self.write_text(" nano-seconds".custom_color(*(OUR_YELLOW)));
            }
        } else {
            self.write_text(seconds.to_string().blue());
            self.write_text(" seconds".custom_color(*(OUR_YELLOW)));
            if nanoseconds != 0 {
                self.general_text(" and ");
                self.write_text(
                    nanoseconds
                        .to_string()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text(" nanoseconds".custom_color(*(OUR_YELLOW)));
            }
        }
    }

    pub fn format_timeval(&mut self, seconds: i64, microseconds: i64) {
        if seconds == 0 {
            if microseconds == 0 {
                self.write_text("immediately".custom_color(*(OUR_YELLOW)));
            } else {
                self.write_text("after ".custom_color(*(OUR_YELLOW)));
                self.write_text(
                    microseconds
                        .to_string()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text(" microseconds".custom_color(*(OUR_YELLOW)));
            }
        } else {
            self.write_text("after ".custom_color(*(OUR_YELLOW)));
            self.write_text(
                seconds
                    .to_string()
                    .custom_color(*(OUR_YELLOW)),
            );
            self.write_text(" seconds".custom_color(*(OUR_YELLOW)));
            if microseconds != 0 {
                self.general_text(", ");
                self.write_text(
                    microseconds
                        .to_string()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text(" microseconds".custom_color(*(OUR_YELLOW)));
            }
        }
    }

    pub fn write_path_file(&mut self, filename: String) {
        let mut pathname = String::new();

        let mut file_start = 0;
        for (index, chara) in filename.chars().rev().enumerate() {
            if chara == '/' && index != 0 {
                file_start = filename.len() - index;
                break;
            }
        }
        self.write_text(filename[0..file_start].custom_color(*(OUR_YELLOW)));
        self.write_text(filename[file_start..].custom_color(*(PAGES_COLOR)));
    }

    pub(crate) fn possible_dirfd_file(&mut self, dirfd: i32, filename: String) {
        let file_path_buf = PathBuf::from(filename);
        if file_path_buf.is_relative() {
            if dirfd == AT_FDCWD {
                let current_working_directory =
                    procfs::process::Process::new(self.process_pid.into())
                        .unwrap()
                        .cwd()
                        .unwrap();
                self.write_text(
                    current_working_directory
                        .as_path()
                        .to_string_lossy()
                        .custom_color(*(OUR_YELLOW)),
                );
                self.write_text("/".custom_color(*(OUR_YELLOW)));
                let path_without_leading_relativeness =
                    lose_relativity_on_path(file_path_buf.as_path().to_string_lossy().to_owned());
                self.write_text(
                    path_without_leading_relativeness
                        .custom_color(*(PAGES_COLOR)),
                );
            } else {
                let file_info =
                    procfs::process::FDInfo::from_raw_fd(self.process_pid.into(), dirfd).unwrap();
                match file_info.target {
                    procfs::process::FDTarget::Path(path) => {
                        self.write_text(
                            path.as_path()
                                .to_string_lossy()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if !path.is_absolute() || path.len() != 1 {
                            self.write_text("/".custom_color(*(OUR_YELLOW)));
                        }
                        let path_without_leading_relativeness = lose_relativity_on_path(
                            file_path_buf.as_path().to_string_lossy().to_owned(),
                        );
                        self.write_text(
                            path_without_leading_relativeness
                                .custom_color(*(PAGES_COLOR)),
                        );
                    }
                    _ => unreachable!(),
                }
            }
        } else {
            self.write_path_file(file_path_buf.as_path().to_string_lossy().into_owned());
        }
    }

    pub(crate) fn possible_dirfd_file_output(&mut self, dirfd: i32, filename: String) -> String {
        let mut string = String::new();
        let file_path_buf = PathBuf::from(filename);
        if file_path_buf.is_relative() {
            if dirfd == AT_FDCWD {
                let cwd = procfs::process::Process::new(10).unwrap().cwd().unwrap();
                string.push_str(&cwd.as_path().to_string_lossy());
                string.push_str("/");
                let path_without_leading_relativeness =
                    lose_relativity_on_path(file_path_buf.as_path().to_string_lossy().to_owned());
                string.push_str(&path_without_leading_relativeness);
            } else {
                let file_info =
                    procfs::process::FDInfo::from_raw_fd(self.process_pid.into(), dirfd).unwrap();
                match file_info.target {
                    procfs::process::FDTarget::Path(path) => {
                        self.write_text(
                            path.as_path()
                                .to_string_lossy()
                                .custom_color(*(OUR_YELLOW)),
                        );
                        if !path.is_absolute() || path.len() != 1 {
                            string.push_str("/");
                        }
                        let path_without_leading_relativeness = lose_relativity_on_path(
                            file_path_buf.as_path().to_string_lossy().to_owned(),
                        );
                        string.push_str(&path_without_leading_relativeness);
                    }
                    _ => unreachable!(),
                }
            }
        } else {
            string.push_str(&file_path_buf.as_path().to_string_lossy().to_owned());
        }
        string
    }

    pub fn mode_matcher(&mut self, mode: rustix::fs::Mode) {
        // USER
        let mut perms = vec![];
        if mode.contains(rustix::fs::Mode::RUSR) {
            perms.push("read".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::WUSR) {
            perms.push("write".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::XUSR) {
            perms.push("execute".custom_color(*(OUR_YELLOW)));
        }
        if !perms.is_empty() {
            self.general_text(" allowing the user to ");
            self.vanilla_commas_handler(perms);
            self.general_text(", ");
        }

        // GROUP
        let mut group_perms = vec![];
        if mode.contains(rustix::fs::Mode::RGRP) {
            group_perms.push("read".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::WGRP) {
            group_perms.push("write".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::XGRP) {
            group_perms.push("execute".custom_color(*(OUR_YELLOW)));
        }
        if !group_perms.is_empty() {
            self.general_text(" allowing the group to ");
            self.vanilla_commas_handler(group_perms);
            self.general_text(", ");
        }
        // OTHER
        let mut other_perms = vec![];
        if mode.contains(rustix::fs::Mode::ROTH) {
            other_perms.push("read".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::WOTH) {
            other_perms.push("write".custom_color(*(OUR_YELLOW)));
        }
        if mode.contains(rustix::fs::Mode::XOTH) {
            other_perms.push("execute".custom_color(*(OUR_YELLOW)));
        }
        if !other_perms.is_empty() {
            self.general_text(" allowing others to ");
            self.vanilla_commas_handler(other_perms);
            self.general_text(", ");
        }

        // SETS
        let mut sets = vec![];
        if mode.contains(rustix::fs::Mode::SUID) {
            sets.push("set-uid".custom_color(*(OUR_YELLOW)));
        } else if mode.contains(rustix::fs::Mode::SGID) {
            sets.push("set-gid".custom_color(*(OUR_YELLOW)));
        } else if mode.contains(rustix::fs::Mode::SVTX) {
            sets.push("sticky-bit".custom_color(*(OUR_YELLOW)));
        }
        if !sets.is_empty() {
            self.general_text(" and set ");
            self.vanilla_commas_handler(sets);
        }
    }

    pub fn resource_matcher(&mut self, resource: Resource) {
        match resource {
            Resource::RLIMIT_AS => {
                self.write_text(
                    "maximum virtual memory size".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_CORE => {
                self.write_text(
                    "maximum core size that may be dumped"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_CPU => {
                self.write_text(
                    "maximum time in seconds to use in the CPU"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_DATA => {
                self.write_text(
                    "maximum data segment size".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_FSIZE => {
                self.write_text(
                    "maximum allowed size of files to creates"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_NOFILE => {
                self.write_text(
                    "maximum allowed open file descriptors"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_STACK => {
                self.write_text(
                    "maximum stack size".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_LOCKS => {
                self.write_text(
                    "maximum number of flock() locks and fcntl() leases"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_MEMLOCK => {
                // affects mlock
                self.write_text(
                    "maximum amount of memory that can be locked"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_MSGQUEUE => {
                self.write_text(
                    "maximum number of bytes to use on message queues"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_NICE => {
                self.write_text(
                    "maximum nice value".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_NPROC => {
                self.write_text(
                    "maximum number of threads".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_RSS => {
                // affects madvise
                self.write_text(
                    "maximum RSS memory".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_RTPRIO => {
                self.write_text(
                    "maximum real-time priority".custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_RTTIME => {
                self.write_text(
                    "maximum time in micro-seconds to use in the CPU without syscalls"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            Resource::RLIMIT_SIGPENDING => {
                self.write_text(
                    "maximum number of queued pending signals"
                        .custom_color(*(OUR_YELLOW)),
                );
            }
            _ => {}
        }
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
