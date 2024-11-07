use std::{
    env::current_dir,
    mem,
    os::fd::RawFd,
    path::{Path, PathBuf},
};

use crate::{
    syscall_object::SyscallObject,
    types::{Bytes, BytesPagesRelevant, LandlockRuleTypeFlags},
    utilities::{
        errno_to_string, get_child_memory_break, get_mem_difference_from_previous,
        where_in_childs_memory, x86_signal_to_string, FOLLOW_FORKS,
    },
};
use colored::{Color, ColoredString, Colorize};
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FallocateFlags},
    libc::{
        cpu_set_t, pid_t, rlimit, timespec, timeval, AT_FDCWD, EPOLL_CLOEXEC, EPOLL_CTL_ADD,
        EPOLL_CTL_DEL, EPOLL_CTL_MOD, FUTEX_CLOCK_REALTIME, FUTEX_CMP_REQUEUE,
        FUTEX_CMP_REQUEUE_PI, FUTEX_FD, FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_PRIVATE_FLAG,
        FUTEX_REQUEUE, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET,
        FUTEX_WAIT_REQUEUE_PI, FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP,
        LINUX_REBOOT_CMD_CAD_OFF, MADV_COLD, MADV_COLLAPSE, MADV_DODUMP, MADV_DOFORK,
        MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE, MADV_HUGEPAGE, MADV_HWPOISON,
        MADV_KEEPONFORK, MADV_MERGEABLE, MADV_NOHUGEPAGE, MADV_NORMAL, MADV_PAGEOUT,
        MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_RANDOM, MADV_REMOVE, MADV_SEQUENTIAL,
        MADV_UNMERGEABLE, MADV_WILLNEED, MADV_WIPEONFORK, MAP_ANON, MAP_ANONYMOUS, MAP_FIXED,
        MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_HUGETLB, MAP_HUGE_16GB, MAP_HUGE_16MB,
        MAP_HUGE_1GB, MAP_HUGE_1MB, MAP_HUGE_256MB, MAP_HUGE_2GB, MAP_HUGE_2MB, MAP_HUGE_32MB,
        MAP_HUGE_512KB, MAP_HUGE_512MB, MAP_HUGE_64KB, MAP_HUGE_8MB, MAP_LOCKED, MAP_NONBLOCK,
        MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE, MAP_STACK,
        MAP_SYNC, MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT, O_APPEND, O_ASYNC, O_CLOEXEC, O_CREAT,
        O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_LARGEFILE, O_NDELAY, O_NOATIME, O_NOCTTY,
        O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TMPFILE, O_TRUNC, PRIO_PGRP, PRIO_PROCESS,
        PRIO_USER, P_ALL, P_PGID, P_PID, P_PIDFD,
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
    pub(crate) fn get_syscall_return(&mut self) -> Result<String, ()> {
        let eph_return = self.parse_return_value_one_line();
        if self.paused {
            self.one_line.truncate(5);
            self.one_line.iter_mut().for_each(|colored| {
                *colored = colored.clone().dimmed();
            });
            self.one_line.push(" CONTINUED ".on_black());
        } else {
            self.one_line.clear();
        }
        eph_return
    }
    pub(crate) fn one_line_formatter(&mut self) -> Result<(), ()> {
        use crate::syscall_object::SyscallState::*;

        if self.state == Entering {
            if FOLLOW_FORKS.get() {
                self.one_line.extend(vec![
                    "\n".white(),
                    self.child.to_string().bright_blue(),
                    " ".dimmed(),
                    SyscallObject::colorize_syscall_name(&self.sysno, &self.category),
                    " - ".dimmed(),
                ]);
            } else {
                if self.get_syscall_return().is_ok() {
                    self.one_line.extend(vec![
                        "\n".white(),
                        self.child.to_string().blue(),
                        // self.child.to_string().on_black(),
                        " ".dimmed(),
                        SyscallObject::colorize_syscall_name(&self.sysno, &self.category),
                        " - ".dimmed(),
                    ]);
                } else {
                    self.one_line.extend(vec![
                        "\n".white(),
                        self.child.to_string().red(),
                        // self.child.to_string().on_red(),
                        " ".dimmed(),
                        SyscallObject::colorize_syscall_name(&self.sysno, &self.category),
                        " - ".dimmed(),
                    ]);
                }
            }
        }
        //
        //======================
        //
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
                let syscall_brk_num = self.args[0];
                let syscall_brk = self.pavfol(0);
                let getting_current_break = syscall_brk_num == 0;

                match self.state {
                    Entering => {
                        if getting_current_break {
                            self.one_line.push("get the current program break".white());
                        } else {
                            self.one_line.push("change program break to ".white());
                            self.one_line.push(syscall_brk.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            if getting_current_break {
                                self.one_line.push("current program break: ".green());
                                self.one_line.push(eph_return.unwrap().yellow());
                            } else {
                                let new_brk_num = self.result.0.unwrap();
                                let new_brk = self.parse_return_value_one_line();
                                let mem_difference =
                                    get_mem_difference_from_previous(new_brk_num as _);
                                let mem_difference_bytes =
                                    BytesPagesRelevant::from_ceil(mem_difference as usize);
                                if mem_difference == 0 {
                                    self.one_line
                                        .push("no allocation or deallocation occured".white());
                                } else if mem_difference > 0 {
                                    self.one_line.push("allocated ".white());
                                    self.one_line
                                        .push(mem_difference_bytes.to_string().yellow());
                                } else {
                                    self.one_line.push("deallocated ".white());
                                    self.one_line
                                        .push(mem_difference_bytes.to_string().yellow());
                                }
                                self.one_line.push(", new program break: ".green());
                                self.one_line.push(eph_return.unwrap().yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::close => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("close the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("file closed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::open => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        // TODO! fix open flags granularity
                        // TODO! also fix file mode granularity
                        //
                        self.one_line.push("open the file ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully opened file".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::openat => {
                //
                let anchor = self.pavfol(0);
                let filename = self.pavfol(1);
                let filename_path = Path::new(&filename);
                let flags_num = self.args[2] as i32;
                let flags = self.pavfol(2);
                match self.state {
                    Entering => {
                        // TODO! fix open flags granularity
                        // TODO! also fix file mode granularity
                        // let flags: nix::fcntl::OFlag =
                        //     unsafe { std::mem::transmute(self.args_vec[2] as u32) };
                        // create a temporary file
                        // pathname is a directory
                        // an unnamed inode will be created in that directory's filesystem.
                        // Anything written to the resulting file will be lost
                        // when the last file descriptor is closed, unless the file is given a name.
                        if (flags_num & O_TMPFILE) > 0 {
                            self.one_line
                                .push("create an unnamed temporary file in the path ".white());
                        } else {
                            self.one_line.push("open the file ".white());
                        }

                        if filename_path.is_absolute() {
                            handle_path_file(filename, &mut self.one_line);
                            // self.one_line.push(filename.yellow())
                        } else {
                            if self.args[0] as i32 == AT_FDCWD {
                                let pwd = current_dir().unwrap();
                                let joined_path = pwd.join(filename_path);
                                self.one_line.push("open the file ".white());
                                let filename = joined_path.to_str().unwrap().to_owned();
                                handle_path_file(filename, &mut self.one_line);
                                // self.one_line.push(joined_path.as_str().unwrap().yellow());
                            } else {
                                let anchor_path = Path::new(&anchor);
                                let joined_path = anchor_path.join(filename_path);
                                self.one_line.push("open the file ".white());
                                let filename = joined_path.to_str().unwrap().to_owned();
                                handle_path_file(filename, &mut self.one_line);
                                // self.one_line.push(joined_path.as_str().unwrap().yellow());
                            }
                        }
                        let mut directives = vec![];
                        if (flags_num & O_APPEND) == O_APPEND {
                            directives.push("open the file in append mode".yellow());
                        }
                        if (flags_num & O_ASYNC) == O_ASYNC {
                            directives.push("enable signal-driven I/O".yellow());
                        }
                        if (flags_num & O_CLOEXEC) == O_CLOEXEC {
                            directives.push(
                                "close the file descriptor on the next exec syscall".yellow(),
                            );
                        }
                        if (flags_num & O_CREAT) > 0 {
                            directives.push("create the file if it does not exist".yellow());
                        }
                        if (flags_num & O_DIRECT) > 0 {
                            directives.push("use direct file I/O".yellow());
                        }
                        if (flags_num & O_DIRECTORY) > 0 {
                            directives.push("fail if the path is not a directory".yellow());
                        }
                        if (flags_num & O_DSYNC) > 0 {
                            directives.push("ensure writes are completely teransferred to hardware before return".yellow());
                        }
                        if (flags_num & O_EXCL) > 0 {
                            directives.push("ensure O_CREAT fails if the file already exists or is a symbolic link".yellow());
                        }
                        if (flags_num & O_LARGEFILE) > 0 {
                            directives.push(
                                "allow files larger than `off_t` and up to `off64_t`".yellow(),
                            );
                        }
                        if (flags_num & O_NOATIME) > 0 {
                            directives
                                .push("do not update the file last access time on read".yellow());
                        }
                        if (flags_num & O_NOCTTY) > 0 {
                            directives
                                .push("do not use the file as the process's controlling terminal if its a terminal device".yellow());
                        }
                        if (flags_num & O_NOFOLLOW) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives
                                .push("fail if the base of the file is a symbolic link".yellow());
                        }
                        if (flags_num & O_NONBLOCK) > 0 || (flags_num & O_NDELAY) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives.push("open the file in non-blocking mode".yellow());
                        }
                        if (flags_num & O_PATH) > 0 {
                            // TODO! change this to have better wording, change `base`
                            directives.push("return a `shallow` file descriptor".yellow());
                        }
                        if (flags_num & O_SYNC) > 0 {
                            directives.push("ensure writes are completely teransferred to hardware before return".yellow());
                        }
                        directives_handler(directives, &mut self.one_line);

                        if (flags_num & O_TRUNC) > 0 {
                            self.one_line
                                .push("truncate the file's length to zero".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully opened file".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::stat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("get the stats of the file: ".white());
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fstat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("get the stats of the file: ".white());
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::lstat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("get the stats of the file: ".white());
                        handle_path_file(filename, &mut self.one_line);
                        self.one_line
                            .push(" and do not recurse symbolic links".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::statfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get stats for the filesystem mounted in: ".white());
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fstatfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get stats for the filesystem that contains the file: ".white());
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::newfstatat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename: String = self.pavfol(1);
                let flags: rustix::fs::AtFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("get the stats of the file: ".white());
                        handle_path_file(filename, &mut self.one_line);

                        let mut flag_directive = vec![];
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it".yellow(),
                            );
                        }
                        if flags.contains(rustix::fs::AtFlags::EACCESS) {
                            flag_directive.push("check using effective user & group ids".yellow());
                        }
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                            flag_directive.push("recurse symbolic links if found".yellow());
                        }
                        if flags.contains(rustix::fs::AtFlags::NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .yellow(),
                    );
                        }
                        if flags.contains(rustix::fs::AtFlags::EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty".yellow(),
                            );
                        }
                        if flag_directive.len() > 0 {
                            self.one_line.push(" (".white());
                            let mut flag_directive_iter = flag_directive.into_iter().peekable();
                            if flag_directive_iter.peek().is_some() {
                                self.one_line.push(flag_directive_iter.next().unwrap());
                            }
                            for entry in flag_directive_iter {
                                self.one_line.push(", ".white());
                                self.one_line.push(entry);
                            }
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::statx => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename: String = self.pavfol(1);
                let flags: rustix::fs::AtFlags =
                    unsafe { std::mem::transmute(self.args[2] as u32) };
                let statx_mask: rustix::fs::StatxFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("get the stats of the file: ".white());
                        handle_path_file(filename, &mut self.one_line);

                        let mut flag_directive = vec![];
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it".yellow(),
                            );
                        }
                        if flags.contains(rustix::fs::AtFlags::EACCESS) {
                            flag_directive.push("check using effective user & group ids".yellow());
                        }
                        if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                            flag_directive.push("recurse symbolic links if found".yellow());
                        }
                        if flags.contains(rustix::fs::AtFlags::NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .yellow(),
                    );
                        }
                        if flags.contains(rustix::fs::AtFlags::EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty".yellow(),
                            );
                        }
                        if flag_directive.len() > 0 {
                            self.one_line.push(" (".white());
                            let mut flag_directive_iter = flag_directive.into_iter().peekable();
                            if flag_directive_iter.peek().is_some() {
                                self.one_line.push(flag_directive_iter.next().unwrap());
                            }
                            for entry in flag_directive_iter {
                                self.one_line.push(", ".white());
                                self.one_line.push(entry);
                            }
                            self.one_line.push(")".white());
                        }
                        // TODO!
                        // println!("{:?}", statx_mask);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::chown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = self.args[1] as i32;
                let group_given = self.args[2] as i32;
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.one_line.push("change the owner of ".white());
                            handle_path_file(filename, &mut self.one_line);
                            self.one_line.push(" to ".white());
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push(", and its group to ".white());
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push("change the owner of the file: ".white());
                                handle_path_file(filename, &mut self.one_line);
                                self.one_line.push("to ".white());
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("ownership changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = self.args[1] as i32;
                let group_given = self.args[2] as i32;
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.one_line.push("change the owner of ".white());
                            handle_path_file(filename, &mut self.one_line);
                            self.one_line.push(" to ".white());
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push(", and its group to ".white());
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push("change the owner of the file: ".white());
                                handle_path_file(filename, &mut self.one_line);

                                self.one_line.push("to ".white());
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("ownership changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::lchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = self.args[1] as i32;
                let group_given = self.args[2] as i32;
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.one_line.push("change the owner of ".white());
                            handle_path_file(filename, &mut self.one_line);
                            self.one_line.push(" to ".white());
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push(", and its group to ".white());
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push("change the owner of the file: ".white());
                                handle_path_file(filename, &mut self.one_line);
                                self.one_line.push("to ".white());
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("ownership changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fchownat => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = self.args[2] as i32;
                let group_given = self.args[3] as i32;
                let filename = self.pavfol(1);
                match self.state {
                    Entering => {
                        if owner_given != -1 {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.as_str().unwrap();

                            self.one_line.push("change the owner of ".white());
                            handle_path_file(filename, &mut self.one_line);
                            self.one_line.push(" to ".white());
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push(", and its group to ".white());
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.one_line.push("change the owner of the file: ".white());
                                handle_path_file(filename, &mut self.one_line);
                                self.one_line.push("to ".white());
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("ownership changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::madvise => {
                // addr, len, adv
                let len = self.pavfol(1);
                let addr = self.pavfol(0);
                let advice = self.args[2] as i32;
                match self.state {
                    Entering => {
                        if (advice & MADV_NORMAL) == MADV_NORMAL {
                            self.one_line.push("provide default treatment for ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_RANDOM) == MADV_RANDOM {
                            self.one_line.push("expect ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" to be referenced in random order".white());
                        } else if (advice & MADV_SEQUENTIAL) == MADV_SEQUENTIAL {
                            self.one_line.push("expect ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" to be referenced in sequential order".white());
                        } else if (advice & MADV_WILLNEED) == MADV_WILLNEED {
                            self.one_line.push("expect ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" to be accessed in the future".white());
                        } else if (advice & MADV_DONTNEED) == MADV_DONTNEED {
                            self.one_line.push("do not expect the".yellow());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" to be accessed in the future".white());
                        } else if (advice & MADV_REMOVE) == MADV_REMOVE {
                            // equivalent to punching a hole in the corresponding range
                            self.one_line.push("free".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_DONTFORK) == MADV_DONTFORK {
                            self.one_line.push("do not allow ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" to be available to children from ".white());
                            self.one_line.push("fork()".blue());
                        } else if (advice & MADV_DOFORK) == MADV_DOFORK {
                            self.one_line.push("allow ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" to be available to children from ".white());
                            self.one_line.push("fork()".blue());
                            self.one_line.push(" ".white());
                            self.one_line.push("(Undo MADV_DONTFORK)".yellow());
                        } else if (advice & MADV_HWPOISON) == MADV_HWPOISON {
                            // treat subsequent references to those pages like a hardware memory corruption
                            self.one_line.push("poison ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_MERGEABLE) == MADV_MERGEABLE {
                            // KSM merges only private anonymous pages
                            self.one_line
                                .push("enable KSM (Kernel Samepage Merging) for ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_UNMERGEABLE) == MADV_UNMERGEABLE {
                            self.one_line.push(
                                "unmerge all previous KSM merges from MADV_MERGEABLE in ".white(),
                            );
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_HUGEPAGE) == MADV_HUGEPAGE {
                            self.one_line.push("enable".yellow());
                            self.one_line
                                .push(" transparent huge pages (THP) on ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_NOHUGEPAGE) == MADV_NOHUGEPAGE {
                            self.one_line.push("disable".yellow());
                            self.one_line
                                .push(" transparent huge pages (THP) on ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_COLLAPSE) == MADV_COLLAPSE {
                            // TODO! citation needed
                            self.one_line
                                .push("perform a synchronous collapse of ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" that's mapped into transparent huge pages (THP)".white());
                        } else if (advice & MADV_DONTDUMP) == MADV_DONTDUMP {
                            self.one_line.push("exclude ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" from core dumps".white());
                        } else if (advice & MADV_DODUMP) == MADV_DODUMP {
                            self.one_line.push("include ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" in core dumps ".white());
                            self.one_line.push("(Undo MADV_DONTDUMP)".yellow());
                        } else if (advice & MADV_FREE) == MADV_FREE {
                            self.one_line.push("the range of ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push(" is no longer required and is ok to free".white());
                        } else if (advice & MADV_WIPEONFORK) == MADV_WIPEONFORK {
                            self.one_line.push("zero-fill the range of ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" to any child from ".white());
                            self.one_line.push("fork()".blue());
                        } else if (advice & MADV_KEEPONFORK) == MADV_KEEPONFORK {
                            self.one_line.push("keep the range of ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" to any child from ".white());
                            self.one_line.push("fork()".blue());
                            self.one_line.push(" ".white());
                            self.one_line.push("(Undo MADV_WIPEONFORK)".yellow());
                        } else if (advice & MADV_COLD) == MADV_COLD {
                            // This makes the pages a more probable reclaim target during memory pressure
                            self.one_line.push("deactivate ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line
                                .push("  (make more probable to reclaim)".white());
                        } else if (advice & MADV_PAGEOUT) == MADV_PAGEOUT {
                            // This is done to free up memory occupied by these pages.
                            // If a page is anonymous, it will be swapped out.
                            // If a page  is  file-backed and dirty, it will be written back to the backing storage
                            self.one_line.push("page out ".white()); // "page out" is more intuitive, "reclaim" is misleading
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_POPULATE_READ) == MADV_POPULATE_READ {
                            self.one_line.push("prefault ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" while avoiding memory access ".white());
                            self.one_line.push("(simulate reading)".yellow());
                        } else if (advice & MADV_POPULATE_WRITE) == MADV_POPULATE_WRITE {
                            self.one_line.push("prefault ".white());
                            self.one_line.push(len.yellow());
                            self.one_line.push(" of memory starting from ".white());
                            self.one_line.push(addr.yellow());
                            self.one_line.push(" while avoiding memory access ".white());
                            self.one_line.push("(simulate writing)".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("memory advice registered".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mmap => {
                // MMAP ARGS
                //
                //
                //
                let mapping_flags_num = self.args[3] as i32;

                let shared = (mapping_flags_num & MAP_SHARED) == MAP_SHARED;
                let private = (mapping_flags_num & MAP_PRIVATE) == MAP_PRIVATE;

                let shared_validate = (mapping_flags_num as i32 & MAP_SHARED_VALIDATE) > 0;

                let anonymous = ((mapping_flags_num & MAP_ANON) == MAP_ANON)
                    || ((mapping_flags_num & MAP_ANONYMOUS) == MAP_ANONYMOUS);

                let huge_pages_used = (mapping_flags_num & MAP_HUGETLB) == MAP_HUGETLB;
                let populate = (mapping_flags_num & MAP_POPULATE) == MAP_POPULATE;
                let lock = (mapping_flags_num & MAP_LOCKED) == MAP_LOCKED;

                let fixed = (mapping_flags_num & MAP_FIXED) == MAP_FIXED;
                let non_blocking = (mapping_flags_num & MAP_NONBLOCK) == MAP_NONBLOCK;
                let no_reserve = (mapping_flags_num & MAP_NORESERVE) == MAP_NORESERVE;
                let stack = (mapping_flags_num & MAP_STACK) == MAP_STACK;

                let sync = (mapping_flags_num as i32 & MAP_SYNC) > 0;

                let prot_flags: ProtFlags = unsafe { std::mem::transmute(self.args[2] as u32) };
                let bytes = self.pavfol(1);
                let fd = self.args[4] as RawFd;
                let addr = self.args[0] as *const ();
                let address = self.pavfol(0);
                let offset_num = self.args[5];
                let offset = self.pavfol(5);
                match self.state {
                    Entering => {
                        // AMOUNT OF BYTES
                        //
                        //
                        //
                        if !anonymous {
                            self.one_line.push("map ".white());
                        } else {
                            self.one_line.push("allocate ".white());
                        }
                        self.one_line.push(bytes.yellow());
                        // BACKED BY FILE
                        //
                        //
                        //
                        if !anonymous {
                            self.one_line.push(" of the file: ".white());
                            let filename = self.pavfol(4);
                            self.one_line.push(filename.yellow());
                            if offset_num > 0 {
                                self.one_line.push(" at an offset of ".white());
                                self.one_line.push(offset.to_string().yellow());
                            }
                        }

                        self.one_line.push(" as ".white());
                        // PRIVATE VS SHARED
                        //
                        //
                        //
                        // check shared_validate first because its 0x3 (shared and private are 0x1, and 0x2)
                        if shared_validate {
                            self.one_line.push("shared memory".yellow());
                        } else if shared {
                            self.one_line.push("shared memory".yellow());
                        // no need to check MAP_PRIVATE,
                        // its the last option at this point
                        // and mmap will fail if its not provided
                        } else if private {
                            self.one_line.push("private copy-on-write memory".yellow());
                        }

                        // HUGE PAGES
                        //
                        //
                        //
                        if huge_pages_used {
                            self.one_line.push(" using ".white());
                            if (mapping_flags_num & MAP_HUGE_64KB) == MAP_HUGE_64KB {
                                self.one_line.push("64 KB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_512KB) == MAP_HUGE_512KB {
                                self.one_line.push("512 KB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_1MB) == MAP_HUGE_1MB {
                                self.one_line.push("1 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_2MB) == MAP_HUGE_2MB {
                                self.one_line.push("2 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_8MB) == MAP_HUGE_8MB {
                                self.one_line.push("8 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_16MB) == MAP_HUGE_16MB {
                                self.one_line.push("16 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_32MB) == MAP_HUGE_32MB {
                                self.one_line.push("32 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_256MB) == MAP_HUGE_256MB {
                                self.one_line.push("256 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_512MB) == MAP_HUGE_512MB {
                                self.one_line.push("512 MB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_1GB) == MAP_HUGE_1GB {
                                self.one_line.push("1 GB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_2GB) == MAP_HUGE_2GB {
                                self.one_line.push("2 GB ".yellow());
                            } else if (mapping_flags_num & MAP_HUGE_16GB) == MAP_HUGE_16GB {
                                self.one_line.push("16 GB ".yellow());
                            }
                            self.one_line.push("hugepages".yellow());
                        }

                        // POPULATE
                        //
                        //
                        //
                        if populate && !non_blocking {
                            self.one_line.push(" ".white());
                            self.one_line.push("and prefault it".yellow());
                            // MAP_NON_BLOCK disables MAP_POPULATE since 2.5.46
                        }

                        let mut others = vec![];
                        if lock {
                            others.push("don't swap memory".yellow());
                        }
                        if no_reserve {
                            // we trust that there will be enough swap space at any time in the future
                            // Swap space is shared by all the processes, so there can never be a guarantee that there is enough of it
                            // preallocating it (more or less) gives a guaranty that the calling process will always have enough of it
                            others.push("don't reserve swap space".yellow());
                        }

                        if stack {
                            others.push("choose an address suitable for a stack".yellow());
                        }

                        if sync && shared_validate {
                            others.push("use Direct Access (DAX) for file writes".yellow());
                        }

                        if others.len() > 0 {
                            self.one_line.push(" (".white());
                            vanilla_commas_handler(others, &mut self.one_line);
                            self.one_line.push(")".white());
                        }

                        // ADDRESS
                        //
                        //
                        //
                        if addr.is_null() {
                            self.one_line.push(" at ".white());
                            self.one_line
                                .push("an appropiate kernel chosen address".yellow());
                        } else if (mapping_flags_num & MAP_FIXED) == MAP_FIXED {
                            self.one_line.extend([
                                " starting ".white(),
                                "exactly at ".yellow(),
                                address.yellow(),
                            ]);
                        } else if (mapping_flags_num & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE {
                            self.one_line.extend([
                                " starting ".white(),
                                "exactly at ".yellow(),
                                address.yellow(),
                                " and fail if a mapping already exists ".yellow(),
                            ]);
                        } else {
                            self.one_line.extend([
                                " starting ".white(),
                                "around ".yellow(),
                                address.yellow(),
                            ]);
                        }

                        // MEMORY DIRECTION
                        //
                        //
                        //
                        if (mapping_flags_num & MAP_GROWSDOWN) == MAP_GROWSDOWN {
                            self.one_line.push(" growing down,".yellow());
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
                                flags.push("reading".yellow());
                            }
                            if prot_flags.contains(ProtFlags::PROT_WRITE) {
                                flags.push("writing".yellow());
                            }
                            if prot_flags.contains(ProtFlags::PROT_EXEC) {
                                flags.push("execution".yellow());
                            }
                            if !flags.is_empty() {
                                self.one_line.push(" and allow ".white());
                                vanilla_commas_handler(flags, &mut self.one_line);
                            }
                        } else {
                            // TODO! guard pages note should be improved
                            self.one_line
                                .push(" without protection (Guard Pages)".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("new mapping address: ".green());
                            let address = eph_return.unwrap();
                            // p!(where_in_childs_memory(self.child, self.result.0.unwrap())
                            //     .unwrap()
                            //     .pathname);
                            self.one_line.push(address.yellow());
                            // if anonymous {
                            //     let k = get_child_memory_break(self.child);
                            //     let res = self.result.0.unwrap();
                            //     if (res >= k.1 .0) & (res <= k.1 .1) {
                            //         p!(mapping_flags);
                            //         p!("mmap address inside stack");
                            //         println!(
                            //             "stack range: 0x{:x} - 0x{:x}, mmap: 0x{:x}, mmap return: {}",
                            //             k.1 .0, k.1 .1, self.args[0], address
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
                            //             k.0, self.args[0], address
                            //         );
                            //     } else {
                            //         p!("..")
                            //     }
                            // }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::munmap => {
                let address = self.pavfol(0);
                let bytes = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("unmap ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" from memory starting at ".white());
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully unmapped region".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::msync => {
                let address = self.pavfol(0);
                let bytes = self.pavfol(1);
                let msync_flags: MsFlags = unsafe { std::mem::transmute(self.args[2] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("flush all changes made on ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" of memory starting from ".white());
                        self.one_line.push(address.yellow());
                        self.one_line.push(" back to the filesystem".white());
                        if msync_flags.contains(MsFlags::MS_ASYNC) {
                            self.one_line.push(" (".white());
                            self.one_line
                                .push("schedule the update, but return immediately".yellow());
                            self.one_line.push(")".white());
                        } else if msync_flags.contains(MsFlags::MS_INVALIDATE) {
                            self.one_line.push(" (".white());
                            self.one_line.push("block until completion".yellow());
                            self.one_line.push(")".white());
                        } else if msync_flags.contains(MsFlags::MS_SYNC) {
                            // this is used to propagate
                            self.one_line.push(" (".white());
                            self.one_line.push(
                                "invalidate other mappings of the file to propagate these changes"
                                    .yellow(),
                            );
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mprotect => {
                let address = self.pavfol(0);
                let bytes = self.pavfol(1);
                let prot_flags: ProtFlags = unsafe { std::mem::transmute(self.args[2] as u32) };
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
                            self.one_line.push("prevent ".white());
                            self.one_line.push("all access".yellow());
                        } else {
                            if all_prots.intersects(prot_flags) {
                                self.one_line.push("allow ".white());
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
                                            self.one_line.push("reading".yellow());
                                        }
                                        ProtFlags::PROT_WRITE => {
                                            self.one_line.push("writing".yellow());
                                        }
                                        ProtFlags::PROT_EXEC => {
                                            self.one_line.push("execution".yellow());
                                        }
                                        _ => unreachable!(),
                                    }
                                    if index != len - 1 {
                                        self.one_line.push(", ".yellow());
                                    }
                                }
                            }
                        }
                        // AMOUNT OF BYTES
                        //
                        //
                        //
                        self.one_line.push(" on ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" of memory ".white());
                        // ADDRESS
                        //
                        //
                        //
                        self.one_line.push("starting from ".white());
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("memory protection modified".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::lseek => {
                let filename = self.pavfol(0);
                let offset_num = self.args[1] as i64;
                let offset = self.pavfol(1);

                let whence: Whence = unsafe { std::mem::transmute(self.args[2] as u32) };
                match self.state {
                    Entering => {
                        match whence {
                            Whence::SeekSet => {
                                if offset_num == 0 {
                                    self.one_line
                                        .push("move the file pointer of the file: ".white());
                                    self.one_line.push(filename.yellow());
                                    self.one_line.push(" to ".white());
                                    self.one_line.push("the beginning of the file".yellow());
                                } else {
                                    self.one_line.push(offset.yellow());
                                    self.one_line
                                        .push("from the beginning of the file".yellow());
                                }
                            }
                            Whence::SeekCur => {
                                self.one_line
                                    .push("move the file pointer of the file: ".white());
                                self.one_line.push(filename.yellow());
                                self.one_line.push(" ".white());
                                if offset_num == 0 {
                                    // self.one_line
                                    //     .push("[intentrace: redundant syscall (won't do anything)]".white());

                                    self.one_line.push("to ".white());
                                    self.one_line.push("the current file pointer".yellow());
                                } else if offset_num > 0 {
                                    self.one_line.push(offset.yellow());
                                    self.one_line.push(" forwards".yellow());
                                } else {
                                    self.one_line.push((&offset[1..]).yellow());
                                    self.one_line.push(" backwards".yellow());
                                }
                            }
                            Whence::SeekEnd => {
                                self.one_line
                                    .push("move the file pointer of the file: ".white());
                                self.one_line.push(filename.yellow());
                                self.one_line.push(" ".white());

                                if offset_num == 0 {
                                    self.one_line.push("to ".white());
                                    self.one_line.push("the end of the file".yellow());
                                } else if offset_num > 0 {
                                    self.one_line.push(offset.yellow());
                                    self.one_line.push(" after ".white());
                                    self.one_line.push("the end of the file".yellow());
                                } else {
                                    self.one_line.push((&offset[1..]).yellow());
                                    self.one_line.push(" before ".white());
                                    self.one_line.push("the end of the file".yellow());
                                }
                            }
                            Whence::SeekData => {
                                self.one_line
                                    .push("move the file pointer of the file: ".white());
                                self.one_line.push(filename.yellow());
                                self.one_line.push(" to ".white());
                                self.one_line.push("the nearest data block".yellow());
                                self.one_line.push(" you find ".white());
                                if offset_num == 0 {
                                    self.one_line.push("at the beginning of the file".yellow());
                                } else if offset_num > 0 {
                                    self.one_line.push("after ".yellow());
                                    self.one_line.push(offset.yellow());
                                } else {
                                    self.one_line.push(offset.yellow());
                                    // this should be an error
                                    self.one_line
                                        .push(" before the beginning of the file ".yellow());
                                }
                            }
                            Whence::SeekHole => {
                                self.one_line
                                    .push("move the file pointer of the file: ".white());
                                self.one_line.push(filename.yellow());
                                self.one_line.push(" to ".white());
                                self.one_line.push("the nearest data hole".yellow());
                                self.one_line.push(" you find ".white());
                                if offset_num == 0 {
                                    self.one_line.push("at the beginning of the file".yellow());
                                } else if offset_num > 0 {
                                    self.one_line.push("after ".yellow());
                                    self.one_line.push(offset.yellow());
                                } else {
                                    self.one_line.push(offset.yellow());
                                    // TODO! test this
                                    self.one_line
                                        .push(" before the beginning of the file ".yellow());
                                }
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("new offset location: ".green());
                            self.one_line.push(eph_return.unwrap().green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mlock => {
                let address = self.pavfol(0);
                let bytes_num = self.args[1];
                let bytes = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("prevent swapping of memory on ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" starting from: ".white());
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mlock2 => {
                let address = self.pavfol(0);
                let bytes_num = self.args[1];
                let bytes = self.pavfol(1);
                let flags = self.args[2] as u32;
                match self.state {
                    Entering => {
                        self.one_line.push("prevent swapping of memory on ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" starting from: ".white());
                        self.one_line.push(address.yellow());

                        // if flags.contains(crate::utilities::mlock2::MLOCK_ONFAULT) {
                        // 1 = MLOCK_ONFAULT
                        if (flags & 1) == 1 {
                            self.one_line.push(" (".white());
                            // this allow non-resident pages to get locked later when they are faulted
                            self.one_line.push("only lock resident-pages, only lock non-resident pages once they're faulted".white());
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::munlock => {
                let address = self.pavfol(0);
                let bytes_num = self.args[1];
                let bytes = self.pavfol(1);

                match self.state {
                    Entering => {
                        self.one_line.push("allow swapping of memory on ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" starting from: ".white());
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("memory range is now swappable".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::munlockall => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "allow the entire memory of the calling process to be swappable"
                                .white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("memory range is now swappable".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mremap => {
                // TODO! current mremap logic is not good and needs rewriting
                let old_address_num = self.args[0];
                let old_address = self.pavfol(0);
                let old_len_num = self.args[1];
                let old_len = self.pavfol(1);
                let new_len_num = self.args[2];
                let new_len = self.pavfol(2);
                let flags: MRemapFlags = unsafe { std::mem::transmute(self.args[3] as u32) };
                let new_address_num = self.args[4];
                let new_address = self.pavfol(4);
                match self.state {
                    Entering => {
                        if new_len_num > old_len_num {
                            self.one_line.push("expand the memory region of ".white());
                            self.one_line.push(old_len.yellow());
                            self.one_line.push(" starting from: ".yellow());
                            self.one_line.push(old_address.yellow());
                        } else if new_len_num < old_len_num {
                            self.one_line.push("shrink the memory region of ".white());
                            self.one_line.push(old_len.yellow());
                            self.one_line.push(" starting from: ".yellow());
                            self.one_line.push(old_address.yellow());
                        } else if new_len_num == old_len_num {
                            if old_address_num == new_address_num {
                                self.one_line
                                    .push("[intentrace Notice: syscall no-op]".blink());
                            } else {
                                self.one_line.push("move the memory region of ".white());
                                self.one_line.push(old_len.yellow());
                                self.one_line.push(" starting from: ".yellow());
                                self.one_line.push(old_address.yellow());
                            }
                        }
                        if flags.contains(MRemapFlags::MREMAP_FIXED)
                            && flags.contains(MRemapFlags::MREMAP_MAYMOVE)
                        {
                            self.one_line.push(" (".white());
                            self.one_line.push(
                        "move the mapping to a different address if you can not expand at current address"
                            .yellow(),
                    );
                            self.one_line.push(")".white());
                        } else if flags.contains(MRemapFlags::MREMAP_MAYMOVE) {
                            self.one_line.push(" (".white());
                            self.one_line.push(
                        "move the mapping to a different address if you can not expand at current address"
                            .yellow(),
                    );
                            self.one_line.push(")".white());
                        } // else if flags.contains( MRemapFlags::MREMAP_DONTUNMAP) {
                          // unsupported at rustix atm
                          // }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mincore => {
                // TODO! current mremap logic is not good and needs rewriting
                let address_num = self.args[0];
                let address = self.pavfol(0);
                let length_num = self.args[1];
                let length = self.pavfol(1);

                match self.state {
                    Entering => {
                        self.one_line
                            .push("populate a vector of bytes representing ".white());
                        self.one_line.push(length.yellow());
                        self.one_line
                            .push(" of the process's memory starting from: ".yellow());
                        self.one_line.push(address.yellow());
                        self.one_line.push(
                            " indicating resident and non-resident pages in each byte".white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mlockall => {
                let flags_num = self.args[0] as i32;
                let flags: rustix::mm::MlockAllFlags =
                    unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("prevent swapping of ".white());

                        match (
                            (flags_num & MCL_CURRENT) == MCL_CURRENT,
                            (flags_num & MCL_FUTURE) == MCL_FUTURE,
                        ) {
                            (true, true) => {
                                self.one_line
                                    .push("all current and future mapped pages".yellow());
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.one_line.push(" (only lock resident-pages for current and future mappings, lock non-resident pages whenever they're faulted)".white());
                                }
                            }
                            (true, false) => {
                                self.one_line.push("all currently mapped pages".yellow());
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.one_line.push(" (only lock currently resident-pages, only lock non-resident pages once they're faulted)".white());
                                }
                            }
                            (false, true) => {
                                self.one_line.push("all future mapped pages ".yellow());
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.one_line.push(" (do not lock future pages the moment they're mapped, only lock whenever they're faulted)".white());
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
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::read => {
                let filename = self.pavfol(0);
                let bytes_to_read = self.args[2];
                let bytes = self.pavfol(2);
                match self.state {
                    Entering => {
                        self.one_line.push("read ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" from the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if bytes_num == 0 {
                                self.one_line.push("read ".green());
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (end of file)".green());
                            } else if bytes_num < bytes_to_read {
                                self.one_line.push("read ".green());
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (fewer than requested)".green());
                            } else {
                                self.one_line.push("read all ".green());
                                self.one_line.push(bytes_to_read.to_string().yellow());
                                self.one_line.push(" Bytes".yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::write => {
                let bytes_to_write = self.args[2];
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("write ".white());
                        if bytes_to_write < 20 {
                            self.one_line.push(format!("{:?}", self.pavfol(1)).yellow());
                        } else {
                            self.one_line.push(self.pavfol(2).yellow());
                        }
                        self.one_line.push(" into the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if bytes_num < bytes_to_write {
                                self.one_line.push("wrote ".green());
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (fewer than requested)".green());
                            } else {
                                self.one_line.push("wrote all ".green());
                                self.one_line.push(bytes_to_write.to_string().yellow());
                                self.one_line.push(" Bytes".yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pread64 => {
                let bytes_to_read = self.args[2];
                let bytes = self.pavfol(2);
                let filename = self.pavfol(0);
                let offset = self.pavfol(3);
                match self.state {
                    Entering => {
                        self.one_line.push("read ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" from the file: ".white());
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" at an offset of ".white());
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num: u64 = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if bytes_num == 0 {
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (end of file)".green());
                            } else if bytes_num < bytes_to_read {
                                self.one_line.push("read ".green());
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (fewer than requested)".green());
                            } else {
                                self.one_line.push("read all ".green());
                                self.one_line.push(bytes_to_read.to_string().yellow());
                                self.one_line.push(" Bytes".yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pwrite64 => {
                let bytes_to_write = self.args[2];
                let filename = self.pavfol(0);
                let offset = self.pavfol(3);

                match self.state {
                    Entering => {
                        self.one_line.push("write ".white());
                        if bytes_to_write < 20 {
                            self.one_line.push(format!("{:?}", self.pavfol(1)).yellow());
                        } else {
                            self.one_line.push(self.pavfol(2).yellow());
                        }
                        self.one_line.push(" into the file: ".white());
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" at an offset of ".white());
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if bytes_num < bytes_to_write {
                                self.one_line.push("wrote ".green());
                                self.one_line.push(bytes_string.yellow());
                                self.one_line.push(" (fewer than requested)".green());
                            } else {
                                self.one_line.push("wrote all ".green());
                                self.one_line.push(bytes_to_write.to_string().yellow());
                                self.one_line.push(" Bytes".yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::readv => {
                let number_of_iovecs = self.args[2];
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("read from ".white());
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.one_line
                                .push(" region of memory from the file: ".white());
                        } else {
                            self.one_line
                                .push(" scattered regions of memory from the file: ".white());
                        }
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("read ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::writev => {
                let filename = self.pavfol(0);
                let number_of_iovecs = self.args[2];

                match self.state {
                    Entering => {
                        self.one_line.push("write into ".white());
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.one_line
                                .push(" region of memory of the file: ".white());
                        } else {
                            self.one_line
                                .push(" scattered regions of memory of the file: ".white());
                        }
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("wrote ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::preadv => {
                let number_of_iovecs = self.args[2];
                let filename = self.pavfol(0);
                let offset = self.pavfol(3);
                match self.state {
                    Entering => {
                        self.one_line.push("read from ".white());
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.one_line
                                .push(" region of memory from the file: ".white());
                        } else {
                            self.one_line
                                .push(" scattered regions of memory from the file: ".white());
                        }
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" at an offset of ".white());
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("read ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pwritev => {
                let number_of_iovecs = self.args[2];
                let filename = self.pavfol(0);
                let offset = self.pavfol(3);

                match self.state {
                    Entering => {
                        self.one_line.push("write into ".white());
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.one_line
                                .push(" region of memory of the file: ".white());
                        } else {
                            self.one_line
                                .push(" scattered regions of memory of the file: ".white());
                        }
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" at an offset of ".white());
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("wrote ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }

            Sysno::sync => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("flush all pending filesystem data and metadata writes".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("all writes flushed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            // TODO! granular
            // check if the file was moved only or renamed only or moved and renamed at the same time
            Sysno::rename => {
                let old_path = self.pavfol(0);
                let new_path = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("move the file: ".white());
                        self.one_line.push(old_path.yellow());
                        self.one_line.push(" to: ".white());
                        self.one_line.push(new_path.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("file moved".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::renameat => {
                let old_dirfd = self.pavfol(0);
                let old_path = self.pavfol(1);
                let new_dirfd = self.pavfol(2);
                let new_path = self.pavfol(3);
                match self.state {
                    Entering => {
                        self.one_line.push("move the file: ".white());
                        self.one_line.push(old_path.yellow());
                        self.one_line.push(" to: ".white());
                        self.one_line.push(new_path.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("file moved".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mkdir => {
                let path = self.pavfol(0);
                let path_rust = PathBuf::from(path);
                match self.state {
                    Entering => match path_rust.canonicalize() {
                        Ok(abs_path) => {
                            let canon_path = abs_path.canonicalize().unwrap();
                            self.one_line.push("create a new directory ".white());
                            self.one_line
                                .push(canon_path.file_name().unwrap().to_string_lossy().yellow());
                            self.one_line.push(" inside: ".white());
                            self.one_line
                                .push(canon_path.parent().unwrap().to_string_lossy().yellow());
                        }
                        Err(_) => {
                            self.one_line.push("[intentrace Error: path error]".blink());
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("directory created".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::mkdirat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let path: String = self.pavfol(1);
                let path_rust = PathBuf::from(path);
                match self.state {
                    Entering => {
                        if dirfd == AT_FDCWD {
                            match path_rust.canonicalize() {
                                Ok(abs_path) => {
                                    let canon_path = abs_path.canonicalize().unwrap();
                                    self.one_line.push("create a new directory ".white());
                                    self.one_line.push(
                                        canon_path.file_name().unwrap().to_string_lossy().yellow(),
                                    );
                                    self.one_line.push(" inside: ".white());
                                    self.one_line.push(
                                        canon_path.parent().unwrap().to_string_lossy().yellow(),
                                    );
                                }
                                Err(_) => {
                                    self.one_line.push("[intentrace Error: path error]".blink());
                                }
                            }
                        } else {
                            panic!("dirfd not handled yet")
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("directory created".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getcwd => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the current working directory".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("cwd: ".green());
                            let target = self.pavfol(0);
                            self.one_line.push(target.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::symlink => {
                let target = self.pavfol(0);
                let symlink = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("create the symlink: ".white());
                        self.one_line.push(symlink.yellow());
                        let symlink_buf = PathBuf::from(symlink);
                        match symlink_buf.canonicalize() {
                            Ok(sl) => {
                                self.one_line.pop();
                                self.one_line.push(sl.to_string_lossy().yellow());
                            }
                            Err(_) => {}
                        }
                        self.one_line.push(" and link it with: ".white());
                        self.one_line.push(target.yellow());
                        let target_buf = PathBuf::from(target);
                        match target_buf.canonicalize() {
                            Ok(tg) => {
                                self.one_line.pop();
                                self.one_line.push(tg.to_string_lossy().yellow());
                            }
                            Err(_) => {}
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("symlink created".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::symlinkat => {
                let target = self.pavfol(0);
                let symlink = self.pavfol(1);
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);

                match self.state {
                    Entering => {
                        self.one_line.push("create the symlink: ".white());
                        self.one_line.push(symlink.yellow());
                        let symlink_buf = PathBuf::from(symlink);
                        if dirfd == AT_FDCWD {
                            match symlink_buf.canonicalize() {
                                Ok(abs_path) => {
                                    self.one_line.pop();
                                    let file_name = abs_path.file_name().unwrap().to_string_lossy();
                                    self.one_line.push(file_name.yellow());
                                }
                                Err(_) => {
                                    // TODO!
                                }
                            }
                        } else {
                            panic!("dirfd not handled yet")
                        }
                        match symlink_buf.canonicalize() {
                            Ok(sl) => {
                                self.one_line.pop();
                                self.one_line.push(sl.to_string_lossy().yellow());
                            }
                            Err(_) => {}
                        }
                        self.one_line.push(" and link it with: ".white());
                        self.one_line.push(target.yellow());
                        let target_buf = PathBuf::from(target);
                        match target_buf.canonicalize() {
                            Ok(tg) => {
                                self.one_line.pop();
                                self.one_line.push(tg.to_string_lossy().yellow());
                            }
                            Err(_) => {}
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("symlink created".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    } // the file does not exist at this point
                }
            }
            Sysno::unlink => {
                let path = self.pavfol(0);
                let path_rust = PathBuf::from(path);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("unlink and possibly delete the file: ".white());
                        match path_rust.canonicalize() {
                            Ok(abs_path) => {
                                let canon_path = abs_path.canonicalize().unwrap();
                                self.one_line.push(
                                    canon_path.file_name().unwrap().to_string_lossy().yellow(),
                                );
                            }
                            Err(_) => {
                                self.one_line.push(path_rust.to_string_lossy().yellow());
                                // self.one_line.push("[intentrace Error: path error]".blink());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("unlinking successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    } // caution: the file is deleted at this point
                }
            }
            Sysno::unlinkat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let path = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("unlink and possibly delete the file: ".white());
                        self.one_line.push(path.yellow());
                        let path_rust = PathBuf::from(path);
                        if dirfd == AT_FDCWD {
                            match path_rust.canonicalize() {
                                Ok(abs_path) => {
                                    self.one_line.pop();
                                    let file_name = abs_path.file_name().unwrap().to_string_lossy();
                                    self.one_line.push(file_name.yellow());
                                }
                                Err(_) => {
                                    // self.one_line.push("[intentrace Error: path error]".blink());
                                }
                            }
                        } else {
                            // handle dirfd
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("unlinking successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::access => {
                let filename: String = self.pavfol(0);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(self.args[1] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.one_line.push("check if the file: ".white());
                            handle_path_file(filename, &mut self.one_line);
                            self.one_line.push(" exists".yellow());
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks.push("read".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push("write".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push("execute".yellow());
                            }
                            if !checks.is_empty() {
                                self.one_line
                                    .push("check if the process is allowed to ".white());
                                vanilla_commas_handler(checks, &mut self.one_line);
                                self.one_line.push(" the file ".white());
                                self.one_line.push(filename.yellow());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::faccessat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename = self.pavfol(1);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(self.args[2] as u32) };
                let flags: nix::fcntl::AtFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.one_line.push("check if the file : ".white());
                            self.one_line.push(filename.yellow());
                            self.one_line.push(" ".white());
                            self.one_line.push("exists".yellow());
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks.push("read".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push("write".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push("execute".yellow());
                            }
                            if !checks.is_empty() {
                                self.one_line
                                    .push("check if the process is allowed to ".white());
                                vanilla_commas_handler(checks, &mut self.one_line);
                                self.one_line.push(" the file ".white());
                                self.one_line.push(filename.yellow());
                            }
                        }
                        let mut flag_directive = vec![];
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it".yellow(),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EACCESS) {
                            flag_directive.push("check using effective user & group ids".yellow());
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW) {
                            flag_directive.push("recurse symbolic links if found".yellow());
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .yellow(),
                    );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty".yellow(),
                            );
                        }
                        directives_handler(flag_directive, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::faccessat2 => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename = self.pavfol(1);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(self.args[2] as u32) };
                let flags: nix::fcntl::AtFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.one_line.push("check if the file: ".white());
                            self.one_line.push(filename.yellow());
                            self.one_line.push(" ".white());
                            self.one_line.push("exists".yellow());
                        } else {
                            let mut checks = vec![];
                            if access_mode.contains(nix::unistd::AccessFlags::R_OK) {
                                checks.push("read".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::W_OK) {
                                checks.push("write".yellow());
                            }
                            if access_mode.contains(nix::unistd::AccessFlags::X_OK) {
                                checks.push("execute".yellow());
                            }

                            if !checks.is_empty() {
                                self.one_line
                                    .push("check if the process is allowed to ".white());
                                vanilla_commas_handler(checks, &mut self.one_line);
                                self.one_line.push(" the file ".white());
                                self.one_line.push(filename.yellow());
                            }
                        }
                        let mut flag_directive = vec![];
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it".yellow(),
                            );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EACCESS) {
                            flag_directive.push("check using effective user & group ids".yellow());
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW) {
                            flag_directive.push("recurse symbolic links if found".yellow());
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_NO_AUTOMOUNT) {
                            flag_directive.push(
                        "don't automount the basename of the path if its an automount directory"
                            .yellow(),
                    );
                        }
                        if flags.contains(nix::fcntl::AtFlags::AT_EMPTY_PATH) {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty".yellow(),
                            );
                        }
                        directives_handler(flag_directive, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::readlink => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the target path of the symbolic link: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("target retrieved: ".green());
                            let target = self.pavfol(1);
                            self.one_line.push(target.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::readlinkat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename: String = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the target path of the symbolic link: ".white());
                        self.one_line.push(filename.yellow());
                        let file_path_buf = PathBuf::from(filename);
                        if dirfd == AT_FDCWD {
                            match file_path_buf.canonicalize() {
                                Ok(abs_path) => {
                                    self.one_line.pop();
                                    let file_name = abs_path.file_name().unwrap().to_string_lossy();
                                    self.one_line.push(file_name.yellow());
                                }
                                Err(_) => {
                                    // self.one_line.push("[intentrace Error: path error]".blink());
                                }
                            }
                        } else {
                            panic!("dirfd not handled yet")
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("target retrieved: ".green());
                            let target = self.pavfol(2);
                            self.one_line.push(target.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::chmod => {
                let filename: String = self.pavfol(0);
                let mode: rustix::fs::Mode = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("change the mode of the file: ".white());
                        self.one_line.push(filename.yellow());
                        mode_matcher(mode, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fchmod => {
                let filename: String = self.pavfol(0);
                let mode: rustix::fs::Mode = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("change the mode of the file: ".white());
                        self.one_line.push(filename.yellow());
                        mode_matcher(mode, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fchmodat => {
                let dirfd = self.args[0] as i32;
                let dirfd_parsed = self.pavfol(0);
                let filename: String = self.pavfol(1);
                let mode: rustix::fs::Mode = unsafe { std::mem::transmute(self.args[2] as u32) };
                let flag: FchmodatFlags = unsafe { std::mem::transmute(self.args[3] as u8) };
                match self.state {
                    Entering => {
                        self.one_line.push("change the mode of the file: ".white());
                        self.one_line.push(filename.yellow());
                        let file_path_buf = PathBuf::from(filename);
                        if dirfd == AT_FDCWD {
                            match file_path_buf.canonicalize() {
                                Ok(abs_path) => {
                                    self.one_line.pop();
                                    let file_name = abs_path.file_name().unwrap().to_string_lossy();
                                    self.one_line.push(file_name.yellow());
                                }
                                Err(_) => {
                                    // self.one_line.push("[intentrace Error: path error]".blink());
                                }
                            }
                        } else {
                            panic!("dirfd not handled yet")
                        }
                        mode_matcher(mode, &mut self.one_line);
                        self.one_line.push("and ".white());
                        match flag {
                            FchmodatFlags::FollowSymlink => {
                                self.one_line.push("recurse symlinks".yellow());
                            }
                            FchmodatFlags::NoFollowSymlink => {
                                self.one_line.push("do not recurse symlinks".yellow());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::syncfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("flush all pending filesystem data and metadata writes for the filesystem that contains the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pipe => {
                let file_descriptors = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("create a pipe for inter-process communication".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("created the pipe: ".green());
                            self.one_line.push(file_descriptors.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pipe2 => {
                let file_descriptors = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("create a pipe for inter-process communication".white());
                        // flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("created the pipe: ".green());
                            self.one_line.push(file_descriptors.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::dup => {
                let file_descriptor = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("duplicate the file descriptor: ".white());
                        self.one_line.push(file_descriptor.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("created a new duplicate file descriptor: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::dup2 => {
                let to_be_duplicated = self.pavfol(0);
                let duplicate = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("duplicate the file descriptor: ".white());
                        self.one_line.push(to_be_duplicated.yellow());
                        self.one_line.push(" using the descriptor: ".white());
                        self.one_line.push(duplicate.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::dup3 => {
                let to_be_duplicated = self.pavfol(0);
                let duplicate = self.pavfol(1);
                let dup_flag_num = self.args[2] as i32;
                match self.state {
                    Entering => {
                        self.one_line
                            .push("duplicate the file descriptor: ".white());
                        self.one_line.push(to_be_duplicated.yellow());
                        self.one_line.push(" using the descriptor: ".white());
                        self.one_line.push(duplicate.yellow());
                        if (dup_flag_num & O_CLOEXEC) == O_CLOEXEC {
                            self.one_line
                                .push(" and close the file on the next exec syscall".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fsync => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "flush all pending data and metadata writes for the file: ".white(),
                        );
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("all writes flushed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fdatasync => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("flush all pending data and critical metadata writes (ignore non-critical metadata) for the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("all writes flushed".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::truncate => {
                let filename = self.pavfol(0);
                let length = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("change the size of the file: ".white());
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" to precisely ".white());
                        self.one_line.push(length.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::ftruncate => {
                let filename = self.pavfol(0);
                let length = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("change the size of the file: ".white());
                        self.one_line.push(filename.yellow());
                        self.one_line.push(" to precisely ".white());
                        self.one_line.push(length.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::select => {
                let highest_fd = self.args[0];
                let readfds = self.args[1];
                let writefds = self.args[2];
                let exceptfds = self.args[3];
                let timeout = self.args[4];
                match self.state {
                    Entering => {
                        self.one_line.push("block all ".white());
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push("read waiting".yellow());

                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     SyscallObject::read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         self.args[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push("write waiting".yellow());
                        }
                        if exceptfds != 0 {
                            blockers.push("error waiting".yellow());
                        }
                        anding_handler(blockers, &mut self.one_line);
                        self.one_line.push(" file descriptors lower than ".white());
                        self.one_line.push(highest_fd.to_string().blue());

                        if timeout > 0 {
                            let timeval = SyscallObject::read_bytes_as_struct::<16, timeval>(
                                self.args[4] as usize,
                                self.child as _,
                            )
                            .unwrap();
                            self.one_line.push(", and timeout ".white());
                            format_timeval(timeval.tv_sec, timeval.tv_usec, &mut self.one_line);
                        } else {
                            self.one_line.push(", and ".white());
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if res == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else if res > 0 {
                                self.one_line.push(res.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pselect6 => {
                let highest_fd = self.args[0];
                let readfds = self.args[1];
                let writefds = self.args[2];
                let exceptfds = self.args[3];
                let timeout = self.args[4];
                let signal_mask = self.args[5];
                match self.state {
                    Entering => {
                        self.one_line.push("block for events on all ".white());
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push("read waiting".yellow());

                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     SyscallObject::read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         self.args[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push("write waiting".yellow());
                        }
                        if exceptfds != 0 {
                            blockers.push("error waiting".yellow());
                        }
                        anding_handler(blockers, &mut self.one_line);
                        self.one_line.push(" file descriptors lower than ".white());
                        self.one_line.push(highest_fd.to_string().blue());
                        if signal_mask != 0 {
                            self.one_line.push(", and ".white());
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if timeout > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[4] as usize,
                                self.child as _,
                            )
                            .unwrap();
                            self.one_line.push(", and timeout ".white());
                            format_timespec(timespec.tv_sec, timespec.tv_nsec, &mut self.one_line);
                        } else {
                            self.one_line.push(", and ".white());
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if res == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else if res > 0 {
                                self.one_line.push(res.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::poll => {
                let nfds = self.args[1];
                let timeout = self.args[2];
                match self.state {
                    Entering => {
                        self.one_line.push("block for new events on the ".white());
                        self.one_line.push(nfds.to_string().blue());
                        self.one_line.push(" provided file descriptors, ".white());
                        self.one_line.push("and timeout after ".white());
                        self.one_line.push(timeout.to_string().blue());
                        self.one_line.push(" milliseconds".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if num_fds == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else {
                                self.one_line.push(num_fds.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::ppoll => {
                let nfds = self.args[1];
                let timeout = self.args[2];
                let signal_mask = self.args[3];

                match self.state {
                    Entering => {
                        self.one_line.push("block for new events on the ".white());
                        self.one_line.push(nfds.to_string().blue());
                        self.one_line.push(" provided file descriptors".white());

                        if signal_mask != 0 {
                            self.one_line.push(", or ".white());
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if timeout > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[2] as usize,
                                self.child as _,
                            )
                            .unwrap();
                            self.one_line.push(", and timeout ".white());
                            format_timespec(timespec.tv_sec, timespec.tv_nsec, &mut self.one_line);
                        } else {
                            self.one_line.push(", and ".white());
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.one_line.push(" |=> ".white());
                            if num_fds == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else {
                                self.one_line.push(num_fds.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_create => {
                let nfds = self.args[0];
                match self.state {
                    Entering => {
                        self.one_line
                            .push("create an epoll instance with a capacity of ".white());
                        self.one_line.push(nfds.to_string().yellow());
                        self.one_line.push(" file descriptors".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_create1 => {
                let flags = self.args[0];
                match self.state {
                    Entering => {
                        self.one_line.push("create an epoll instance ".white());

                        if flags as i32 == EPOLL_CLOEXEC {
                            self.one_line.push("(".white());
                            self.one_line
                                .push("close file descriptors on the next exec syscall".yellow());
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_wait => {
                let epfd = self.args[0];
                let max_events = self.args[2];
                let time = self.args[3];
                match self.state {
                    Entering => {
                        self.one_line.push("block until a maximum of ".white());
                        self.one_line.push(max_events.to_string().yellow());
                        self.one_line
                            .push(" events occur on epoll instance ".white());
                        self.one_line.push(epfd.to_string().blue());
                        if time > 0 {
                            self.one_line.push(" and wait for ".white());
                            self.one_line.push(time.to_string().blue());
                            self.one_line.push(" milliseconds".yellow());
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.one_line.push(" ".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_pwait => {
                let epfd = self.args[0];
                let max_events = self.args[2];
                let time = self.args[3];
                let signal_mask = self.args[4];
                match self.state {
                    Entering => {
                        self.one_line.push("block until a maximum of ".white());
                        self.one_line.push(max_events.to_string().yellow());
                        self.one_line
                            .push(" events occur on epoll instance ".white());
                        self.one_line.push(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.one_line.push(", or ".white());
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if time > 0 {
                            self.one_line.push(" and wait for ".white());
                            self.one_line.push(time.to_string().blue());
                            self.one_line.push(" milliseconds".yellow());
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.one_line.push(" ".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_pwait2 => {
                let epfd = self.args[0];
                let max_events = self.args[2];
                let time = self.args[3];
                let signal_mask = self.args[4];
                match self.state {
                    Entering => {
                        self.one_line.push("block until a maximum of ".white());
                        self.one_line.push(max_events.to_string().yellow());
                        self.one_line
                            .push(" events occur on epoll instance ".white());
                        self.one_line.push(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.one_line.push(", or ".white());
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if time > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[3] as usize,
                                self.child as _,
                            )
                            .unwrap();
                            self.one_line.push(", and timeout ".white());
                            format_timespec(timespec.tv_sec, timespec.tv_nsec, &mut self.one_line);
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.one_line.push(" ".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::epoll_ctl => {
                let epfd = self.args[0];
                let operation = self.args[1];
                let file_descriptor = self.args[2];
                match self.state {
                    Entering => {
                        if (operation as i32 & EPOLL_CTL_ADD) == EPOLL_CTL_ADD {
                            self.one_line.push("add".yellow());
                            self.one_line.push(" file descriptor ".white());
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.one_line.push(" to ".white());
                        } else if (operation as i32 & EPOLL_CTL_DEL) == EPOLL_CTL_DEL {
                            self.one_line.push("remove".yellow());
                            self.one_line.push(" file descriptor ".white());
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.one_line.push(" from ".white());
                        } else if (operation as i32 & EPOLL_CTL_MOD) == EPOLL_CTL_MOD {
                            self.one_line.push("modify the settings of ".yellow());
                            self.one_line.push(" file descriptor ".white());
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.one_line.push(" in ".white());
                        }
                        self.one_line.push("epoll instance ".white());
                        self.one_line.push(epfd.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::ioctl => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("perform operation ".white());
                        self.one_line
                            .push(format!("#{}", self.args[1].to_string()).yellow());
                        self.one_line.push(" on the device: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("operation successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fcntl => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line.push("perform operation ".white());
                        self.one_line
                            .push(format!("#{}", self.args[1].to_string()).yellow());
                        self.one_line.push(" on the file: ".white());
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("operation successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
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

                let operation = self.args[0];
                let value = self.args[1];

                match self.state {
                    Entering => {
                        if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                            if value == 0 {
                                self.one_line.push(
                                    "disable the `cpuid` instruction for the calling thread"
                                        .white(),
                                );
                            } else {
                                self.one_line.push(
                                    "enable the `cpuid` instruction for the calling thread".white(),
                                );
                            }
                        } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                            self.one_line.push(
                                "check whether the `cpuid` instruction is enabled or disabled"
                                    .white(),
                            );
                        } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                            self.one_line
                                .push("Set the 64-bit base for the FS register to ".white());
                            self.one_line.push(value.to_string().blue());
                        } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                            self.one_line.push(
                                "retrieve the calling thread's 64-bit FS register value".white(),
                            );
                        } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                            self.one_line
                                .push("Set the 64-bit base for the GS register to ".white());
                            self.one_line.push(value.to_string().blue());
                        } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                            self.one_line.push(
                                "retrieve the calling thread's 64-bit GS register value".white(),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());

                            if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                                if value == 0 {
                                    self.one_line.push(
                                        "successfully disabled the `cpuid` instruction".green(),
                                    );
                                } else {
                                    self.one_line.push(
                                        "successfully enabled the `cpuid` instruction".green(),
                                    );
                                }
                            } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                                let value = self.pavfol(1).parse::<u64>().unwrap();

                                if value == 0 {
                                    self.one_line
                                        .push("the `cpuid` instruction is disabled".green());
                                } else {
                                    self.one_line
                                        .push("the `cpuid` instruction is enabled".green());
                                }
                            } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                                self.one_line.push("FS register modified".green());
                            } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                                let value = self.pavfol(1);
                                self.one_line
                                    .push("retrieved value of the FS register: ".green());
                                self.one_line.push(value.blue());
                            } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                                self.one_line.push("GS register modified".green());
                            } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                                let value = self.pavfol(1);
                                self.one_line.push("value of the GS register ".green());
                                self.one_line.push(value.blue());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::sched_yield => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "relinquish the CPU, and move to the end of the scheduler queue"
                                .white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully yielded CPU".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigaction => {
                let signal_num = self.args[0];
                let signal_action = self.args[1] as *const ();
                let old_signal_action = self.args[2] as *const ();

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
                        //         self.args[1] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("sigaction",sigaction);
                        // }

                        // if !old_signal_action.is_null() {
                        //     let old_sigaction = SyscallObject::read_bytes_as_struct::<152, sigaction>(
                        //         self.args[2] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("old_sigaction",old_sigaction);
                        // }

                        match x86_signal_to_string(signal_num) {
                            Some(signal_as_string) => {
                                // second is non-NULL: the new action for signal signum is installed from act.
                                // third is non-NULL: the previous action is saved in oldact.
                                // second is NULL: query the current signal handler
                                // second and third is NULL: check whether a given signal is valid for the current machine
                                if !signal_action.is_null() {
                                    self.one_line
                                        .push("change the process's default handler for ".white());
                                    self.one_line.push(signal_as_string.yellow());
                                    self.one_line.push(" to the provided action".white());
                                    if !old_signal_action.is_null() {
                                        self.one_line.push(
                                            ", and retrieve the current signal handler".white(),
                                        );
                                    }
                                } else {
                                    if !old_signal_action.is_null() {
                                        self.one_line
                                            .push("retrieve the current signal handler".white());
                                    } else {
                                        self.one_line.push(
                                            "check if the current machine supports: ".white(),
                                        );
                                        self.one_line.push(signal_as_string.yellow());
                                    }
                                }
                            }
                            None => {
                                self.one_line.push(
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
                            self.one_line.push(" |=> ".white());
                            match x86_signal_to_string(signal_num) {
                                Some(signal_as_string) => {
                                    if !signal_action.is_null() {
                                        self.one_line.push("default handler changed".green());
                                        if !old_signal_action.is_null() {
                                            self.one_line
                                                .push(", and current handler retrieved".green());
                                        }
                                    } else {
                                        if !old_signal_action.is_null() {
                                            self.one_line.push("current handler retrieved".green());
                                        } else {
                                            // TODO! citation needed, but very safe to assume correct
                                            self.one_line.push("signal supported".green());
                                        }
                                    }
                                }
                                None => {
                                    self.one_line.push("successful".green());
                                }
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigprocmask => {
                let how: nix::sys::signal::SigmaskHow =
                    unsafe { std::mem::transmute(self.args[0] as u32) };
                let set = self.args[1] as *const ();
                let old_set = self.args[2] as *const ();
                match self.state {
                    Entering => {
                        if set.is_null() {
                            if !old_set.is_null() {
                                self.one_line.push(
                                    "retrieve the proccess's current list of blocked signals"
                                        .white(),
                                );
                            } else {
                                self.one_line
                                    .push("[intentrace Notice: syscall no-op]".blink());
                            }
                        } else {
                            match how {
                                nix::sys::signal::SigmaskHow::SIG_BLOCK => {
                                    self.one_line.push("add any missing signal from the provided signals to the proccess's list of blocked signals".white());
                                }
                                nix::sys::signal::SigmaskHow::SIG_UNBLOCK => {
                                    self.one_line.push("remove the provided signals from the proccess's list of blocked signals".white());
                                }
                                nix::sys::signal::SigmaskHow::SIG_SETMASK => {
                                    self.one_line.push("replace the proccess's list of blocked signals with the signals provided".white());
                                }
                                _ => {}
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            if set.is_null() {
                                if !old_set.is_null() {
                                    self.one_line.push("retrieved blocked signals".green());
                                } else {
                                    self.one_line
                                        .push("[intentrace Notice: syscall no-op]".blink());
                                }
                            } else {
                                match how {
                                    nix::sys::signal::SigmaskHow::SIG_BLOCK => {
                                        self.one_line.push("signals added".green());
                                    }
                                    nix::sys::signal::SigmaskHow::SIG_UNBLOCK => {
                                        self.one_line.push("signals removed".green());
                                    }
                                    nix::sys::signal::SigmaskHow::SIG_SETMASK => {
                                        self.one_line.push("successfully replaced".green());
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigsuspend => {
                match self.state {
                    Entering => {
                        self.one_line.push("replace the process' list of blocked signals with the signals provided, then wait until the delivery of either a signal that invokes a signal handler or a signal that terminates the thread".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("list of blocked signals modified".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::sigaltstack => {
                let new_stack_null = (self.args[0] as u32 as *const ()).is_null();
                let old_stack_null = (self.args[1] as u32 as *const ()).is_null();

                match self.state {
                    Entering => match (new_stack_null, old_stack_null) {
                        (true, true) => {
                            self.one_line.push(
                                "[intentrace: redundant syscall (won't do anything)]".blink(),
                            );
                        }
                        (true, false) => {
                            self.one_line
                                .push("replace the current signal stack with a new one".white());
                        }
                        (false, true) => {
                            self.one_line
                                .push("retrieve the current signal stack".white());
                        }
                        (false, false) => {
                            self.one_line.push(
                            "retrieve the current signal stack and then replace it with a new one,"
                                .white(),
                        );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            match (new_stack_null, old_stack_null) {
                                (true, true) => {
                                    self.one_line.push("successful".green());
                                }
                                (true, false) => {
                                    self.one_line.push("successfully replaced".green());
                                }
                                (false, true) => {
                                    self.one_line.push("signal stack retrieved".green());
                                }
                                (false, false) => {
                                    self.one_line.push(
                                        "signal stack replaced and old signal stack retrieved"
                                            .green(),
                                    );
                                }
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigreturn => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("return from signal handler and cleanup".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigpending => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "return the signals pending for delivery for the calling thread"
                                .white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("pending signals returned".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigtimedwait => {
                match self.state {
                    Entering => {
                        // TODO! use the timespec struct
                        self.one_line
                .push("stop the calling process until one of the signals provided is pending, or the given timeout is exceeded".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_sigqueueinfo => {
                let thread_group = self.args[0];
                let signal_num = self.args[1];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.one_line
                                .push("send the data attached and the ".white());
                            self.one_line.push(signal_as_string.yellow());
                            self.one_line.push(" signal to the thread group: ".white());
                            self.one_line.push(thread_group.to_string().yellow());
                        }
                        None => {
                            self.one_line.push(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("data and signal sent".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rt_tgsigqueueinfo => {
                let thread_group = self.args[0];
                let thread = self.args[1];
                let signal_num = self.args[2];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.one_line
                                .push("send the data attached and the ".white());
                            self.one_line.push(signal_as_string.yellow());
                            self.one_line.push(" signal to thread: ".white());
                            self.one_line.push(thread.to_string().yellow());
                            self.one_line.push(" in thread group: ".white());
                            self.one_line.push(thread_group.to_string().yellow());
                        }
                        None => {
                            self.one_line.push(
                                "[intentrace: signal not supported on x86]"
                                    .blink()
                                    .bright_black(),
                            );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("data and signal sent".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::pidfd_send_signal => {
                let process = self.pavfol(0);
                let signal_num = self.args[1];
                match self.state {
                    Entering => {
                        match x86_signal_to_string(signal_num) {
                            Some(signal_as_string) => {
                                self.one_line.push("send the ".white());
                                self.one_line.push(signal_as_string.yellow());
                                // bad wording
                                self.one_line.push(
                                    " signal to the process identified with the file descriptor: "
                                        .white(),
                                );
                                self.one_line.push(process.yellow());
                            }
                            None => {
                                self.one_line.push(
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
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::signalfd => {
                let fd = self.args[0] as i32;
                match self.state {
                    Entering => {
                        if fd == -1 {
                            self.one_line.push(
                        "create a new file descriptor for receiving the set of specified signals"
                            .white(),
                    );
                        } else {
                            let fd_file = self.pavfol(0);
                            self.one_line.push("use the file: ".white());
                            self.one_line.push(fd_file.yellow());
                            self.one_line
                                .push(" to receive the provided signals".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::signalfd4 => {
                let fd = self.args[0] as i32;
                let flags: SfdFlags = unsafe { std::mem::transmute(self.args[2] as u32) };
                match self.state {
                    Entering => {
                        if fd == -1 {
                            self.one_line.push(
                                "create a file descriptor to use for receiving the provided signals"
                                    .white(),
                            );
                        } else {
                            let fd_file = self.pavfol(0);
                            self.one_line.push("use the file: ".white());
                            self.one_line.push(fd_file.yellow());
                            self.one_line
                                .push(" to receive the provided signals".white());
                        }
                        let mut flag_directives = vec![];

                        if flags.contains(SfdFlags::SFD_CLOEXEC) {
                            flag_directives
                                .push("close the file with the next exec syscall".yellow());
                        }
                        if flags.contains(SfdFlags::SFD_NONBLOCK) {
                            flag_directives.push("use the file on non blocking mode".yellow());
                        }
                        directives_handler(flag_directives, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("file descriptor created".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::gettid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the thread id of the calling thread".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let thread = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the thread id: ".green());
                            self.one_line.push(thread.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getpid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the process id of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let process_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the process id: ".green());
                            self.one_line.push(process_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getppid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the process id of the parent process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let process_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the parent process' id: ".green());
                            self.one_line.push(process_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::get_robust_list => {
                let process_id_num = self.args[0];
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the list of the robust futexes for ".white());
                        if process_id_num == 0 {
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.one_line.push("thread ".white());
                            self.one_line.push(process_id_num.to_string().blue());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let address = self.pavfol(1);
                            let length_of_list =
                                SyscallObject::read_word(self.args[2] as usize, self.child)
                                    .unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("head of the retrieved list is stored in ".green());
                            self.one_line.push(address.yellow());
                            self.one_line.push(" with length ".green());
                            self.one_line.push(length_of_list.to_string().blue());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::set_robust_list => {
                let address = self.pavfol(0);
                let length_of_list = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "set the calling thread's robust futexes list to the list at ".white(),
                        );
                        self.one_line.push(address.yellow());
                        self.one_line.push(" with length ".white());
                        self.one_line.push(length_of_list.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::setpgid => {
                let process_id_num = self.args[0];
                let process_id = self.pavfol(0);
                let new_pgid_num = self.args[1];
                let new_pgid = self.pavfol(1);
                match self.state {
                    Entering => {
                        if process_id_num == 0 {
                            self.one_line.push("set the process group ID of ".white());
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.one_line
                                .push("set the process group ID of process: ".white());
                            self.one_line.push(process_id.yellow());
                        }
                        if new_pgid_num == 0 {
                            self.one_line.push(" to: ".white());
                            self.one_line.push("the calling process' ID".yellow());
                        } else {
                            self.one_line.push(" to: ".white());
                            self.one_line.push(new_pgid.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getpgid => {
                let process_id_num = self.args[0];
                let process_id = self.pavfol(0);
                match self.state {
                    Entering => {
                        if process_id_num == 0 {
                            self.one_line.push("get the process group ID of ".white());
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.one_line
                                .push("get the process group ID of process: ".white());
                            self.one_line.push(process_id.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let pgid = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the group id: ".green());
                            self.one_line.push(pgid.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getpgrp => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the process group ID of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let pgid = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the group id: ".green());
                            self.one_line.push(pgid.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getrandom => {
                let random_flags: GetRandomFlags =
                    unsafe { std::mem::transmute(self.args[2] as u32) };
                let bytes_num = self.args[1];
                let bytes = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push("get ".white());
                        self.one_line.push(bytes.yellow());
                        self.one_line.push(" of random bytes from the ".white());
                        if random_flags.contains(GetRandomFlags::RANDOM) {
                            self.one_line.push("random source".yellow());
                            self.one_line.push(" and ".white());
                            if random_flags.contains(GetRandomFlags::NONBLOCK) {
                                self.one_line
                                    .push("do not block if the random source is empty".yellow());
                            } else {
                                self.one_line
                                    .push("block if the random source is empty".yellow());
                            }
                        } else {
                            self.one_line.push("urandom source".yellow());
                            self.one_line.push(" and ".white());
                            if random_flags.contains(GetRandomFlags::NONBLOCK) {
                                self.one_line.push(
                                    "do not block if the entropy pool is uninitialized".yellow(),
                                );
                            } else {
                                self.one_line
                                    .push("block if the entropy pool is uninitialized".yellow());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_retrieved = self.result.0.unwrap();

                            self.one_line.push(" |=> ".white());
                            if bytes_retrieved == 0 {
                                self.one_line.push("retrieved ".green());
                                self.one_line.push(eph_return.unwrap().green());
                            } else if bytes_retrieved < bytes_num {
                                self.one_line.push("retrieved ".green());
                                self.one_line.push(eph_return.unwrap().green());
                                self.one_line.push(" (fewer than requested)".green());
                            } else {
                                self.one_line.push("retrieved all ".green());
                                self.one_line.push(eph_return.unwrap().green());
                                self.one_line.push(" (complete)".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::setrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.one_line.push("set the process's ".white());
                        resource_matcher(resource, &mut self.one_line);
                        self.one_line
                            .push(" to the soft and hard limits provided".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the soft and hard limits for the process's ".white());
                        resource_matcher(resource, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::prlimit64 => {
                let pid = self.args[0] as pid_t;
                let resource: Resource = unsafe { std::mem::transmute(self.args[1] as u32) };
                let set_struct = self.args[2] as *const ();
                let get_struct = self.args[3] as *const ();
                let pid_of_self = pid == 0;
                match self.state {
                    Entering => {
                        if !set_struct.is_null() {
                            self.one_line.push("set ".white());
                            if pid_of_self {
                                self.one_line.push("the calling process's".yellow());
                            } else {
                                self.one_line.push("process ".yellow());
                                self.one_line.push(pid.to_string().yellow());
                                self.one_line.push("'s".white());
                            }
                            self.one_line.push(" ".white());
                            resource_matcher(resource, &mut self.one_line);
                            self.one_line
                                .push(" to the soft and hard limits provided".white());
                            if !get_struct.is_null() {
                                self.one_line.push(", and get the old limits".yellow());
                            }
                        } else if !get_struct.is_null() {
                            self.one_line
                                .push("get the soft and hard limits for ".white());
                            if pid_of_self {
                                self.one_line.push("the calling process's".yellow());
                            } else {
                                self.one_line.push("process ".yellow());
                                self.one_line.push(pid.to_string().yellow());
                                self.one_line.push("'s".white());
                            }
                            self.one_line.push(" ".white());
                            resource_matcher(resource, &mut self.one_line);
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            let rlims = SyscallObject::read_bytes_as_struct::<16, rlimit>(
                                self.args[3] as usize,
                                self.child as _,
                            )
                            .unwrap();
                            match resource {
                                Resource::RLIMIT_AS => {
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_CORE => {
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_CPU => {
                                    // maximum time in seconds to use in the CPU
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" seconds".green());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" seconds".green());
                                }
                                Resource::RLIMIT_DATA => {
                                    // maximum data segment size
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_FSIZE => {
                                    // maximum allowed size of files to creates
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_NOFILE => {
                                    // maximum allowed open file descriptors
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" fds".green());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" fds".green());
                                }
                                Resource::RLIMIT_STACK => {
                                    // maximum stack size
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_LOCKS => {
                                    // maximum number of flock() locks and fcntl() leases
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_MEMLOCK => {
                                    // maximum amount of memory that can be locked
                                    // affects mlock
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_MSGQUEUE => {
                                    // maximum number of bytes to use on message queues
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_NICE => {
                                    // maximum nice value
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_NPROC => {
                                    // maximum number of threads
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" threads".green());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" threads".green());
                                }
                                Resource::RLIMIT_RSS => {
                                    // maximum RSS memory
                                    // affects madvise
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line.push(
                                        Bytes::from(rlims.rlim_cur as usize).to_string().blue(),
                                    );
                                }
                                Resource::RLIMIT_RTPRIO => {
                                    // real-time priority
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                }
                                Resource::RLIMIT_RTTIME => {
                                    // Specifies a limit (in microseconds) on the amount of CPU time
                                    // that a process scheduled under a real-time scheduling policy
                                    // may consume without making a blocking system call.

                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" micro-seconds".green());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" micro-seconds".green());
                                }
                                Resource::RLIMIT_SIGPENDING => {
                                    // maximum number of queued pending signals
                                    self.one_line.push("soft limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" signals".green());
                                    self.one_line.push(", hard limit: ".green());
                                    self.one_line
                                        .push((rlims.rlim_cur as usize).to_string().blue());
                                    self.one_line.push(" signals".green());
                                }

                                _ => {}
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getrusage => {
                let resource: UsageWho = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get resource usage metrics for ".white());

                        match resource {
                            UsageWho::RUSAGE_SELF => {
                                self.one_line.push("the calling process (sum of resource usage for all threads in the process)".yellow());
                            }
                            UsageWho::RUSAGE_CHILDREN => {
                                self.one_line.push("all the terminated children and further descendants of the calling process".yellow());
                            }
                            UsageWho::RUSAGE_THREAD => {
                                self.one_line.push("the calling thread".yellow());
                            }
                            _ => todo!(),
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::sysinfo => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "get memory and swap usage metrics for the calling process".white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::times => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "get time metrics for the calling process and its children".white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::sched_setaffinity => {
                let thread_id = self.args[0];

                let cpus =
                    SyscallObject::read_affinity_from_child(self.args[2] as usize, self.child)
                        .unwrap();
                match self.state {
                    Entering => {
                        if !cpus.is_empty() {
                            self.one_line.push("only allow ".white());
                            if thread_id == 0 {
                                self.one_line.push("the calling thread".yellow());
                            } else {
                                self.one_line.push("thread ".yellow());
                                self.one_line.push(thread_id.to_string().yellow());
                            }
                            self.one_line.push(" to run on ".white());
                            let mut cpu_iter = cpus.into_iter();
                            self.one_line
                                .push(format!("[CPU {}]", cpu_iter.next().unwrap()).yellow());
                            for cpu in cpu_iter {
                                self.one_line.push(", ".yellow());
                                self.one_line.push(format!("[CPU {}]", cpu).yellow());
                            }
                        } else {
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("thread successfully locked".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::sched_getaffinity => {
                let thread_id = self.args[0];
                // let cpu_set: cpu_set_t = unsafe { std::mem::transmute(self.args_vec[2] as u32) };
                // let num_cpus = num_cpus::get();
                let mut set: cpu_set_t = unsafe { mem::zeroed() };

                let cpus =
                    SyscallObject::read_affinity_from_child(self.args[2] as usize, self.child)
                        .unwrap();
                match self.state {
                    Entering => {
                        self.one_line.push("find which CPUs ".white());
                        if thread_id == 0 {
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.one_line.push("thread ".yellow());
                            self.one_line.push(thread_id.to_string().yellow());
                        }
                        self.one_line.push(" is allowed to run on".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("CPUs allowed: ".green());
                            if cpus.is_empty() {
                                self.one_line.push("None".white());
                            } else {
                                let mut cpu_iter = cpus.into_iter();
                                self.one_line.push(
                                    format!("[CPU {}]", cpu_iter.next().unwrap()).bright_blue(),
                                );
                                for cpu in cpu_iter {
                                    self.one_line.push(", ".green());
                                    self.one_line.push(format!("[CPU {}]", cpu).bright_blue());
                                }
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::exit => {
                let status = self.args[0] as i32;
                match self.state {
                    Entering => {
                        self.one_line
                            .push("exit the calling process with status: ".white());
                        if status < 0 {
                            self.one_line.push(status.to_string().red());
                        } else {
                            self.one_line.push(status.to_string().yellow());
                        }
                        self.one_line.push(" |=> ".white());
                        self.one_line.push("process exited with status ".green());
                        self.one_line.push(status.to_string().blue());
                    }
                    _ => unreachable!(),
                }
            }
            Sysno::exit_group => {
                let status = self.args[0] as i32;
                match self.state {
                    Entering => {
                        self.one_line
                            .push("exit all threads in the group with status: ".white());
                        if status < 0 {
                            self.one_line.push(status.to_string().red());
                        } else {
                            self.one_line.push(status.to_string().yellow());
                        }
                        self.one_line.push(" |=> ".white());
                        self.one_line
                            .push("all threads in the group exited with status ".green());
                        self.one_line.push(status.to_string().blue());
                    }
                    _ => unreachable!(),
                }
            }
            Sysno::tgkill => {
                let thread_group = self.args[0];
                let thread = self.args[1];
                let signal_num = self.args[2];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.one_line.push("send ".white());
                            self.one_line.push(signal_as_string.yellow());
                            self.one_line.push(" to thread: ".white());
                            self.one_line.push(thread.to_string().yellow());
                            self.one_line.push(" in thread group: ".white());
                            self.one_line.push(thread_group.to_string().yellow());
                        }
                        None => {
                            self.one_line.push(
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
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::tkill => {
                let thread = self.args[0];
                let signal_num = self.args[1];
                match self.state {
                    Entering => match x86_signal_to_string(signal_num) {
                        Some(signal_as_string) => {
                            self.one_line.push("send ".white());
                            self.one_line.push(signal_as_string.yellow());
                            self.one_line.push(" to thread: ".white());
                            self.one_line.push(thread.to_string().yellow());
                        }
                        None => {
                            self.one_line.push(
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
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::rseq => {
                let rseq_flag = self.args[2];
                let registering = rseq_flag == 0;
                match self.state {
                    Entering => {
                        if registering {
                            self.one_line.push(
                        "register a per-thread shared data structure between kernel and user-space"
                            .white(),
                    );
                        } else {
                            self.one_line.push(
                        "unregister a previously registered per-thread shared data structure"
                            .white(),
                    );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            if registering {
                                self.one_line.push("successfully registered".green());
                            } else {
                                self.one_line.push("successfully unregistered".green());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::uname => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("retrieve general system information".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("information retrieved".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getuid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the real user ID of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let user_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the real user ID: ".green());
                            self.one_line.push(user_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::geteuid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the effective user ID of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let user_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the effective user ID: ".green());
                            self.one_line.push(user_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getgid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the real group ID of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let group_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the real group ID: ".green());
                            self.one_line.push(group_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getegid => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("get the effective group ID of the calling process".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let group_id = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the effective group ID: ".green());
                            self.one_line.push(group_id.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::shutdown => {
                let socket = self.pavfol(0);
                let shutdown_how_num = self.args[1] as u32;
                let shutdown_how: rustix::net::Shutdown =
                    unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        // SHUT_RD = 0
                        if (shutdown_how_num & 0) == 0 {
                            self.one_line
                                .push("stop incoming reception of data into the socket: ".white());
                            self.one_line.push(socket.yellow());
                        }
                        // SHUT_WR = 1
                        if (shutdown_how_num & 1) == 1 {
                            self.one_line.push(
                                "stop outgoing transmission of data from the socket: ".white(),
                            );
                            self.one_line.push(socket.yellow());
                        }
                        // SHUT_RDWR = 2
                        if (shutdown_how_num & 2) == 2 {
                            self.one_line.push(
                        "terminate incoming and outgoing data communication with the socket: "
                            .white(),
                    );
                            self.one_line.push(socket.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::futex => {
                let futex1_addr = self.pavfol(0);
                let futex2_addr = self.pavfol(4);
                let futex_flags_num = self.args[1] as i32;
                // let futex_flags: FutexFlags =
                //     unsafe { std::mem::transmute(self.arguments[1] as u32) };
                let futex_ops_num = self.args[1] as i32;
                // let futex_ops: FutexOperation =
                //     unsafe { std::mem::transmute(self.arguments[1] as u32) };
                let val = self.args[2];
                let val2 = self.args[3];
                let timeout = self.args[3] as *const ();
                // OPERATION
                match self.state {
                    Entering => {
                        if (futex_ops_num & FUTEX_WAIT) == FUTEX_WAIT {
                            self.one_line.push(
                                "if comparison succeeds block and wait for FUTEX_WAKE".yellow(),
                            );
                        } else if (futex_ops_num & FUTEX_WAKE) == FUTEX_WAKE {
                            self.one_line.push("wake a maximum of ".white());
                            self.one_line.push(val.to_string().yellow());
                            self.one_line
                                .push(" waiters waiting on the futex at ".white());
                            self.one_line.push(futex1_addr.yellow());
                        } else if (futex_ops_num & FUTEX_FD) == FUTEX_FD {
                            self.one_line
                                .push("create a file descriptor for the futex at ".white());
                            self.one_line.push(futex1_addr.yellow());
                            self.one_line
                                .push(" to use with asynchronous syscalls".white());
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE) == FUTEX_CMP_REQUEUE {
                            self.one_line
                                .push("if comparison succeeds wake a maximum of ".white());
                            self.one_line.push(val.to_string().yellow());
                            self.one_line
                                .push(" waiters waiting on the futex at ".white());
                            self.one_line.push(futex1_addr.yellow());
                            self.one_line.push(" and requeue a maximum of ".white());
                            self.one_line.push(val2.to_string().yellow());
                            self.one_line
                                .push(" from the remaining waiters to the futex at ".white());
                            self.one_line.push(futex2_addr.yellow());
                        } else if (futex_ops_num & FUTEX_REQUEUE) == FUTEX_REQUEUE {
                            self.one_line
                                .push("without comparing wake a maximum of ".white());
                            self.one_line.push(val.to_string().yellow());
                            self.one_line
                                .push(" waiters waiting on the futex at ".white());
                            self.one_line.push(futex1_addr.yellow());
                            self.one_line.push(" and requeue a maximum of ".white());
                            self.one_line.push(val2.to_string().yellow());
                            self.one_line
                                .push(" from the remaining waiters to the futex at ".white());
                            self.one_line.push(futex2_addr.yellow());
                        } else if (futex_ops_num & FUTEX_WAKE_OP) == FUTEX_WAKE_OP {
                            self.one_line
                                .push("operate on 2 futexes at the same time".white());
                        } else if (futex_ops_num & FUTEX_WAIT_BITSET) == FUTEX_WAIT_BITSET {
                            self.one_line.push("if comparison succeeds block and wait for FUTEX_WAKE and register a bitmask for selective waiting".white());
                        } else if (futex_ops_num & FUTEX_WAKE_BITSET) == FUTEX_WAKE_BITSET {
                            self.one_line.push("wake a maximum of ".white());
                            self.one_line.push(val.to_string().yellow());
                            self.one_line
                                .push(" waiters waiting on the futex at ".white());
                            self.one_line.push(futex1_addr.yellow());
                            self.one_line
                                .push(" from the provided waiters bitmask".yellow());
                        } else if (futex_ops_num & FUTEX_LOCK_PI) == FUTEX_LOCK_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_LOCK_PI2) == FUTEX_LOCK_PI2 {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_TRYLOCK_PI) == FUTEX_TRYLOCK_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_UNLOCK_PI) == FUTEX_UNLOCK_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE_PI) == FUTEX_CMP_REQUEUE_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.one_line
                                .push("priority-inheritance futex operation ".white());
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else {
                            self.one_line
                                .push("[intentrace: unknown flag]".bright_black());
                        }
                        // workarounds pending rustix deprecation of FutexOperation for Operations
                        // TODO! Priority-inheritance futexes
                        let mut directives = vec![];
                        if (futex_flags_num & FUTEX_PRIVATE_FLAG) == FUTEX_PRIVATE_FLAG {
                            directives.push(
                                "only use futex between threads of the same process".yellow(),
                            );
                        }
                        if (futex_flags_num & FUTEX_CLOCK_REALTIME) == FUTEX_CLOCK_REALTIME {
                            directives.push("measure timeout using the CLOCK_REALTIME".yellow());
                        } else {
                            directives.push("measure timeout using CLOCK_MONOTONIC".yellow());
                        }
                        if !directives.is_empty() {
                            self.one_line.push(" (".white());
                            let mut directives_iter = directives.into_iter().peekable();
                            if directives_iter.peek().is_some() {
                                self.one_line.push(directives_iter.next().unwrap());
                            }
                            for entry in directives_iter {
                                self.one_line.push(", ".white());
                                self.one_line.push(entry);
                            }
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::set_tid_address => {
                let thread_id =
                    SyscallObject::read_word(self.args[0] as usize, self.child).unwrap();
                match self.state {
                    Entering => {
                        self.one_line
                            .push("set `clear_child_tid` for the calling thread to ".white());
                        self.one_line.push(thread_id.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("thread id of the calling thread: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fork => {
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "create a new child process by duplicating the calling process".white(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let child_process = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("child process created: ".green());
                            self.one_line.push(child_process.yellow());
                            self.one_line.push(new_process());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::vfork => {
                match self.state {
                    Entering => {
                        self.one_line
                    .push("create a new child process with copy-on-write memory, and suspend execution until child terminates".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let child_process = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("child process created: ".green());
                            self.one_line.push(child_process.yellow());
                            self.one_line.push(new_process());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::eventfd => {
                match self.state {
                    Entering => {
                        self.one_line
                            .push("create a file to use for event notifications/waiting".white());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("created the eventfd: ".green());
                            self.one_line.push(file_descriptor.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::eventfd2 => {
                let flags: eventfd::EfdFlags = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.one_line
                            .push("create a file to use for event notifications/waiting".white());

                        let mut directives = vec![];
                        if flags.contains(eventfd::EfdFlags::EFD_CLOEXEC) {
                            directives.push("close the file with the next exec syscall".yellow());
                        }
                        if flags.contains(eventfd::EfdFlags::EFD_NONBLOCK) {
                            directives.push("use the file on non blocking mode".yellow());
                        }
                        if flags.contains(eventfd::EfdFlags::EFD_SEMAPHORE) {
                            directives
                                .push("utilize semaphore-like semantics when reading".yellow());
                        }
                        if !directives.is_empty() {
                            self.one_line.push(" (".white());
                            let mut directives_iter = directives.into_iter().peekable();
                            if directives_iter.peek().is_some() {
                                self.one_line.push(directives_iter.next().unwrap());
                            }
                            for entry in directives_iter {
                                self.one_line.push(", ".white());
                                self.one_line.push(entry);
                            }
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("created the eventfd: ".green());
                            self.one_line.push(file_descriptor.yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::waitid => {
                // let id_type: nix::sys::wait::Id =
                //     unsafe { std::mem::transmute(self.args_vec[0] as u32) };
                let id_type = self.args[0] as u32;
                let id = self.args[1];
                let options: WaitPidFlag = unsafe { std::mem::transmute(self.args[3] as u32) };
                let rusage = self.args[4] as *const ();
                match self.state {
                    Entering => {
                        if id_type == P_ALL {
                            self.one_line.push("wait until any child ".white());
                        } else if id_type == P_PGID {
                            if id == 0 {
                                self.one_line.push(
                                    "wait until any child in the current process group ".white(),
                                );
                            } else {
                                self.one_line
                                    .push("wait until any child process with PGID ".white());
                                self.one_line.push(id.to_string().yellow());
                            }
                        } else if id_type == P_PID {
                            self.one_line.push("wait until child process ".white());
                            self.one_line.push(id.to_string().yellow());
                        } else if id_type == P_PIDFD {
                            self.one_line.push("wait until child with PIDFD ".white());
                            self.one_line.push(id.to_string().yellow());
                        }
                        self.one_line.push(" ".white());
                        let mut options_ticked = vec![];

                        if options.contains(WaitPidFlag::WEXITED) {
                            options_ticked.push("exits".yellow());
                        }
                        if options.contains(WaitPidFlag::WCONTINUED) {
                            options_ticked.push("is resumed by SIGCONT".yellow());
                        }
                        if options.contains(WaitPidFlag::WSTOPPED) {
                            options_ticked.push("is stopped by a signal".yellow());
                        }
                        oring_handler(options_ticked, &mut self.one_line);

                        let mut options_directives = vec![];
                        if options.contains(WaitPidFlag::__WNOTHREAD) {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            options_directives.push("only wait on this thread's children".yellow());
                        }
                        if options.contains(WaitPidFlag::__WALL) {
                            /// Wait on all children, regardless of type
                            options_directives.push("wait on all children".yellow());
                        }
                        if options.contains(WaitPidFlag::__WCLONE) {
                            /// Wait for "clone" children only.
                            options_directives.push("wait for clone children only".yellow());
                        }
                        if options.contains(WaitPidFlag::WNOHANG) {
                            options_directives
                                .push("return immediately if no child exited".yellow());
                        }
                        if options.contains(WaitPidFlag::WNOWAIT) {
                            options_directives.push("leave the child in a waitable state".yellow());
                        }
                        if !rusage.is_null() {
                            options_directives.push("retrieve child resource usage data".yellow());
                        }
                        directives_handler(options_directives, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::wait4 => {
                let pid = self.args[0] as i32;
                let options: WaitPidFlag = unsafe { std::mem::transmute(self.args[2] as u32) };
                let mut options_ticked = vec![];
                let wstatus = self.args[1];
                match self.state {
                    Entering => {
                        if options.contains(WaitPidFlag::WEXITED) {
                            options_ticked.push("exits".yellow());
                        }
                        if options.contains(WaitPidFlag::WCONTINUED) {
                            options_ticked.push("is resumed by SIGCONT".yellow());
                        }
                        if options.contains(WaitPidFlag::WSTOPPED) {
                            options_ticked.push("is stopped by a signal".yellow());
                        }
                        if options_ticked.is_empty() {
                            if pid < -1 {
                                self.one_line.push(
                                    "wait for state change in any child with process group ID "
                                        .white(),
                                );
                                self.one_line.push(pid.to_string().blue());
                            } else if pid == -1 {
                                self.one_line
                                    .push("wait for state change in any child".white());
                            } else if pid == 0 {
                                self.one_line.push(
                                    "wait for state change in any child with a similar process group ID".white(),
                                );
                            } else {
                                self.one_line
                                    .push("wait for state change in child process ".white());
                                self.one_line.push(pid.to_string().blue());
                            }
                        } else {
                            if pid < -1 {
                                self.one_line
                                    .push("wait until any child with process group ID ".white());
                                self.one_line.push(pid.to_string().blue());
                            } else if pid == -1 {
                                self.one_line.push("wait until any child".white());
                            } else if pid == 0 {
                                self.one_line.push(
                                    "wait until any child with a similar process group ID".white(),
                                );
                            } else {
                                self.one_line.push("wait until child process ".white());
                                self.one_line.push(pid.to_string().blue());
                            }

                            self.one_line.push(" ".white());
                            oring_handler(options_ticked, &mut self.one_line);
                        }

                        let mut directives = vec![];
                        if options.contains(WaitPidFlag::__WNOTHREAD) {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            directives.push("only wait on this thread's children".yellow());
                        }
                        if options.contains(WaitPidFlag::__WALL) {
                            /// Wait on all children, regardless of type
                            directives.push("wait on all children".yellow());
                        }
                        if options.contains(WaitPidFlag::__WCLONE) {
                            /// Wait for "clone" children only.
                            directives.push("wait for clone children only".yellow());
                        }
                        directives_handler(directives, &mut self.one_line);

                        let mut retrieves = vec![];
                        if wstatus != 0 {
                            retrieves.push("exit status".yellow());
                        }
                        let rusage = self.args[3];
                        if rusage != 0 {
                            retrieves.push("resource usage metrics".yellow());
                        }

                        if !retrieves.is_empty() {
                            self.one_line.push(" (".white());
                            self.one_line.push("retrieve the child's ".white());
                            anding_handler(retrieves, &mut self.one_line);
                            self.one_line.push(")".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.one_line.push(" |=> ".white());
                            if wstatus == 0 {
                                self.one_line.push("Successful".green());
                            } else {
                                let wstatus_value = self.pavfol(1).parse::<u64>().unwrap();
                                // TODO! this is a workaround because nix's waitstatus resolver errors with EINVAL very often
                                if nix::libc::WIFEXITED(wstatus_value as i32) {
                                    let status = nix::libc::WEXITSTATUS(wstatus_value as i32);
                                    self.one_line
                                        .push("process exited with status code: ".green());
                                    self.one_line.push(status.to_string().blue());
                                } else if nix::libc::WIFSIGNALED(wstatus_value as i32) {
                                    let signal =
                                        x86_signal_to_string(wstatus_value as u64).unwrap();
                                    self.one_line.push("process was killed by ".green());
                                    self.one_line.push(signal.to_string().blue());
                                    if nix::libc::WCOREDUMP(wstatus_value as i32) {
                                        self.one_line.push(" ".white());
                                        self.one_line.push("(core dumped)".green());
                                    }
                                } else if nix::libc::WIFSTOPPED(wstatus_value as i32) {
                                    // TODO! Granularity needed here, this is currently a workaround
                                    self.one_line.push("process was stopped".green());
                                    // self.one_line.push("process was stopped by ".green());
                                    // self.one_line.push(signal.to_string().blue());
                                } else {
                                    self.one_line
                                        .push("process was resumed from a stop state by ".green());
                                    self.one_line.push("SIGCONT".blue());
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
                                //         self.one_line.push(status_code.to_string().blue());
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
                                //         self.one_line.push("process was killed by ".green());
                                //         self.one_line.push(signal.to_string().blue());
                                //         if core_dump {
                                //             self.one_line.push(" ".white());
                                //             self.one_line.push("(core dumped)".green());
                                //         }
                                //     }
                                //     /// The process is alive, but was stopped by the given signal. This
                                //     /// is only reported if `WaitPidFlag::WUNTRACED` was passed. This
                                //     /// case matches the C macro `WIFSTOPPED(status)`; the second field
                                //     /// is `WSTOPSIG(status)`.
                                //     nix::sys::wait::WaitStatus::Stopped(pid, signal) => {
                                //         self.one_line.push("process was stopped by ".green());
                                //         self.one_line.push(signal.to_string().blue());
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
                                //         self.one_line.push("process was stopped by a ".green());
                                //         self.one_line.push(signal.to_string().blue());
                                //         self.one_line.push(" signal due to ".white());
                                //         let ptrace: nix::sys::ptrace::Event =
                                //             unsafe { mem::transmute(ptrace_event) };
                                //         self.one_line.push(format!("{:?}", ptrace).green());
                                //     }
                                //     /// The traced process was stopped by execution of a system call,
                                //     /// and `PTRACE_O_TRACESYSGOOD` is in effect. See [`ptrace`(2)] for
                                //     /// more information.
                                //     ///
                                //     /// [`ptrace`(2)]: https://man7.org/linux/man-pages/man2/ptrace.2.html
                                //     nix::sys::wait::WaitStatus::PtraceSyscall(pid) => {
                                //         self.one_line.push("process stopped by ".green());
                                //         self.one_line.push("PTRACE_O_TRACESYSGOOD".blue());
                                //         self.one_line.push(" while executing a syscall".green());
                                //     }
                                //     /// The process was previously stopped but has resumed execution
                                //     /// after receiving a `SIGCONT` signal. This is only reported if
                                //     /// `WaitPidFlag::WCONTINUED` was passed. This case matches the C
                                //     /// macro `WIFCONTINUED(status)`.
                                //     nix::sys::wait::WaitStatus::Continued(pid) => {
                                //         self.one_line.push(
                                //             "process was resumed from a stop state by ".green(),
                                //         );
                                //         self.one_line.push("SIGCONT".blue());
                                //     }
                                //     /// There are currently no state changes to report in any awaited
                                //     /// child process. This is only returned if `WaitPidFlag::WNOHANG`
                                //     /// was used (otherwise `wait()` or `waitpid()` would block until
                                //     /// there was something to report).
                                //     nix::sys::wait::WaitStatus::StillAlive => {
                                //         self.one_line.push("no state changes to report".green());
                                //     }
                                // }
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::clone3 => {
                let size_of_cl_args = self.args[1];
                let cl_args = SyscallObject::read_bytes_as_struct::<88, clone3::CloneArgs>(
                    self.args[0] as usize,
                    self.child as _,
                )
                .unwrap();
                let clone_flags: clone3::Flags = unsafe { std::mem::transmute(cl_args.flags) };
                let clone_vm = clone_flags.contains(clone3::Flags::VM);

                match self.state {
                    Entering => {
                        if clone_vm {
                            self.one_line.push("spawn a new thread with a ".white());

                            self.one_line.push(
                                SyscallObject::style_bytes_page_aligned_ceil(cl_args.stack_size)
                                    .yellow(),
                            );
                            self.one_line.push(" stack starting at ".white());
                            self.one_line
                                .push(format!("0x{:x}", cl_args.stack).yellow());
                            // directives.push("run in the same memory space".yellow());
                        } else {
                            self.one_line.push("spawn a new child process".white());
                            // directives.push("copy the memory space".yellow());
                        }

                        // share with parent
                        //
                        //
                        //
                        //

                        let mut shares = vec![];
                        if clone_flags.contains(clone3::Flags::FILES) {
                            shares.push("the file descriptor table".yellow());
                        }

                        //  else {
                        //     shares.push("copy the file descriptor table".yellow());
                        // }

                        if clone_flags.contains(clone3::Flags::FS) {
                            shares.push("filesystem information".yellow());
                        }

                        // else {
                        //     shares.push("copy filesystem information".yellow());
                        // }

                        // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                        // }

                        if clone_flags.contains(clone3::Flags::IO) {
                            shares.push("I/O context".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::SIGHAND) {
                            shares.push("the table of signal handlers".yellow());
                        }
                        //  else {
                        //     shares.push("copy the signal handlers table".yellow());
                        // }
                        if clone_flags.contains(clone3::Flags::SYSVSEM) {
                            shares.push("sem-adj values".yellow());
                        }
                        //  else {
                        //     shares.push("don't share sem-adj values".yellow());
                        // }

                        if !shares.is_empty() {
                            self.one_line.push(" (".white());
                            self.one_line.push("share ".white());
                            anding_handler(shares, &mut self.one_line);
                            self.one_line.push(")".white());
                        }

                        // execute in new
                        //
                        //
                        //
                        //
                        let mut executes = vec![];

                        if clone_flags.contains(clone3::Flags::NEWCGROUP) {
                            executes.push("CGroup namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWIPC) {
                            executes.push("IPC namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWNET) {
                            executes.push("network namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWNS) {
                            executes.push("mount namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWPID) {
                            executes.push("PID namespace".yellow());
                        }
                        // if clone_flags.contains(clone3::Flags::NEWTIME) {
                        // }
                        if clone_flags.contains(clone3::Flags::NEWUSER) {
                            executes.push("user namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWUTS) {
                            executes.push("UTS namespace".yellow());
                        }

                        if !executes.is_empty() {
                            self.one_line.push(" (".white());
                            self.one_line.push("execute in a new ".white());
                            anding_handler(executes, &mut self.one_line);
                            self.one_line.push(")".white());
                        }

                        let mut directives = vec![];

                        if clone_flags.contains(clone3::Flags::PARENT) {
                            directives.push("inherit the same parent".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::PARENT_SETTID) {
                            directives.push("store the child TID in the parent's memory".yellow());
                        }
                        // It is currently not possible to use this flag together with CLONE_THREAD. This
                        // means that the process identified by the PID file descriptor will always be a
                        // thread group leader.
                        if clone_flags.contains(clone3::Flags::PIDFD) {
                            directives.push("return a PIDFD for the child".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::PTRACE) {
                            directives.push("allow ptracing if parent is ptraced".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::SETTLS) {
                            directives.push("modify the thread local storage descriptor".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::THREAD) {
                            directives.push("place in the same thread group".yellow());
                        } else {
                            directives.push("place in a new thread group".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::UNTRACED) {
                            directives.push("prevent forcing of CLONE_PTRACE".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::VFORK) {
                            directives.push("suspend parent execution as with vFork".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_CLEARTID) {
                            // directives.push("set the child's ".yellow());
                            // directives.push("clear_child_tid".blue());
                            // directives.push("to ".yellow());
                            // directives.push(cl_args.child_tid.to_string().blue());
                            directives.push(
                        "clear TID on the child's memory on exit and wake the associated futex"
                            .yellow(),
                    );
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_SETTID) {
                            directives.push("store the child TID in child's memory".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::CLEAR_SIGHAND) {
                            directives.push("default all inherited signal handlers".yellow());
                        }

                        directives_handler(directives, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("thread id of the child: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                            if clone_vm {
                                self.one_line.push(new_thread());
                            } else {
                                self.one_line.push(new_process());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::clone => {
                let clone_flags: clone3::Flags = unsafe { std::mem::transmute(self.args[0]) };
                let clone_vm = clone_flags.contains(clone3::Flags::VM);
                let stack = self.args[0];

                match self.state {
                    Entering => {
                        if clone_vm {
                            self.one_line
                                .push("spawn a new thread at stack address ".white());
                            self.one_line.push(format!("0x{:x}", stack).yellow());
                            // directives.push("run in the same memory space".yellow());
                        } else {
                            self.one_line.push("spawn a new child process".white());
                            // directives.push("copy the memory space".yellow());
                        }

                        // share with parent
                        //
                        //
                        //
                        //

                        let mut shares = vec![];
                        if clone_flags.contains(clone3::Flags::FILES) {
                            shares.push("the file descriptor table".yellow());
                        }

                        //  else {
                        //     shares.push("copy the file descriptor table".yellow());
                        // }

                        if clone_flags.contains(clone3::Flags::FS) {
                            shares.push("filesystem information".yellow());
                        }

                        // else {
                        //     shares.push("copy filesystem information".yellow());
                        // }

                        // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                        // }

                        if clone_flags.contains(clone3::Flags::IO) {
                            shares.push("I/O context".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::SIGHAND) {
                            shares.push("the table of signal handlers".yellow());
                        }
                        //  else {
                        //     shares.push("copy the signal handlers table".yellow());
                        // }
                        if clone_flags.contains(clone3::Flags::SYSVSEM) {
                            shares.push("sem-adj values".yellow());
                        }
                        //  else {
                        //     shares.push("don't share sem-adj values".yellow());
                        // }

                        if !shares.is_empty() {
                            self.one_line.push(" (".white());
                            self.one_line.push("share ".white());
                            anding_handler(shares, &mut self.one_line);
                            self.one_line.push(")".white());
                        }

                        // execute in new
                        //
                        //
                        //
                        //
                        let mut executes = vec![];

                        if clone_flags.contains(clone3::Flags::NEWCGROUP) {
                            executes.push("CGroup namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWIPC) {
                            executes.push("IPC namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWNET) {
                            executes.push("network namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWNS) {
                            executes.push("mount namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWPID) {
                            executes.push("PID namespace".yellow());
                        }
                        // if clone_flags.contains(clone3::Flags::NEWTIME) {
                        // }
                        if clone_flags.contains(clone3::Flags::NEWUSER) {
                            executes.push("user namespace".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::NEWUTS) {
                            executes.push("UTS namespace".yellow());
                        }

                        if !executes.is_empty() {
                            self.one_line.push(" (".white());
                            self.one_line.push("execute in a new ".white());
                            anding_handler(executes, &mut self.one_line);
                            self.one_line.push(")".white());
                        }

                        let mut directives = vec![];

                        if clone_flags.contains(clone3::Flags::PARENT) {
                            directives.push("inherit the same parent".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::PARENT_SETTID) {
                            directives.push("store the child TID in the parent's memory".yellow());
                        }
                        // It is currently not possible to use this flag together with CLONE_THREAD. This
                        // means that the process identified by the PID file descriptor will always be a
                        // thread group leader.
                        if clone_flags.contains(clone3::Flags::PIDFD) {
                            directives.push("return a PIDFD for the child".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::PTRACE) {
                            directives.push("allow ptracing if parent is ptraced".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::SETTLS) {
                            directives.push("modify the thread local storage descriptor".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::THREAD) {
                            directives.push("place in the same thread group".yellow());
                        } else {
                            directives.push("place in a new thread group".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::UNTRACED) {
                            directives.push("prevent forcing of CLONE_PTRACE".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::VFORK) {
                            directives.push("suspend parent execution as with vFork".yellow());
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
                            .yellow(),
                    );
                        }
                        if clone_flags.contains(clone3::Flags::CHILD_SETTID) {
                            directives.push("store the child TID in child's memory".yellow());
                        }
                        if clone_flags.contains(clone3::Flags::CLEAR_SIGHAND) {
                            directives.push("default all inherited signal handlers".yellow());
                        }

                        directives_handler(directives, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("thread id of the child: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                            // let a = -38;
                            // let b: u32 = unsafe { mem::transmute(a) };
                            // pp!("b: ", b);
                            // let a: i64 = -38;
                            // let b: u64 = unsafe { mem::transmute(a) };
                            // pp!("b: ", b);
                            // TODO! fix occasional error (syscall returns -38)
                            if clone_vm {
                                self.one_line.push(new_thread());
                            } else {
                                self.one_line.push(new_process());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::execve => {
                let program_name = self.pavfol(0);
                let arguments = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.one_line.push(
                            "replace the current program with the following program and arguments"
                                .white(),
                        );
                        self.one_line.push(program_name.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::nanosleep => {
                let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                    self.args[0] as usize,
                    self.child as _,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        self.one_line.push("suspend execution for ".white());
                        format_timespec_non_relative(
                            timespec.tv_sec,
                            timespec.tv_nsec,
                            &mut self.one_line,
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granularity
                            // remaining time due to interruption is stored inside
                            // the second syscall argument *rem (which is a timespec struct)
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::landlock_create_ruleset => {
                let attr = self.args[0] as *const ();
                let size = self.args[1];
                let flags_num = self.args[2];
                // LANDLOCK_CREATE_RULESET_VERSION = 1
                let retrieving_abi_version = (flags_num & 1) == 1 && attr.is_null() && size == 0;
                match self.state {
                    Entering => {
                        // let flags: LandlockCreateFlags =
                        //     unsafe { std::mem::transmute(self.arguments[2] as u32) };
                        if retrieving_abi_version {
                            self.one_line.push(
                                "retrieve the highest supported Landlock ABI version".white(),
                            );
                        } else {
                            self.one_line
                                .push("create a file descriptor for a landlock ruleset".white());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            if retrieving_abi_version {
                                let abi_version = self.result.0.unwrap() as f64;
                                self.one_line.push("got the ABI version: ".green());
                                self.one_line.push(abi_version.to_string().yellow());
                            } else {
                                let file_descriptor = eph_return.unwrap();
                                self.one_line
                                    .push("created the ruleset file descriptor: ".green());
                                self.one_line.push(file_descriptor.yellow());
                            }
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::landlock_add_rule => {
                let ruleset_fd = self.pavfol(0);
                let rule_type_num = self.args[1];
                let rule_type: LandlockRuleTypeFlags =
                    unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        // LANDLOCK_RULE_PATH_BENEATH = 1
                        if (rule_type_num & 1) == 1 {
                            self.one_line.push("add a new rule for ".white());
                            self.one_line
                                .push("file system path-beneath access rights".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("rule added".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::landlock_restrict_self => {
                let ruleset_fd = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("enforce the landlock ruleset inside: ".white());
                        self.one_line.push(ruleset_fd.white());
                        self.one_line.push(" on the calling process".white());
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("ruleset is now enforced".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::fallocate => {
                let file_descriptor = self.pavfol(0);
                let mode_num = self.args[1];
                let mode: nix::fcntl::FallocateFlags =
                    unsafe { std::mem::transmute(self.args[1] as u32) };
                let offset_num = self.args[2];
                let offset = self.pavfol(2);
                let bytes = self.pavfol(3);
                match self.state {
                    Entering => {
                        if mode_num == 0
                            || mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                            || mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_UNSHARE_RANGE)
                        {
                            self.one_line.push("allocate ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.one_line
                                    .push(" at the beginning of the file: ".white());
                            } else {
                                self.one_line.push(" starting at ".white());
                                self.one_line.push(offset.yellow());
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            }
                            self.one_line.push(file_descriptor.yellow());
                            if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                                && !mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE)
                            {
                                // this improves performance when appeding (makes appending later faster)
                                self.one_line.push(" (".white());
                                self.one_line.push("do not increase the file size if the range is larger, simply zeroize the out of bound bytes)".white());
                                self.one_line.push(")".white());
                            } else if mode
                                .contains(nix::fcntl::FallocateFlags::FALLOC_FL_UNSHARE_RANGE)
                            {
                                // this improves performance when appeding (makes appending later faster)
                                self.one_line.push(" (".white());

                                self.one_line.push(
                                    "modify any shared file data to private copy-on-write".yellow(),
                                );
                                self.one_line.push(")".white());
                            } else {
                                self.one_line.push(" (".white());
                                self.one_line.push(
                                    "increase file size and zeroize if the range is larger"
                                        .yellow(),
                                );
                                self.one_line.push(")".white());
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE)
                            && mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                        {
                            self.one_line.push("deallocate ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.one_line
                                    .push(" at the beginning of the file: ".white());
                            } else {
                                self.one_line.push(" starting at ".white());
                                self.one_line.push(offset.yellow());
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            }
                            self.one_line.push(file_descriptor.yellow());
                        } else if mode
                            .contains(nix::fcntl::FallocateFlags::FALLOC_FL_COLLAPSE_RANGE)
                        {
                            self.one_line.push("remove ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            } else {
                                self.one_line.push(" starting at ".white());
                                self.one_line.push(offset.yellow());
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            }
                            self.one_line.push(file_descriptor.yellow());
                            self.one_line.push(" without leaving a hole".yellow());
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.one_line.push("zeroize ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            } else {
                                self.one_line.push(" starting at ".white());
                                self.one_line.push(offset.yellow());
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            }
                            self.one_line.push(file_descriptor.yellow());
                            if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE) {
                                self.one_line.push(" (".white());
                                self.one_line.push(
                                    "do not increase the file size if the range is larger".yellow(),
                                );
                                self.one_line.push(")".white());
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.one_line.push("insert ".magenta());
                            self.one_line.push(bytes.yellow());
                            self.one_line.push(" of holes".magenta());

                            if offset_num == 0 {
                                self.one_line
                                    .push(" at the beginning of the file: ".white());
                            } else {
                                self.one_line.push(" starting at ".white());
                                self.one_line.push(offset.yellow());
                                self.one_line
                                    .push(" from the beginning of the file: ".white());
                            }
                            self.one_line.push(file_descriptor.yellow());
                            self.one_line.push(
                                " without overwriting existing data (displace data instead)"
                                    .white(),
                            );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("operation successful".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getpriority => {
                let which = self.args[0] as u32;
                let target = self.args[1];

                match self.state {
                    Entering => {
                        self.one_line.push("get the scheduling priority ".white());
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.one_line.push("of ".white());
                            if target == 0 {
                                self.one_line.push("the calling process".yellow());
                            } else {
                                self.one_line.push("process: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.one_line.push("of ".white());
                            if target == 0 {
                                self.one_line
                                    .push("the process group of calling process".yellow());
                            } else {
                                self.one_line.push("process group: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.one_line.push("for ".white());
                            if target == 0 {
                                self.one_line
                                    .push("the real user id of the calling process".yellow());
                            } else {
                                self.one_line.push("the real user id: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                        }
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("got the scheduling priority: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::setpriority => {
                let which = self.args[0] as u32;
                let target = self.args[1];
                let prio = self.pavfol(2);

                match self.state {
                    Entering => {
                        self.one_line.push("set the scheduling priority ".white());
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.one_line.push("of ".white());
                            if target == 0 {
                                self.one_line.push("the calling process".yellow());
                            } else {
                                self.one_line.push("process: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                            self.one_line.push(" to ".white());
                            self.one_line.push(prio.yellow());
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.one_line.push("of ".white());
                            if target == 0 {
                                self.one_line
                                    .push("the process group of calling process".yellow());
                            } else {
                                self.one_line.push("process group: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                            self.one_line.push(" to ".white());
                            self.one_line.push(prio.yellow());
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.one_line.push("for ".white());
                            if target == 0 {
                                self.one_line
                                    .push("the real user id of the calling process".yellow());
                            } else {
                                self.one_line.push("the real user id: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                                self.one_line.push(" to ".white());
                                self.one_line.push(prio.yellow());
                            }
                        }
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line
                                .push("successfully set the scheduling priority".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getdents => {
                let directory = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("retrieve the entries inside the directory ".white());
                        self.one_line.push(directory.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully retrieved".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
                        }
                    }
                }
            }
            Sysno::getdents64 => {
                let directory = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.one_line
                            .push("retrieve the entries inside the directory ".white());
                        self.one_line.push(directory.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.one_line.push(" |=> ".white());
                            self.one_line.push("successfully retrieved".green());
                        } else {
                            // TODO! granular
                            one_line_error(eph_return, &mut self.one_line, &self.errno);
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

pub fn one_line_error(
    eph_return: Result<String, ()>,
    one_line: &mut Vec<ColoredString>,
    self_errno: &Option<Errno>,
) {
    // TODO! Deprecate this logic for more granularity
    one_line.push(" |=> ".white());
    one_line.push(format!("{}", errno_to_string(self_errno.unwrap())).red());
}

pub fn mode_matcher(mode: rustix::fs::Mode, one_line: &mut Vec<ColoredString>) {
    // USER
    let mut perms = vec![];
    if mode.contains(rustix::fs::Mode::RUSR) {
        perms.push("read".yellow());
    }
    if mode.contains(rustix::fs::Mode::WUSR) {
        perms.push("write".yellow());
    }
    if mode.contains(rustix::fs::Mode::XUSR) {
        perms.push("execute".yellow());
    }
    if !perms.is_empty() {
        one_line.push(" allowing the user to ".white());
        let mut perms_iter = perms.into_iter().peekable();
        if perms_iter.peek().is_some() {
            one_line.push(perms_iter.next().unwrap());
        }
        for entry in perms_iter {
            one_line.push(", ".white());
            one_line.push(entry);
        }
        one_line.push(", ".white());
    }

    // GROUP
    let mut perms = vec![];
    if mode.contains(rustix::fs::Mode::RGRP) {
        perms.push("read".yellow());
    }
    if mode.contains(rustix::fs::Mode::WGRP) {
        perms.push("write".yellow());
    }
    if mode.contains(rustix::fs::Mode::XGRP) {
        perms.push("execute".yellow());
    }
    if !perms.is_empty() {
        one_line.push(" allowing the group to ".white());
        let mut perms_iter = perms.into_iter().peekable();
        if perms_iter.peek().is_some() {
            one_line.push(perms_iter.next().unwrap());
        }
        for entry in perms_iter {
            one_line.push(", ".white());
            one_line.push(entry);
        }
        one_line.push(", ".white());
    }
    // OTHER
    let mut perms = vec![];
    if mode.contains(rustix::fs::Mode::ROTH) {
        perms.push("read".yellow());
    }
    if mode.contains(rustix::fs::Mode::WOTH) {
        perms.push("write".yellow());
    }
    if mode.contains(rustix::fs::Mode::XOTH) {
        perms.push("execute".yellow());
    }
    if !perms.is_empty() {
        one_line.push(" allowing others to ".white());
        let mut perms_iter = perms.into_iter().peekable();
        if perms_iter.peek().is_some() {
            one_line.push(perms_iter.next().unwrap());
        }
        for entry in perms_iter {
            one_line.push(", ".white());
            one_line.push(entry);
        }
        one_line.push(", ".white());
    }

    // SETS
    let mut sets = vec![];
    if mode.contains(rustix::fs::Mode::SUID) {
        sets.push("set-uid".yellow());
    } else if mode.contains(rustix::fs::Mode::SGID) {
        sets.push("set-gid".yellow());
    } else if mode.contains(rustix::fs::Mode::SVTX) {
        sets.push("sticky-bit".yellow());
    }
    if !sets.is_empty() {
        one_line.push(" and set ".white());
        let mut sets_iter = sets.into_iter().peekable();
        if sets_iter.peek().is_some() {
            one_line.push(sets_iter.next().unwrap());
        }
        for entry in sets_iter {
            one_line.push(", ".white());
            one_line.push(entry);
        }
    }
}

pub fn resource_matcher(resource: Resource, one_line: &mut Vec<ColoredString>) {
    match resource {
        Resource::RLIMIT_AS => {
            one_line.push("maximum virtual memory size".yellow());
        }
        Resource::RLIMIT_CORE => {
            one_line.push("maximum core size that may be dumped".yellow());
        }
        Resource::RLIMIT_CPU => {
            one_line.push("maximum time in seconds to use in the CPU".yellow());
        }
        Resource::RLIMIT_DATA => {
            one_line.push("maximum data segment size".yellow());
        }
        Resource::RLIMIT_FSIZE => {
            one_line.push("maximum allowed size of files to creates".yellow());
        }
        Resource::RLIMIT_NOFILE => {
            one_line.push("maximum allowed open file descriptors".yellow());
        }
        Resource::RLIMIT_STACK => {
            one_line.push("maximum stack size".yellow());
        }
        Resource::RLIMIT_LOCKS => {
            one_line.push("maximum number of flock() locks and fcntl() leases".yellow());
        }
        Resource::RLIMIT_MEMLOCK => {
            // affects mlock
            one_line.push("maximum amount of memory that can be locked".yellow());
        }
        Resource::RLIMIT_MSGQUEUE => {
            one_line.push("maximum number of bytes to use on message queues".yellow());
        }
        Resource::RLIMIT_NICE => {
            one_line.push("maximum nice value".yellow());
        }
        Resource::RLIMIT_NPROC => {
            one_line.push("maximum number of threads".yellow());
        }
        Resource::RLIMIT_RSS => {
            // affects madvise
            one_line.push("maximum RSS memory".yellow());
        }
        Resource::RLIMIT_RTPRIO => {
            one_line.push("maximum real-time priority".yellow());
        }
        Resource::RLIMIT_RTTIME => {
            one_line
                .push("maximum time in micro-seconds to use in the CPU without syscalls".yellow());
        }
        Resource::RLIMIT_SIGPENDING => {
            one_line.push("maximum number of queued pending signals".yellow());
        }
        _ => {}
    }
}

pub fn format_timespec(seconds: i64, nanoseconds: i64, one_line: &mut Vec<ColoredString>) {
    if seconds == 0 {
        if nanoseconds == 0 {
            one_line.push("immediately".yellow());
        } else {
            one_line.push("after ".yellow());
            one_line.push(nanoseconds.to_string().yellow());
            one_line.push(" nanoseconds".yellow());
        }
    } else {
        one_line.push("after ".yellow());
        one_line.push(seconds.to_string().yellow());
        one_line.push(" seconds".yellow());
        if nanoseconds != 0 {
            one_line.push(", ".white());
            one_line.push(nanoseconds.to_string().yellow());
            one_line.push(" nanoseconds".yellow());
        }
    }
}
pub fn format_timespec_non_relative(
    seconds: i64,
    nanoseconds: i64,
    one_line: &mut Vec<ColoredString>,
) {
    if seconds == 0 {
        if nanoseconds == 0 {
            one_line.push("0".blue());
            one_line.push(" nano-seconds".yellow());
        } else {
            one_line.push(nanoseconds.to_string().blue());
            one_line.push(" nano-seconds".yellow());
        }
    } else {
        one_line.push(seconds.to_string().blue());
        one_line.push(" seconds".yellow());
        if nanoseconds != 0 {
            one_line.push(" and ".white());
            one_line.push(nanoseconds.to_string().yellow());
            one_line.push(" nanoseconds".yellow());
        }
    }
}

pub fn format_timeval(seconds: i64, microseconds: i64, one_line: &mut Vec<ColoredString>) {
    if seconds == 0 {
        if microseconds == 0 {
            one_line.push("immediately".yellow());
        } else {
            one_line.push("after ".yellow());
            one_line.push(microseconds.to_string().yellow());
            one_line.push(" microseconds".yellow());
        }
    } else {
        one_line.push("after ".yellow());
        one_line.push(seconds.to_string().yellow());
        one_line.push(" seconds".yellow());
        if microseconds != 0 {
            one_line.push(", ".white());
            one_line.push(microseconds.to_string().yellow());
            one_line.push(" microseconds".yellow());
        }
    }
}

pub fn oring_handler(vector: Vec<ColoredString>, one_line: &mut Vec<ColoredString>) {
    if !vector.is_empty() {
        let mut vector_iter = vector.into_iter().peekable();
        if vector_iter.peek().is_some() {
            one_line.push(vector_iter.next().unwrap());
        }
        let mut ender = vec![];
        if vector_iter.peek().is_some() {
            ender.push(", or ".white());
            ender.push(vector_iter.next().unwrap());
        }
        for entry in vector_iter {
            one_line.push(", or ".white());
            one_line.push(entry);
        }
        one_line.extend(ender);
    }
}

pub fn anding_handler(vector: Vec<ColoredString>, one_line: &mut Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    if vector_iter.peek().is_some() {
        one_line.push(vector_iter.next().unwrap());
    }
    let mut ender = vec![];
    if vector_iter.peek().is_some() {
        ender.push(", and ".white());
        ender.push(vector_iter.next().unwrap());
    }
    // else {
    //     ender.push(" ".white());
    // }
    for entry in vector_iter {
        one_line.push(", ".white());
        one_line.push(entry);
    }
    one_line.extend(ender);
}

pub fn directives_handler(vector: Vec<ColoredString>, one_line: &mut Vec<ColoredString>) {
    if !vector.is_empty() {
        one_line.push(" (".white());
        let mut vector_iter = vector.into_iter().peekable();
        if vector_iter.peek().is_some() {
            one_line.push(vector_iter.next().unwrap());
        }
        for entry in vector_iter {
            one_line.push(", ".white());
            one_line.push(entry);
        }
        one_line.push(")".white());
    }
}

pub fn vanilla_commas_handler(vector: Vec<ColoredString>, one_line: &mut Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    if vector_iter.peek().is_some() {
        one_line.push(vector_iter.next().unwrap());
    }
    for entry in vector_iter {
        one_line.push(", ".white());
        one_line.push(entry);
    }
}

pub fn new_process() -> ColoredString {
    "

  ╭──────────────╮
  │              │
  │ NEW PROCESS  │   		
  │              │
  ╰──────────────╯	
"
    .red()
}

pub fn new_thread() -> ColoredString {
    "

  ╭──────────────╮
  │              │
  │  NEW THREAD  │   		
  │              │
  ╰──────────────╯	
"
    .green()
}

pub fn handle_path_file(filename: String, one_line: &mut Vec<ColoredString>) {
    let mut pathname = String::new();

    let mut file_start = 0;
    for (index, chara) in filename.chars().rev().enumerate() {
        if chara == '/' && index != 0 {
            file_start = filename.len() - index;
            break;
        }
    }
    one_line.push(filename[0..file_start].yellow());
    one_line.push(filename[file_start..].blue());
}
