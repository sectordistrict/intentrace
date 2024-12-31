use std::{
    env::current_dir,
    mem,
    os::fd::RawFd,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use crate::{
    syscall_object::SyscallObject,
    types::{Bytes, BytesPagesRelevant, LandlockRuleTypeFlags},
    utilities::{
        colorize_general, errno_to_string, get_child_memory_break,
        get_mem_difference_from_previous, where_in_childs_memory, x86_signal_to_string,
        FOLLOW_FORKS,
    },
};
use colored::{Color, ColoredString, Colorize};
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FallocateFlags},
    libc::{
        cpu_set_t, iovec, msghdr, pid_t, rlimit, timespec, timeval, AT_EMPTY_PATH, AT_FDCWD,
        AT_NO_AUTOMOUNT, AT_REMOVEDIR, AT_STATX_DONT_SYNC, AT_STATX_FORCE_SYNC,
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
        RENAME_WHITEOUT,
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
    pub(crate) fn one_line_error(&mut self) {
        // TODO! Deprecate this logic for more granularity
        self.general_text(" |=> ");
        self.one_line
            .push(format!("{}", errno_to_string(self.errno.unwrap())).red());
    }

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
            if FOLLOW_FORKS.load(Ordering::SeqCst) {
                self.one_line.extend(vec![
                    "\n".white(),
                    self.process_pid.to_string().bright_blue(),
                    " ".dimmed(),
                    SyscallObject::colorize_syscall_name(&self.sysno, &self.category),
                    " - ".dimmed(),
                ]);
            } else {
                if self.get_syscall_return().is_ok() {
                    self.one_line.extend(vec![
                        "\n".white(),
                        self.process_pid.to_string().blue(),
                        // self.child.to_string().on_black(),
                        " ".dimmed(),
                        SyscallObject::colorize_syscall_name(&self.sysno, &self.category),
                        " - ".dimmed(),
                    ]);
                } else {
                    self.one_line.extend(vec![
                        "\n".white(),
                        self.process_pid.to_string().red(),
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
                            self.general_text("get the current program break");
                        } else {
                            self.general_text("change program break to ");
                            self.one_line.push(syscall_brk.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
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
                                    self.general_text("no allocation or deallocation occured");
                                } else if mem_difference > 0 {
                                    self.general_text("allocated ");
                                    self.one_line
                                        .push(mem_difference_bytes.to_string().yellow());
                                } else {
                                    self.general_text("deallocated ");
                                    self.one_line
                                        .push(mem_difference_bytes.to_string().yellow());
                                }
                                self.one_line.push(", new program break: ".green());
                                self.one_line.push(eph_return.unwrap().yellow());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::close => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("close the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("file closed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("open the file ");
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully opened file".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::openat => {
                let dirfd = self.args[0] as i32;
                let filename = self.pavfol(1);
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
                            self.general_text("create an unnamed temporary file in the path: ");
                        } else {
                            self.general_text("open the file: ");
                        }
                        self.possible_dirfd_file(dirfd, filename);

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
                        self.directives_handler(directives);

                        if (flags_num & O_TRUNC) > 0 {
                            self.one_line
                                .push("truncate the file's length to zero".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully opened file".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::stat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fstat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::lstat => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        handle_path_file(filename, &mut self.one_line);
                        self.general_text(" and do not recurse symbolic links");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::statfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get stats for the filesystem mounted in: ");
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fstatfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get stats for the filesystem that contains the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::newfstatat => {
                let dirfd: i32 = self.args[0] as i32;
                let filename: String = self.pavfol(1);
                let flags: rustix::fs::AtFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");
                        self.possible_dirfd_file(dirfd, filename);

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
                            self.general_text(" (");
                            let mut flag_directive_iter = flag_directive.into_iter().peekable();
                            if flag_directive_iter.peek().is_some() {
                                self.one_line.push(flag_directive_iter.next().unwrap());
                            }
                            for entry in flag_directive_iter {
                                self.general_text(", ");
                                self.one_line.push(entry);
                            }
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("stats retrieved successfully".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::statx => {
                let dirfd = self.args[0] as i32;
                let pathname: String = self.pavfol(1);
                // let flags: rustix::fs::AtFlags = unsafe { std::mem::transmute(self.args[2] as i32) };
                let flags_num = self.args[2] as i32;
                match self.state {
                    Entering => {
                        self.general_text("get the stats of the file: ");

                        // statx logic for when the pathname is empty
                        if pathname.is_empty() && (flags_num & AT_EMPTY_PATH) > 0 {
                            // if pathname is empty and AT_EMPTY_PATH is given, dirfd is used
                            let dirfd_parsed = self.pavfol(0);
                            self.one_line.push(dirfd_parsed.yellow());
                        } else {
                            handle_path_file(pathname, &mut self.one_line);
                        }

                        let mut flag_directive = vec![];
                        if (flags_num & AT_NO_AUTOMOUNT) > 0 {
                            flag_directive.push("don't automount the basename of the path if its an automount directory".yellow());
                        }
                        if (flags_num & AT_SYMLINK_NOFOLLOW) > 0 {
                            flag_directive.push(
                                "if the path is a symbolic link, get its stats, do not recurse it"
                                    .yellow(),
                            );
                        }
                        if (flags_num & AT_STATX_SYNC_AS_STAT) > 0 {
                            flag_directive.push("behave similar to the `stat` syscall".yellow());
                        }
                        if (flags_num & AT_STATX_FORCE_SYNC) > 0 {
                            flag_directive.push(
                                "force synchronization / guarantee up to date information".yellow(),
                            );
                        }
                        if (flags_num & AT_STATX_DONT_SYNC) > 0 {
                            flag_directive.push("don't force synchronization / retrieve whatever information is cached".yellow());
                        }
                        // if flags.contains(rustix::fs::AtFlags::EACCESS) {
                        //     flag_directive.push("check using effective user & group ids".yellow());
                        // }
                        // if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                        //     flag_directive.push("recurse symbolic links if found".yellow());
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
                            self.one_line.push("stats retrieved successfully".green());
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

                            self.general_text("change the owner of ");
                            handle_path_file(filename, &mut self.one_line);
                            self.general_text(" to ");
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                handle_path_file(filename, &mut self.one_line);
                                self.general_text("to ");
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("ownership changed".green());
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

                            self.general_text("change the owner of the file: ");
                            self.one_line.push(filename.yellow());
                            self.general_text(" to ");
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                self.one_line.push(filename.yellow());

                                self.general_text("to ");
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("ownership changed".green());
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

                            self.general_text("change the owner of ");
                            handle_path_file(filename, &mut self.one_line);
                            self.general_text(" to ");
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                handle_path_file(filename, &mut self.one_line);
                                self.general_text("to ");
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("ownership changed".green());
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
                let dirfd = self.args[0] as i32;
                let filename = self.pavfol(1);
                let owner_given = self.args[2] as i32;
                let group_given = self.args[3] as i32;
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
                            self.one_line.push(owner.green());
                            if group_given != -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text(", and its group to ");
                                self.one_line.push(group.green());
                            }
                        } else {
                            if group_given == -1 {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                self.general_text("change the owner of the file: ");
                                handle_path_file(filename, &mut self.one_line);
                                self.general_text("to ");
                                self.one_line.push(group.green());
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("ownership changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("provide default treatment for ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_RANDOM) == MADV_RANDOM {
                            self.general_text("expect ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be referenced in random order");
                        } else if (advice & MADV_SEQUENTIAL) == MADV_SEQUENTIAL {
                            self.general_text("expect ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be referenced in sequential order");
                        } else if (advice & MADV_WILLNEED) == MADV_WILLNEED {
                            self.general_text("expect ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be accessed in the future");
                        } else if (advice & MADV_DONTNEED) == MADV_DONTNEED {
                            self.one_line.push("do not expect the".yellow());
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be accessed in the future");
                        } else if (advice & MADV_REMOVE) == MADV_REMOVE {
                            // equivalent to punching a hole in the corresponding range
                            self.general_text("free");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_DONTFORK) == MADV_DONTFORK {
                            self.general_text("do not allow ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be available to children from ");
                            self.one_line.push("fork()".blue());
                        } else if (advice & MADV_DOFORK) == MADV_DOFORK {
                            self.general_text("allow ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to be available to children from ");
                            self.one_line.push("fork()".blue());
                            self.general_text(" ");
                            self.one_line.push("(Undo MADV_DONTFORK)".yellow());
                        } else if (advice & MADV_HWPOISON) == MADV_HWPOISON {
                            // treat subsequent references to those pages like a hardware memory corruption
                            self.general_text("poison ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_MERGEABLE) == MADV_MERGEABLE {
                            // KSM merges only private anonymous pages
                            self.general_text("enable KSM (Kernel Samepage Merging) for ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_UNMERGEABLE) == MADV_UNMERGEABLE {
                            self.general_text(
                                "unmerge all previous KSM merges from MADV_MERGEABLE in ",
                            );
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_HUGEPAGE) == MADV_HUGEPAGE {
                            self.one_line.push("enable".yellow());
                            self.general_text(" transparent huge pages (THP) on ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_NOHUGEPAGE) == MADV_NOHUGEPAGE {
                            self.one_line.push("disable".yellow());
                            self.general_text(" transparent huge pages (THP) on ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_COLLAPSE) == MADV_COLLAPSE {
                            // TODO! citation needed
                            self.general_text("perform a synchronous collapse of ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" that's mapped into transparent huge pages (THP)");
                        } else if (advice & MADV_DONTDUMP) == MADV_DONTDUMP {
                            self.general_text("exclude ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" from core dumps");
                        } else if (advice & MADV_DODUMP) == MADV_DODUMP {
                            self.general_text("include ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" in core dumps ");
                            self.one_line.push("(Undo MADV_DONTDUMP)".yellow());
                        } else if (advice & MADV_FREE) == MADV_FREE {
                            self.general_text("the range of ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" is no longer required and is ok to free");
                        } else if (advice & MADV_WIPEONFORK) == MADV_WIPEONFORK {
                            self.general_text("zero-fill the range of ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to any child from ");
                            self.one_line.push("fork()".blue());
                        } else if (advice & MADV_KEEPONFORK) == MADV_KEEPONFORK {
                            self.general_text("keep the range of ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" to any child from ");
                            self.one_line.push("fork()".blue());
                            self.general_text(" ");
                            self.one_line.push("(Undo MADV_WIPEONFORK)".yellow());
                        } else if (advice & MADV_COLD) == MADV_COLD {
                            // This makes the pages a more probable reclaim target during memory pressure
                            self.general_text("deactivate ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text("  (make more probable to reclaim)");
                        } else if (advice & MADV_PAGEOUT) == MADV_PAGEOUT {
                            // This is done to free up memory occupied by these pages.
                            // If a page is anonymous, it will be swapped out.
                            // If a page  is  file-backed and dirty, it will be written back to the backing storage
                            self.general_text("page out ");
                            // "page out" is more intuitive, "reclaim"sleading
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                        } else if (advice & MADV_POPULATE_READ) == MADV_POPULATE_READ {
                            self.general_text("prefault ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" while avoiding memory access ");
                            self.one_line.push("(simulate reading)".yellow());
                        } else if (advice & MADV_POPULATE_WRITE) == MADV_POPULATE_WRITE {
                            self.general_text("prefault ");
                            self.one_line.push(len.yellow());
                            self.general_text(" of memory starting from ");
                            self.one_line.push(addr.yellow());
                            self.general_text(" while avoiding memory access ");
                            self.one_line.push("(simulate writing)".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("memory advice registered".green());
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
                            self.general_text("map ");
                        } else {
                            self.general_text("allocate ");
                        }
                        self.one_line.push(bytes.yellow());
                        // BACKED BY FILE
                        //
                        //
                        //
                        if !anonymous {
                            self.general_text(" of the file: ");
                            let filename = self.pavfol(4);
                            self.one_line.push(filename.yellow());
                            if offset_num > 0 {
                                self.general_text(" at an offset of ");
                                self.one_line.push(offset.to_string().yellow());
                            }
                        }

                        self.general_text(" as ");
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
                            self.general_text(" using ");
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
                            self.general_text(" ");
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
                            self.one_line
                                .push("an appropiate kernel chosen address".yellow());
                        } else if (mapping_flags_num & MAP_FIXED) == MAP_FIXED {
                            self.general_text(" starting ");
                            self.one_line
                                .extend(["exactly at ".yellow(), address.yellow()]);
                        } else if (mapping_flags_num & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE {
                            self.general_text(" starting ");
                            self.one_line.extend([
                                "exactly at ".yellow(),
                                address.yellow(),
                                " and fail if a mapping already exists ".yellow(),
                            ]);
                        } else {
                            self.general_text(" starting ");
                            self.one_line.extend(["around ".yellow(), address.yellow()]);
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
                                self.general_text(" and allow ");
                                self.vanilla_commas_handler(flags);
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
                            self.general_text(" |=> ");
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::munmap => {
                let address = self.pavfol(0);
                let bytes = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("unmap ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" from memory starting at ");
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully unmapped region".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("flush all changes made on ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" of memory starting from ");
                        self.one_line.push(address.yellow());
                        self.general_text(" back to the filesystem");
                        if msync_flags.contains(MsFlags::MS_ASYNC) {
                            self.general_text(" (");
                            self.one_line
                                .push("schedule the update, but return immediately".yellow());
                            self.general_text(")");
                        } else if msync_flags.contains(MsFlags::MS_INVALIDATE) {
                            self.general_text(" (");
                            self.one_line.push("block until completion".yellow());
                            self.general_text(")");
                        } else if msync_flags.contains(MsFlags::MS_SYNC) {
                            // this is used to propagate
                            self.general_text(" (");
                            self.one_line.push(
                                "invalidate other mappings of the file to propagate these changes"
                                    .yellow(),
                            );
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("prevent ");
                            self.one_line.push("all access".yellow());
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
                        self.general_text(" on ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" of memory ");
                        // ADDRESS
                        //
                        //
                        //
                        self.general_text("starting from ");
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("memory protection modified".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                    self.general_text("move the file pointer of the file: ");
                                    self.one_line.push(filename.yellow());
                                    self.general_text(" to ");
                                    self.one_line.push("the beginning of the file".yellow());
                                } else {
                                    self.one_line.push(offset.yellow());
                                    self.one_line
                                        .push("from the beginning of the file".yellow());
                                }
                            }
                            Whence::SeekCur => {
                                self.general_text("move the file pointer of the file: ");
                                self.one_line.push(filename.yellow());
                                self.general_text(" ");
                                if offset_num == 0 {
                                    // self.general_text.push("[intentrace: redundant syscall (won't do anything)]");

                                    self.general_text("to ");
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
                                self.general_text("move the file pointer of the file: ");
                                self.one_line.push(filename.yellow());
                                self.general_text(" ");

                                if offset_num == 0 {
                                    self.general_text("to ");
                                    self.one_line.push("the end of the file".yellow());
                                } else if offset_num > 0 {
                                    self.one_line.push(offset.yellow());
                                    self.general_text(" after ");
                                    self.one_line.push("the end of the file".yellow());
                                } else {
                                    self.one_line.push((&offset[1..]).yellow());
                                    self.general_text(" before ");
                                    self.one_line.push("the end of the file".yellow());
                                }
                            }
                            Whence::SeekData => {
                                self.general_text("move the file pointer of the file: ");
                                self.one_line.push(filename.yellow());
                                self.general_text(" to ");
                                self.one_line.push("the nearest data block".yellow());
                                self.general_text(" you find ");
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
                                self.general_text("move the file pointer of the file: ");
                                self.one_line.push(filename.yellow());
                                self.general_text(" to ");
                                self.one_line.push("the nearest data hole".yellow());
                                self.general_text(" you find ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("new offset location: ".green());
                            self.one_line.push(eph_return.unwrap().green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("prevent swapping of memory on ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" starting from: ");
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("prevent swapping of memory on ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" starting from: ");
                        self.one_line.push(address.yellow());

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
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("allow swapping of memory on ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" starting from: ");
                        self.one_line.push(address.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("memory range is now swappable".green());
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
                            self.one_line.push("memory range is now swappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("expand the memory region of ");
                            self.one_line.push(old_len.yellow());
                            self.one_line.push(" starting from: ".yellow());
                            self.one_line.push(old_address.yellow());
                        } else if new_len_num < old_len_num {
                            self.general_text("shrink the memory region of ");
                            self.one_line.push(old_len.yellow());
                            self.one_line.push(" starting from: ".yellow());
                            self.one_line.push(old_address.yellow());
                        } else if new_len_num == old_len_num {
                            if old_address_num == new_address_num {
                                self.one_line
                                    .push("[intentrace Notice: syscall no-op]".blink());
                            } else {
                                self.general_text("move the memory region of ");
                                self.one_line.push(old_len.yellow());
                                self.one_line.push(" starting from: ".yellow());
                                self.one_line.push(old_address.yellow());
                            }
                        }
                        if flags.contains(MRemapFlags::MREMAP_FIXED)
                            && flags.contains(MRemapFlags::MREMAP_MAYMOVE)
                        {
                            self.general_text(" (");
                            self.one_line.push(                        "move the mapping to a different address if you can not expand at current address"
                            .yellow(),
                    );
                            self.general_text(")");
                        } else if flags.contains(MRemapFlags::MREMAP_MAYMOVE) {
                            self.general_text(" (");
                            self.one_line.push(                        "move the mapping to a different address if you can not expand at current address"
                            .yellow(),
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
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("populate a vector of bytes representing ");
                        self.one_line.push(length.yellow());
                        self.one_line
                            .push(" of the process's memory starting from: ".yellow());
                        self.one_line.push(address.yellow());
                        self.general_text(
                            " indicating resident and non-resident pages in each byte",
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("prevent swapping of ");

                        match (
                            (flags_num & MCL_CURRENT) == MCL_CURRENT,
                            (flags_num & MCL_FUTURE) == MCL_FUTURE,
                        ) {
                            (true, true) => {
                                self.one_line
                                    .push("all current and future mapped pages".yellow());
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.general_text(" (only lock resident-pages for current and future mappings, lock non-resident pages whenever they're faulted)");
                                }
                            }
                            (true, false) => {
                                self.one_line.push("all currently mapped pages".yellow());
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    self.general_text(" (only lock currently resident-pages, only lock non-resident pages once they're faulted)");
                                }
                            }
                            (false, true) => {
                                self.one_line.push("all future mapped pages ".yellow());
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
                            self.one_line
                                .push("memory range is now unswappable".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("read ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" from the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::write => {
                let bytes_to_write = self.args[2];
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("write ");
                        if bytes_to_write < 20 {
                            self.one_line.push(format!("{:?}", self.pavfol(1)).yellow());
                        } else {
                            self.one_line.push(self.pavfol(2).yellow());
                        }
                        self.general_text(" into the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
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
                            self.one_line_error();
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
                        self.general_text("read ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" from the file: ");
                        self.one_line.push(filename.yellow());
                        self.general_text(" at an offset of ");
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num: u64 = self.result.0.unwrap();
                            self.general_text(" |=> ");
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
                            self.one_line_error();
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
                        self.general_text("write ");
                        if bytes_to_write < 20 {
                            self.one_line.push(format!("{:?}", self.pavfol(1)).yellow());
                        } else {
                            self.one_line.push(self.pavfol(2).yellow());
                        }
                        self.general_text(" into the file: ");
                        self.one_line.push(filename.yellow());
                        self.general_text(" at an offset of ");
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            let bytes_num = self.result.0.unwrap();
                            self.general_text(" |=> ");
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readv => {
                let number_of_iovecs = self.args[2];
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("read from ");
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory from the file: ");
                        } else {
                            self.general_text(" scattered regions of memory from the file: ");
                        }
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("read ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::writev => {
                let filename = self.pavfol(0);
                let number_of_iovecs = self.args[2];

                match self.state {
                    Entering => {
                        self.general_text("write into ");
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory of the file: ");
                        } else {
                            self.general_text(" scattered regions of memory of the file: ");
                        }
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("wrote ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("read from ");
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory from the file: ");
                        } else {
                            self.general_text(" scattered regions of memory from the file: ");
                        }
                        self.one_line.push(filename.yellow());
                        self.general_text(" at an offset of ");
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("read ".green());
                            self.one_line.push(bytes_string.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("write into ");
                        self.one_line.push(number_of_iovecs.to_string().yellow());
                        if number_of_iovecs == 1 {
                            self.general_text(" region of memory of the file: ");
                        } else {
                            self.general_text(" scattered regions of memory of the file: ");
                        }
                        self.one_line.push(filename.yellow());
                        self.general_text(" at an offset of ");
                        self.one_line.push(offset.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let bytes_string = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("wrote ".green());
                            self.one_line.push(bytes_string.yellow());
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
                            self.one_line.push("all writes flushed".green());
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
                let old_path = self.pavfol(0);
                let new_path = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("move the file: ");
                        self.one_line.push(old_path.yellow());
                        self.general_text(" to: ");
                        self.one_line.push(new_path.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.one_line.push("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::renameat => {
                let old_dirfd = self.args[0] as i32;
                let old_filename = self.pavfol(1);
                let new_dirfd = self.args[2] as i32;
                let new_filename = self.pavfol(3);
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
                            self.one_line.push("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::renameat2 => {
                let old_dirfd = self.args[0] as i32;
                let old_filename = self.pavfol(1);
                let new_dirfd = self.args[2] as i32;
                let new_filename = self.pavfol(3);
                let flags = self.args[2] as u32;
                match self.state {
                    Entering => {
                        self.general_text("move the file: ");
                        self.possible_dirfd_file(old_dirfd, old_filename);

                        self.general_text(" to: ");
                        self.possible_dirfd_file(new_dirfd, new_filename);

                        let mut directives = vec![];
                        if (flags & RENAME_EXCHANGE) > 0 {
                            directives.push("exchange the paths atomically".yellow())
                        }
                        if (flags & RENAME_NOREPLACE) > 0 {
                            directives.push("error if the new path exists".yellow());
                        }
                        if (flags & RENAME_WHITEOUT) > 0 {
                            directives.push("white-out the original file".yellow());
                        }
                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.one_line.push("file moved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("create a new directory ");
                            self.one_line
                                .push(canon_path.file_name().unwrap().to_string_lossy().yellow());
                            self.general_text(" inside: ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("directory created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::mkdirat => {
                let dirfd = self.args[0] as i32;
                let filename: String = self.pavfol(1);

                match self.state {
                    Entering => {
                        let path = self.possible_dirfd_file_output(dirfd, filename);
                        let path_rust = PathBuf::from(path);

                        self.general_text("create a new directory ");
                        self.one_line.push(
                            path_rust
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .to_owned()
                                .blue(),
                        );
                        self.general_text(" inside: ");
                        self.one_line.push(
                            path_rust
                                .parent()
                                .unwrap()
                                .to_string_lossy()
                                .to_owned()
                                .yellow(),
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("directory created".green());
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
                            self.one_line.push("cwd: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::symlink => {
                let target = self.pavfol(0);
                let symlink = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("create the symlink: ");
                        handle_path_file(symlink, &mut self.one_line);

                        self.general_text(" and link it with: ");
                        handle_path_file(target, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("symlink created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::symlinkat => {
                let target = self.pavfol(0);
                let dirfd = self.args[1] as i32;
                let symlink = self.pavfol(2);

                match self.state {
                    Entering => {
                        self.general_text("create the symlink: ");
                        self.possible_dirfd_file(dirfd, symlink);
                        self.general_text(" and link it with: ");
                        self.one_line.push(target.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("symlink created".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    } // the file does not exist at this point
                }
            }
            Sysno::unlink => {
                let path = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("unlink and possibly delete the file: ");
                        handle_path_file(path, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("unlinking successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    } // caution: the file is deleted at this point
                }
            }
            Sysno::unlinkat => {
                let dirfd = self.args[0] as i32;
                let path = self.pavfol(1);
                let flag = self.args[2] as i32;
                match self.state {
                    Entering => {
                        self.general_text("unlink and possibly delete the file: ");
                        self.possible_dirfd_file(dirfd, path);

                        if (flag & AT_REMOVEDIR) > 0 {
                            self.general_text(" (");
                            self.one_line
                                .push("perform the same operation as ".yellow());
                            self.one_line.push("`rmdir`".blue());
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("unlinking successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("check if the file: ");
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
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file: ");
                                handle_path_file(filename, &mut self.one_line);
                            }
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::faccessat => {
                let dirfd = self.args[0] as i32;
                let filename = self.pavfol(1);
                let access_mode: nix::unistd::AccessFlags =
                    unsafe { std::mem::transmute(self.args[2] as u32) };
                let flags: nix::fcntl::AtFlags =
                    unsafe { std::mem::transmute(self.args[3] as u32) };

                match self.state {
                    Entering => {
                        if access_mode.contains(nix::unistd::AccessFlags::F_OK) {
                            self.general_text("check if the file: ");
                            self.possible_dirfd_file(dirfd, filename);

                            self.general_text(" ");
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
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file: ");
                                self.possible_dirfd_file(dirfd, filename);
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
                        self.directives_handler(flag_directive);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("check if the file: ");
                            self.possible_dirfd_file(dirfd, filename);
                            self.general_text(" ");
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
                                self.general_text("check if the process is allowed to ");
                                self.vanilla_commas_handler(checks);
                                self.general_text(" the file ");
                                self.possible_dirfd_file(dirfd, filename);
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
                        self.directives_handler(flag_directive);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("check is positive".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readlink => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("get the target path of the symbolic link: ");
                        handle_path_file(filename, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("target retrieved: ".green());
                            let target = self.pavfol(1);
                            self.one_line.push(target.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::readlinkat => {
                let dirfd = self.args[0] as i32;
                let filename = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("get the target path of the symbolic link: ");
                        self.possible_dirfd_file(dirfd, filename)
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("target retrieved: ".green());
                            let target = self.pavfol(1);
                            self.one_line.push(target.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::chmod => {
                let filename: String = self.pavfol(0);
                let mode: rustix::fs::Mode = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("change the mode of the file: ");
                        handle_path_file(filename, &mut self.one_line);
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fchmod => {
                let filename: String = self.pavfol(0);
                let mode: rustix::fs::Mode = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("change the mode of the file: ");
                        self.one_line.push(filename.yellow());
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("change the mode of the file: ");
                        self.possible_dirfd_file(dirfd, filename);
                        self.mode_matcher(mode);
                        self.general_text("and ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("mode changed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::syncfs => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("flush all pending filesystem data and metadata writes for the filesystem that contains the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully flushed data".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pipe => {
                let file_descriptors = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("create a pipe for inter-process communication");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("created the pipe: ".green());
                            self.one_line.push(file_descriptors.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::pipe2 => {
                let file_descriptors = self.pavfol(0);
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
                            self.one_line.push("created the pipe: ".green());
                            self.one_line.push(file_descriptors.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::dup => {
                let file_descriptor = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("duplicate the file descriptor: ");
                        self.one_line.push(file_descriptor.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line
                                .push("created a new duplicate file descriptor: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::dup2 => {
                let to_be_duplicated = self.pavfol(0);
                let duplicate = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("duplicate the file descriptor: ");
                        self.one_line.push(to_be_duplicated.yellow());
                        self.general_text(" using the descriptor: ");
                        self.one_line.push(duplicate.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("duplicate the file descriptor: ");
                        self.one_line.push(to_be_duplicated.yellow());
                        self.general_text(" using the descriptor: ");
                        self.one_line.push(duplicate.yellow());
                        if (dup_flag_num & O_CLOEXEC) == O_CLOEXEC {
                            self.one_line
                                .push(" and close the file on the next exec syscall".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfully duplicated".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fsync => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text(
                            "flush all pending data and metadata writes for the file: ",
                        );
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("all writes flushed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fdatasync => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("flush all pending data and critical metadata writes (ignore non-critical metadata) for the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("all writes flushed".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::truncate => {
                let filename = self.pavfol(0);
                let length = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("change the size of the file: ");
                        self.one_line.push(filename.yellow());
                        self.general_text(" to precisely ");
                        self.one_line.push(length.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::ftruncate => {
                let filename = self.pavfol(0);
                let length = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text("change the size of the file: ");
                        self.one_line.push(filename.yellow());
                        self.general_text(" to precisely ");
                        self.one_line.push(length.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block all ");
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
                        self.anding_handler(blockers);
                        self.general_text(" file descriptors lower than ");
                        self.one_line.push(highest_fd.to_string().blue());

                        if timeout > 0 {
                            let timeval = SyscallObject::read_bytes_as_struct::<16, timeval>(
                                self.args[4] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timeval(timeval.tv_sec, timeval.tv_usec);
                        } else {
                            self.general_text(", and ");
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if res == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else if res > 0 {
                                self.one_line.push(res.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block for events on all ");
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
                        self.anding_handler(blockers);
                        self.general_text(" file descriptors lower than ");
                        self.one_line.push(highest_fd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", and ");
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if timeout > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[4] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                        } else {
                            self.general_text(", and ");
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let res = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if res == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else if res > 0 {
                                self.one_line.push(res.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::poll => {
                let nfds = self.args[1];
                let timeout = self.args[2];
                match self.state {
                    Entering => {
                        self.general_text("block for new events on the ");
                        self.one_line.push(nfds.to_string().blue());
                        self.general_text(" provided file descriptors, ");
                        self.general_text("and timeout after ");
                        self.one_line.push(timeout.to_string().blue());
                        self.general_text(" milliseconds");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if num_fds == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else {
                                self.one_line.push(num_fds.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block for new events on the ");
                        self.one_line.push(nfds.to_string().blue());
                        self.general_text(" provided file descriptors");

                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if timeout > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[2] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                        } else {
                            self.general_text(", and ");
                            self.one_line.push("wait forever".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let num_fds = self.result.0.unwrap();
                            self.general_text(" |=> ");
                            if num_fds == 0 {
                                self.one_line.push("timed out before any events".green());
                            } else {
                                self.one_line.push(num_fds.to_string().blue());
                                self.one_line
                                    .push(" file descriptors with new events".green());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_create => {
                let nfds = self.args[0];
                match self.state {
                    Entering => {
                        self.general_text("create an epoll instance with a capacity of ");
                        self.one_line.push(nfds.to_string().yellow());
                        self.general_text(" file descriptors");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::epoll_create1 => {
                let flags = self.args[0];
                match self.state {
                    Entering => {
                        self.general_text("create an epoll instance ");

                        if flags as i32 == EPOLL_CLOEXEC {
                            self.general_text("(");
                            self.one_line
                                .push("close file descriptors on the next exec syscall".yellow());
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block until a maximum of ");
                        self.one_line.push(max_events.to_string().yellow());
                        self.general_text(" events occur on epoll instance ");
                        self.one_line.push(epfd.to_string().blue());
                        if time > 0 {
                            self.general_text(" and wait for ");
                            self.one_line.push(time.to_string().blue());
                            self.one_line.push(" milliseconds".yellow());
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block until a maximum of ");
                        self.one_line.push(max_events.to_string().yellow());
                        self.general_text(" events occur on epoll instance ");
                        self.one_line.push(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if time > 0 {
                            self.general_text(" and wait for ");
                            self.one_line.push(time.to_string().blue());
                            self.one_line.push(" milliseconds".yellow());
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("block until a maximum of ");
                        self.one_line.push(max_events.to_string().yellow());
                        self.general_text(" events occur on epoll instance ");
                        self.one_line.push(epfd.to_string().blue());
                        if signal_mask != 0 {
                            self.general_text(", or ");
                            self.one_line
                                .push("any signal from the provided signal mask".yellow());
                        }

                        if time > 0 {
                            let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                                self.args[3] as usize,
                                self.process_pid as _,
                            )
                            .unwrap();
                            self.general_text(", and timeout ");
                            self.format_timespec(timespec.tv_sec, timespec.tv_nsec);
                        } else {
                            self.one_line.push(" and wait forever".yellow());
                        }

                        self.general_text(" ");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text(" file descriptor ");
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.general_text(" to ");
                        } else if (operation as i32 & EPOLL_CTL_DEL) == EPOLL_CTL_DEL {
                            self.one_line.push("remove".yellow());
                            self.general_text(" file descriptor ");
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.general_text(" from ");
                        } else if (operation as i32 & EPOLL_CTL_MOD) == EPOLL_CTL_MOD {
                            self.one_line.push("modify the settings of ".yellow());
                            self.general_text(" file descriptor ");
                            self.one_line.push(file_descriptor.to_string().blue());
                            self.general_text(" in ");
                        }
                        self.general_text("epoll instance ");
                        self.one_line.push(epfd.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successfull".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::ioctl => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("perform operation ");
                        self.one_line
                            .push(format!("#{}", self.args[1].to_string()).yellow());
                        self.general_text(" on the device: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("operation successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::fcntl => {
                let filename = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("perform operation ");
                        self.one_line
                            .push(format!("#{}", self.args[1].to_string()).yellow());
                        self.general_text(" on the file: ");
                        self.one_line.push(filename.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("operation successful".green());
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

                let operation = self.args[0];
                let value = self.args[1];

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
                            self.one_line.push(value.to_string().blue());
                        } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                            self.general_text(
                                "retrieve the calling thread's 64-bit FS register value",
                            );
                        } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                            self.general_text("Set the 64-bit base for the GS register to ");
                            self.one_line.push(value.to_string().blue());
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
                            self.one_line.push("successfully yielded CPU".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                    self.general_text("change the process's default handler for ");
                                    self.one_line.push(signal_as_string.yellow());
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
                            self.general_text(" |=> ");
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
                            self.one_line_error();
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
                                self.general_text(
                                    "retrieve the proccess's current list of blocked signals",
                                );
                            } else {
                                self.one_line
                                    .push("[intentrace Notice: syscall no-op]".blink());
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
                            self.one_line
                                .push("list of blocked signals modified".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("replace the current signal stack with a new one");
                        }
                        (false, true) => {
                            self.general_text("retrieve the current signal stack");
                        }
                        (false, false) => {
                            self.general_text(                            "retrieve the current signal stack and then replace it with a new one,",
                        );
                        }
                    },
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
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
                            self.one_line.push("successful".green());
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
                            self.one_line.push("pending signals returned".green());
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
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("send the data attached and the ");
                            self.one_line.push(signal_as_string.yellow());
                            self.general_text(" signal to the thread group: ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("data and signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("send the data attached and the ");
                            self.one_line.push(signal_as_string.yellow());
                            self.general_text(" signal to thread: ");
                            self.one_line.push(thread.to_string().yellow());
                            self.general_text(" in thread group: ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("data and signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                self.general_text("send the ");
                                self.one_line.push(signal_as_string.yellow());
                                // bad wording
                                self.general_text(
                                    " signal to the process identified with the file descriptor: ",
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
                            self.general_text(" |=> ");
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::signalfd => {
                let fd = self.args[0] as i32;
                match self.state {
                    Entering => {
                        if fd == -1 {
                            self.general_text(                        "create a new file descriptor for receiving the set of specified signals",
                    );
                        } else {
                            let fd_file = self.pavfol(0);
                            self.general_text("use the file: ");
                            self.one_line.push(fd_file.yellow());
                            self.general_text(" to receive the provided signals");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text(                                "create a file descriptor to use for receiving the provided signals",
                            );
                        } else {
                            let fd_file = self.pavfol(0);
                            self.general_text("use the file: ");
                            self.one_line.push(fd_file.yellow());
                            self.general_text(" to receive the provided signals");
                        }
                        let mut flag_directives = vec![];

                        if flags.contains(SfdFlags::SFD_CLOEXEC) {
                            flag_directives
                                .push("close the file with the next exec syscall".yellow());
                        }
                        if flags.contains(SfdFlags::SFD_NONBLOCK) {
                            flag_directives.push("use the file on non blocking mode".yellow());
                        }
                        self.directives_handler(flag_directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("file descriptor created".green());
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
                            self.one_line.push("got the thread id: ".green());
                            self.one_line.push(thread.yellow());
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
                            self.one_line.push("got the process id: ".green());
                            self.one_line.push(process_id.yellow());
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
                            self.one_line.push("got the parent process' id: ".green());
                            self.one_line.push(process_id.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::get_robust_list => {
                let process_id_num = self.args[0];
                match self.state {
                    Entering => {
                        self.general_text("get the list of the robust futexes for ");
                        if process_id_num == 0 {
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.general_text("thread ");
                            self.one_line.push(process_id_num.to_string().blue());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let address = self.pavfol(1);
                            let length_of_list =
                                SyscallObject::read_word(self.args[2] as usize, self.process_pid)
                                    .unwrap();
                            self.general_text(" |=> ");
                            self.one_line
                                .push("head of the retrieved list is stored in ".green());
                            self.one_line.push(address.yellow());
                            self.one_line.push(" with length ".green());
                            self.one_line.push(length_of_list.to_string().blue());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::set_robust_list => {
                let address = self.pavfol(0);
                let length_of_list = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text(
                            "set the calling thread's robust futexes list to the list at ",
                        );
                        self.one_line.push(address.yellow());
                        self.general_text(" with length ");
                        self.one_line.push(length_of_list.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("set the process group ID of ");
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.general_text("set the process group ID of process: ");
                            self.one_line.push(process_id.yellow());
                        }
                        if new_pgid_num == 0 {
                            self.general_text(" to: ");
                            self.one_line.push("the calling process' ID".yellow());
                        } else {
                            self.general_text(" to: ");
                            self.one_line.push(new_pgid.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("get the process group ID of ");
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.general_text("get the process group ID of process: ");
                            self.one_line.push(process_id.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let pgid = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("got the group id: ".green());
                            self.one_line.push(pgid.yellow());
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
                            self.one_line.push("got the group id: ".green());
                            self.one_line.push(pgid.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("get ");
                        self.one_line.push(bytes.yellow());
                        self.general_text(" of random bytes from the ");
                        if random_flags.contains(GetRandomFlags::RANDOM) {
                            self.one_line.push("random source".yellow());
                            self.general_text(" and ");
                            if random_flags.contains(GetRandomFlags::NONBLOCK) {
                                self.one_line
                                    .push("do not block if the random source is empty".yellow());
                            } else {
                                self.one_line
                                    .push("block if the random source is empty".yellow());
                            }
                        } else {
                            self.one_line.push("urandom source".yellow());
                            self.general_text(" and ");
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

                            self.general_text(" |=> ");
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::setrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("set the process's ");
                        resource_matcher(resource, &mut self.one_line);
                        self.general_text(" to the soft and hard limits provided");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getrlimit => {
                let resource: Resource = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get the soft and hard limits for the process's ");
                        resource_matcher(resource, &mut self.one_line);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("set ");
                            if pid_of_self {
                                self.one_line.push("the calling process's".yellow());
                            } else {
                                self.one_line.push("process ".yellow());
                                self.one_line.push(pid.to_string().yellow());
                                self.general_text("'s");
                            }
                            self.general_text(" ");
                            resource_matcher(resource, &mut self.one_line);
                            self.general_text(" to the soft and hard limits provided");
                            if !get_struct.is_null() {
                                self.one_line.push(", and get the old limits".yellow());
                            }
                        } else if !get_struct.is_null() {
                            self.general_text("get the soft and hard limits for ");
                            if pid_of_self {
                                self.one_line.push("the calling process's".yellow());
                            } else {
                                self.one_line.push("process ".yellow());
                                self.one_line.push(pid.to_string().yellow());
                                self.general_text("'s");
                            }
                            self.general_text(" ");
                            resource_matcher(resource, &mut self.one_line);
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            let rlims = SyscallObject::read_bytes_as_struct::<16, rlimit>(
                                self.args[3] as usize,
                                self.process_pid as _,
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getrusage => {
                let resource: UsageWho = unsafe { std::mem::transmute(self.args[0] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("get resource usage metrics for ");

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
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
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
                            self.one_line.push("successful".green());
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
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sched_setaffinity => {
                let thread_id = self.args[0];

                let cpus = SyscallObject::read_affinity_from_child(
                    self.args[2] as usize,
                    self.process_pid,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        if !cpus.is_empty() {
                            self.general_text("only allow ");
                            if thread_id == 0 {
                                self.one_line.push("the calling thread".yellow());
                            } else {
                                self.one_line.push("thread ".yellow());
                                self.one_line.push(thread_id.to_string().yellow());
                            }
                            self.general_text(" to run on ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("thread successfully locked".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::sched_getaffinity => {
                let thread_id = self.args[0];
                // let cpu_set: cpu_set_t = unsafe { std::mem::transmute(self.args_vec[2] as u32) };
                // let num_cpus = num_cpus::get();
                let mut set: cpu_set_t = unsafe { mem::zeroed() };

                let cpus = SyscallObject::read_affinity_from_child(
                    self.args[2] as usize,
                    self.process_pid,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        self.general_text("find which CPUs ");
                        if thread_id == 0 {
                            self.one_line.push("the calling thread".yellow());
                        } else {
                            self.one_line.push("thread ".yellow());
                            self.one_line.push(thread_id.to_string().yellow());
                        }
                        self.general_text(" is allowed to run on");
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("CPUs allowed: ".green());
                            if cpus.is_empty() {
                                self.general_text("None");
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::exit => {
                let status = self.args[0] as i32;
                match self.state {
                    Entering => {
                        self.general_text("exit the calling process with status: ");
                        if status < 0 {
                            self.one_line.push(status.to_string().red());
                        } else {
                            self.one_line.push(status.to_string().yellow());
                        }
                        self.general_text(" |=> ");
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
                        self.general_text("exit all threads in the group with status: ");
                        if status < 0 {
                            self.one_line.push(status.to_string().red());
                        } else {
                            self.one_line.push(status.to_string().yellow());
                        }
                        self.general_text(" |=> ");
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
                            self.general_text("send ");
                            self.one_line.push(signal_as_string.yellow());
                            self.general_text(" to thread: ");
                            self.one_line.push(thread.to_string().yellow());
                            self.general_text(" in thread group: ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("send ");
                            self.one_line.push(signal_as_string.yellow());
                            self.general_text(" to thread: ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("signal sent".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text(                        "register a per-thread shared data structure between kernel and user-space",
                    );
                        } else {
                            self.general_text(                        "unregister a previously registered per-thread shared data structure",
                    );
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            if registering {
                                self.one_line.push("successfully registered".green());
                            } else {
                                self.one_line.push("successfully unregistered".green());
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
                            self.one_line.push("information retrieved".green());
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
                            self.one_line.push("got the real user ID: ".green());
                            self.one_line.push(user_id.yellow());
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
                            self.one_line.push("got the effective user ID: ".green());
                            self.one_line.push(user_id.yellow());
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
                            self.one_line.push("got the real group ID: ".green());
                            self.one_line.push(group_id.yellow());
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
                            self.one_line.push("got the effective group ID: ".green());
                            self.one_line.push(group_id.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("stop incoming reception of data into the socket: ");
                            self.one_line.push(socket.yellow());
                        }
                        // SHUT_WR = 1
                        if (shutdown_how_num & 1) == 1 {
                            self.general_text(
                                "stop outgoing transmission of data from the socket: ",
                            );
                            self.one_line.push(socket.yellow());
                        }
                        // SHUT_RDWR = 2
                        if (shutdown_how_num & 2) == 2 {
                            self.general_text(                        "terminate incoming and outgoing data communication with the socket: ",
                    );
                            self.one_line.push(socket.yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                "block and wait for FUTEX_WAKE if comparison succeeds".yellow(),
                            );
                        } else if (futex_ops_num & FUTEX_WAKE) == FUTEX_WAKE {
                            self.general_text("wake a maximum of ");
                            self.one_line.push(val.to_string().yellow());
                            self.general_text(" waiters waiting on the futex at ");
                            self.one_line.push(futex1_addr.yellow());
                        } else if (futex_ops_num & FUTEX_FD) == FUTEX_FD {
                            self.general_text("create a file descriptor for the futex at ");
                            self.one_line.push(futex1_addr.yellow());
                            self.general_text(" to use with asynchronous syscalls");
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE) == FUTEX_CMP_REQUEUE {
                            self.general_text("if comparison succeeds wake a maximum of ");
                            self.one_line.push(val.to_string().yellow());
                            self.general_text(" waiters waiting on the futex at ");
                            self.one_line.push(futex1_addr.yellow());
                            self.general_text(" and requeue a maximum of ");
                            self.one_line.push(val2.to_string().yellow());
                            self.general_text(" from the remaining waiters to the futex at ");
                            self.one_line.push(futex2_addr.yellow());
                        } else if (futex_ops_num & FUTEX_REQUEUE) == FUTEX_REQUEUE {
                            self.general_text("without comparing wake a maximum of ");
                            self.one_line.push(val.to_string().yellow());
                            self.general_text(" waiters waiting on the futex at ");
                            self.one_line.push(futex1_addr.yellow());
                            self.general_text(" and requeue a maximum of ");
                            self.one_line.push(val2.to_string().yellow());
                            self.general_text(" from the remaining waiters to the futex at ");
                            self.one_line.push(futex2_addr.yellow());
                        } else if (futex_ops_num & FUTEX_WAKE_OP) == FUTEX_WAKE_OP {
                            self.general_text("operate on 2 futexes at the same time");
                        } else if (futex_ops_num & FUTEX_WAIT_BITSET) == FUTEX_WAIT_BITSET {
                            self.general_text("if comparison succeeds block and wait for FUTEX_WAKE and register a bitmask for selective waiting");
                        } else if (futex_ops_num & FUTEX_WAKE_BITSET) == FUTEX_WAKE_BITSET {
                            self.general_text("wake a maximum of ");
                            self.one_line.push(val.to_string().yellow());
                            self.general_text(" waiters waiting on the futex at ");
                            self.one_line.push(futex1_addr.yellow());
                            self.one_line
                                .push(" from the provided waiters bitmask".yellow());
                        } else if (futex_ops_num & FUTEX_LOCK_PI) == FUTEX_LOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_LOCK_PI2) == FUTEX_LOCK_PI2 {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_TRYLOCK_PI) == FUTEX_TRYLOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_UNLOCK_PI) == FUTEX_UNLOCK_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_CMP_REQUEUE_PI) == FUTEX_CMP_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
                            self.one_line
                                .push("[intentrace: needs granularity]".bright_black());
                        } else if (futex_ops_num & FUTEX_WAIT_REQUEUE_PI) == FUTEX_WAIT_REQUEUE_PI {
                            self.general_text("priority-inheritance futex operation ");
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
                            self.general_text(" (");
                            let mut directives_iter = directives.into_iter().peekable();
                            if directives_iter.peek().is_some() {
                                self.one_line.push(directives_iter.next().unwrap());
                            }
                            for entry in directives_iter {
                                self.general_text(", ");
                                self.one_line.push(entry);
                            }
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            // TODO! granular
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::set_tid_address => {
                let thread_id =
                    SyscallObject::read_word(self.args[0] as usize, self.process_pid).unwrap();
                match self.state {
                    Entering => {
                        self.general_text("set `clear_child_tid` for the calling thread to ");
                        self.one_line.push(thread_id.to_string().blue());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line
                                .push("thread id of the calling thread: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
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
                            self.one_line.push("child process created: ".green());
                            self.one_line.push(child_process.yellow());
                            self.one_line.push(new_process());
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
                            self.one_line.push("child process created: ".green());
                            self.one_line.push(child_process.yellow());
                            self.one_line.push(new_process());
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
                            self.one_line.push("created the eventfd: ".green());
                            self.one_line.push(file_descriptor.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::eventfd2 => {
                let flags: eventfd::EfdFlags = unsafe { std::mem::transmute(self.args[1] as u32) };
                match self.state {
                    Entering => {
                        self.general_text("create a file to use for event notifications/waiting");

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
                            self.general_text(" (");
                            let mut directives_iter = directives.into_iter().peekable();
                            if directives_iter.peek().is_some() {
                                self.one_line.push(directives_iter.next().unwrap());
                            }
                            for entry in directives_iter {
                                self.general_text(", ");
                                self.one_line.push(entry);
                            }
                            self.general_text(")");
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("created the eventfd: ".green());
                            self.one_line.push(file_descriptor.yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("wait until any child ");
                        } else if id_type == P_PGID {
                            if id == 0 {
                                self.general_text(
                                    "wait until any child in the current process group ",
                                );
                            } else {
                                self.general_text("wait until any child process with PGID ");
                                self.one_line.push(id.to_string().yellow());
                            }
                        } else if id_type == P_PID {
                            self.general_text("wait until child process ");
                            self.one_line.push(id.to_string().yellow());
                        } else if id_type == P_PIDFD {
                            self.general_text("wait until child with PIDFD ");
                            self.one_line.push(id.to_string().yellow());
                        }
                        self.general_text(" ");
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
                        self.oring_handler(options_ticked);

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
                        self.directives_handler(options_directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            let file_descriptor = eph_return.unwrap();
                            self.general_text(" |=> ");
                            self.one_line.push("Successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                self.general_text(
                                    "wait for state change in any child with process group ID ",
                                );
                                self.one_line.push(pid.to_string().blue());
                            } else if pid == -1 {
                                self.general_text("wait for state change in any child");
                            } else if pid == 0 {
                                self.general_text(                                    "wait for state change in any child with a similar process group ID",
                                );
                            } else {
                                self.general_text("wait for state change in child process ");
                                self.one_line.push(pid.to_string().blue());
                            }
                        } else {
                            if pid < -1 {
                                self.general_text("wait until any child with process group ID ");
                                self.one_line.push(pid.to_string().blue());
                            } else if pid == -1 {
                                self.general_text("wait until any child");
                            } else if pid == 0 {
                                self.general_text(
                                    "wait until any child with a similar process group ID",
                                );
                            } else {
                                self.general_text("wait until child process ");
                                self.one_line.push(pid.to_string().blue());
                            }

                            self.general_text(" ");
                            self.oring_handler(options_ticked);
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
                        self.directives_handler(directives);

                        let mut retrieves = vec![];
                        if wstatus != 0 {
                            retrieves.push("exit status".yellow());
                        }
                        let rusage = self.args[3];
                        if rusage != 0 {
                            retrieves.push("resource usage metrics".yellow());
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
                                        self.general_text(" ");
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
                                //             general_text.push(" ");
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
                                //         general_text.push(" signal due to ");
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
                                //         self.one_line.push(                                //             "process was resumed from a stop state by ".green(),
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
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::clone3 => {
                let size_of_cl_args = self.args[1];
                let cl_args = SyscallObject::read_bytes_as_struct::<88, clone3::CloneArgs>(
                    self.args[0] as usize,
                    self.process_pid as _,
                )
                .unwrap();
                let clone_flags: clone3::Flags = unsafe { std::mem::transmute(cl_args.flags) };
                let clone_vm = clone_flags.contains(clone3::Flags::VM);

                match self.state {
                    Entering => {
                        if clone_vm {
                            self.general_text("spawn a new thread with a ");

                            self.one_line.push(
                                SyscallObject::style_bytes_page_aligned_ceil(cl_args.stack_size)
                                    .yellow(),
                            );
                            self.general_text(" stack starting at ");
                            self.one_line
                                .push(format!("0x{:x}", cl_args.stack).yellow());
                            // directives.push("run in the same memory space".yellow());
                        } else {
                            self.general_text("spawn a new child process");
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
                            self.general_text(" (");
                            self.general_text("execute in a new ");
                            self.anding_handler(executes);
                            self.general_text(")");
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

                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("thread id of the child: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                            if clone_vm {
                                self.one_line.push(new_thread());
                            } else {
                                self.one_line.push(new_process());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                            self.general_text("spawn a new thread at stack address ");
                            self.one_line.push(format!("0x{:x}", stack).yellow());
                            // directives.push("run in the same memory space".yellow());
                        } else {
                            self.general_text("spawn a new child process");
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
                            self.general_text(" (");
                            self.general_text("execute in a new ");
                            self.anding_handler(executes);
                            self.general_text(")");
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

                        self.directives_handler(directives);
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("thread id of the child: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                            // TODO! fix occasional error (syscall returns -38)
                            if clone_vm {
                                self.one_line.push(new_thread());
                            } else {
                                self.one_line.push(new_process());
                            }
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::execve => {
                let program_name = self.pavfol(0);
                let arguments = self.pavfol(1);
                match self.state {
                    Entering => {
                        self.general_text(
                            "replace the current program with the following program and arguments",
                        );
                        self.one_line.push(program_name.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::nanosleep => {
                let timespec = SyscallObject::read_bytes_as_struct::<16, timespec>(
                    self.args[0] as usize,
                    self.process_pid as _,
                )
                .unwrap();
                match self.state {
                    Entering => {
                        self.general_text("suspend execution for ");
                        self.format_timespec_non_relative(
                            timespec.tv_sec,
                            timespec.tv_nsec,
                        );
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successful".green());
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
                            self.one_line_error();
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
                            self.general_text("add a new rule for ");
                            self.one_line
                                .push("file system path-beneath access rights".yellow());
                        }
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("rule added".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::landlock_restrict_self => {
                let ruleset_fd = self.pavfol(0);
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
                            self.one_line.push("ruleset is now enforced".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.one_line.push(offset.yellow());
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.one_line.push(file_descriptor.yellow());
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

                                self.one_line.push(
                                    "modify any shared file data to private copy-on-write".yellow(),
                                );
                                self.general_text(")");
                            } else {
                                self.general_text(" (");
                                self.one_line.push(
                                    "increase file size and zeroize if the range is larger"
                                        .yellow(),
                                );
                                self.general_text(")");
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE)
                            && mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE)
                        {
                            self.one_line.push("deallocate ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.one_line.push(offset.yellow());
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.one_line.push(file_descriptor.yellow());
                        } else if mode
                            .contains(nix::fcntl::FallocateFlags::FALLOC_FL_COLLAPSE_RANGE)
                        {
                            self.one_line.push("remove ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.general_text(" from the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.one_line.push(offset.yellow());
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.one_line.push(file_descriptor.yellow());
                            self.one_line.push(" without leaving a hole".yellow());
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.one_line.push("zeroize ".magenta());
                            self.one_line.push(bytes.yellow());
                            if offset_num == 0 {
                                self.general_text(" from the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.one_line.push(offset.yellow());
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.one_line.push(file_descriptor.yellow());
                            if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE) {
                                self.general_text(" (");
                                self.one_line.push(
                                    "do not increase the file size if the range is larger".yellow(),
                                );
                                self.general_text(")");
                            }
                        } else if mode.contains(nix::fcntl::FallocateFlags::FALLOC_FL_ZERO_RANGE) {
                            self.one_line.push("insert ".magenta());
                            self.one_line.push(bytes.yellow());
                            self.one_line.push(" of holes".magenta());

                            if offset_num == 0 {
                                self.general_text(" at the beginning of the file: ");
                            } else {
                                self.general_text(" starting at ");
                                self.one_line.push(offset.yellow());
                                self.general_text(" from the beginning of the file: ");
                            }
                            self.one_line.push(file_descriptor.yellow());
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
                            self.one_line.push("operation successful".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getpriority => {
                let which = self.args[0] as u32;
                let target = self.args[1];

                match self.state {
                    Entering => {
                        self.general_text("get the scheduling priority ");
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.general_text("of ");
                            if target == 0 {
                                self.one_line.push("the calling process".yellow());
                            } else {
                                self.one_line.push("process: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.general_text("of ");
                            if target == 0 {
                                self.one_line
                                    .push("the process group of calling process".yellow());
                            } else {
                                self.one_line.push("process group: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.general_text("for ");
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
                            self.general_text(" |=> ");
                            self.one_line.push("got the scheduling priority: ".green());
                            self.one_line.push(eph_return.unwrap().yellow());
                        } else {
                            // TODO! granular
                            self.one_line_error();
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
                        self.general_text("set the scheduling priority ");
                        if (which & PRIO_PROCESS) == PRIO_PROCESS {
                            self.general_text("of ");
                            if target == 0 {
                                self.one_line.push("the calling process".yellow());
                            } else {
                                self.one_line.push("process: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                            self.general_text(" to ");
                            self.one_line.push(prio.yellow());
                        } else if (which & PRIO_PGRP) == PRIO_PGRP {
                            self.general_text("of ");
                            if target == 0 {
                                self.one_line
                                    .push("the process group of calling process".yellow());
                            } else {
                                self.one_line.push("process group: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                            }
                            self.general_text(" to ");
                            self.one_line.push(prio.yellow());
                        } else if (which & PRIO_USER) == PRIO_USER {
                            self.general_text("for ");
                            if target == 0 {
                                self.one_line
                                    .push("the real user id of the calling process".yellow());
                            } else {
                                self.one_line.push("the real user id: ".yellow());
                                self.one_line.push(target.to_string().yellow());
                                self.general_text(" to ");
                                self.one_line.push(prio.yellow());
                            }
                        }
                        // TODO! Flags
                        //
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line
                                .push("successfully set the scheduling priority".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getdents => {
                let directory = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("retrieve the entries inside the directory ");
                        self.one_line.push(directory.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully retrieved".green());
                        } else {
                            // TODO! granular
                            self.one_line_error();
                        }
                    }
                }
            }
            Sysno::getdents64 => {
                let directory = self.pavfol(0);
                match self.state {
                    Entering => {
                        self.general_text("retrieve the entries inside the directory ");
                        self.one_line.push(directory.yellow());
                    }
                    Exiting => {
                        let eph_return = self.get_syscall_return();
                        if eph_return.is_ok() {
                            self.general_text(" |=> ");
                            self.one_line.push("successfully retrieved".green());
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
    pub fn oring_handler(&mut self, vector: Vec<ColoredString>) {
        if !vector.is_empty() {
            let mut vector_iter = vector.into_iter().peekable();
            if vector_iter.peek().is_some() {
                self.one_line.push(vector_iter.next().unwrap());
            }
            let mut ender = vec![];
            if vector_iter.peek().is_some() {
                colorize_general(&mut ender, ", or ");
                ender.push(vector_iter.next().unwrap());
            }
            for entry in vector_iter {
                self.general_text(", or ");
                self.one_line.push(entry);
            }
            self.one_line.extend(ender);
        }
    }

    pub fn anding_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        if vector_iter.peek().is_some() {
            self.one_line.push(vector_iter.next().unwrap());
        }
        let mut ender = vec![];
        if vector_iter.peek().is_some() {
            colorize_general(&mut ender, ", and ");
            ender.push(vector_iter.next().unwrap());
        }
        for entry in vector_iter {
            self.general_text(", ");
            self.one_line.push(entry);
        }
        self.one_line.extend(ender);
    }
    pub fn directives_handler(&mut self, vector: Vec<ColoredString>) {
        if !vector.is_empty() {
            self.general_text(" (");
            let mut vector_iter = vector.into_iter().peekable();
            if vector_iter.peek().is_some() {
                self.one_line.push(vector_iter.next().unwrap());
            }
            for entry in vector_iter {
                self.general_text(", ");
                self.one_line.push(entry);
            }
            self.general_text(")");
        }
    }

    pub fn vanilla_commas_handler(&mut self, vector: Vec<ColoredString>) {
        let mut vector_iter = vector.into_iter().peekable();
        if vector_iter.peek().is_some() {
            self.one_line.push(vector_iter.next().unwrap());
        }
        for entry in vector_iter {
            self.general_text(", ");
            self.one_line.push(entry);
        }
    }

    pub fn mode_matcher(&mut self, mode: rustix::fs::Mode) {
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
            self.general_text(" allowing the user to ");
            let mut perms_iter = perms.into_iter().peekable();
            if perms_iter.peek().is_some() {
                self.one_line.push(perms_iter.next().unwrap());
            }
            for entry in perms_iter {
                self.general_text(", ");
                self.one_line.push(entry);
            }
            self.general_text(", ");
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
            self.general_text(" allowing the group to ");
            let mut perms_iter = perms.into_iter().peekable();
            if perms_iter.peek().is_some() {
                self.one_line.push(perms_iter.next().unwrap());
            }
            for entry in perms_iter {
                self.general_text(", ");
                self.one_line.push(entry);
            }
            self.general_text(", ");
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
            self.general_text(" allowing others to ");
            let mut perms_iter = perms.into_iter().peekable();
            if perms_iter.peek().is_some() {
                self.one_line.push(perms_iter.next().unwrap());
            }
            for entry in perms_iter {
                self.general_text(", ");
                self.one_line.push(entry);
            }
            self.general_text(", ");
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
            self.general_text(" and set ");
            let mut sets_iter = sets.into_iter().peekable();
            if sets_iter.peek().is_some() {
                self.one_line.push(sets_iter.next().unwrap());
            }
            for entry in sets_iter {
                self.general_text(", ");
                self.one_line.push(entry);
            }
        }
    }
    pub fn format_timespec(&mut self, seconds: i64, nanoseconds: i64) {
        if seconds == 0 {
            if nanoseconds == 0 {
                self.one_line.push("immediately".yellow());
            } else {
                self.one_line.push("after ".yellow());
                self.one_line.push(nanoseconds.to_string().yellow());
                self.one_line.push(" nanoseconds".yellow());
            }
        } else {
            self.one_line.push("after ".yellow());
            self.one_line.push(seconds.to_string().yellow());
            self.one_line.push(" seconds".yellow());
            if nanoseconds != 0 {
                self.general_text(", ");
                self.one_line.push(nanoseconds.to_string().yellow());
                self.one_line.push(" nanoseconds".yellow());
            }
        }
    }
    pub fn format_timespec_non_relative(&mut self, 
        seconds: i64,
        nanoseconds: i64,
    ) {
        if seconds == 0 {
            if nanoseconds == 0 {
                self.one_line.push("0".blue());
                self.one_line.push(" nano-seconds".yellow());
            } else {
                self.one_line.push(nanoseconds.to_string().blue());
                self.one_line.push(" nano-seconds".yellow());
            }
        } else {
            self.one_line.push(seconds.to_string().blue());
            self.one_line.push(" seconds".yellow());
            if nanoseconds != 0 {
                self.general_text(" and ");
                self.one_line.push(nanoseconds.to_string().yellow());
                self.one_line.push(" nanoseconds".yellow());
            }
        }
    }

    pub fn format_timeval(&mut self, seconds: i64, microseconds: i64) {
        if seconds == 0 {
            if microseconds == 0 {
                self.one_line.push("immediately".yellow());
            } else {
                self.one_line.push("after ".yellow());
                self.one_line.push(microseconds.to_string().yellow());
                self.one_line.push(" microseconds".yellow());
            }
        } else {
            self.one_line.push("after ".yellow());
            self.one_line.push(seconds.to_string().yellow());
            self.one_line.push(" seconds".yellow());
            if microseconds != 0 {
                self.general_text(", ");
                self.one_line.push(microseconds.to_string().yellow());
                self.one_line.push(" microseconds".yellow());
            }
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

pub fn new_process() -> ColoredString {
    "

  ╭────────────────╮
  │                │
  │  NEW PROCESS   │   		
  │                │
  ╰────────────────╯	
"
    .red()
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
