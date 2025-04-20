use std::{
    env::current_dir,
    io::Write,
    mem::{self, transmute},
    os::fd::RawFd,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use crate::{
    cli::FOLLOW_FORKS,
    colors::{CONTINUED_COLOR, OUR_YELLOW, PAGES_COLOR, PID_NUMBER_COLOR},
    peeker_poker::{
        read_affinity_from_child, read_bytes_as_struct, read_one_word, read_string_specific_length,
        WORD_SIZE,
    },
    return_resolvers::{self, Readers_Writers},
    sizes::{CLONE3_ARGS_SIZE, RLIMIT_SIZE, SIGACTION_SIZE, SIGSET_SIZE, TIMESPEC_SIZE},
    syscall_object::{SyscallObject, SyscallResult},
    types::{Bytes, BytesPagesRelevant},
    utilities::{
        find_fd_for_tracee, get_array_of_strings, get_mem_difference_from_previous,
        lose_relativity_on_path, lower_32_bits, lower_64_bits, new_process, new_thread,
        parse_as_address, parse_as_bytes_pages_ceil, parse_as_file_descriptor,
        parse_as_file_descriptor_possible_dirfd, parse_as_int, parse_as_long, parse_as_signal,
        parse_as_signed_bytes, parse_as_ssize_t, parse_as_unsigned_bytes, string_from_pointer,
        REGISTERS, SYSCATEGORIES_MAP,
    },
    write_text,
    writer::{
        empty_buffer, errorize_pid_color, flush_buffer, write_anding, write_directives,
        write_exiting, write_general_text, write_oring, write_parenthesis, write_path_file,
        write_possible_dirfd_file, write_timespec, write_timespec_non_relative, write_timeval,
        write_vanilla_commas,
    },
};
use colored::{Color, ColoredString, Colorize};
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FallocateFlags},
    libc::{
        clone_args, cpu_set_t, iovec, msghdr, pid_t, rlimit, sigaction, timespec, timeval,
        AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_REMOVEDIR, AT_STATX_DONT_SYNC,
        AT_STATX_FORCE_SYNC, AT_STATX_SYNC_AS_STAT, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW,
        CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_CLEAR_SIGHAND, CLONE_FILES, CLONE_FS,
        CLONE_IO, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID,
        CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS, CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_PIDFD,
        CLONE_PTRACE, CLONE_SETTLS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_UNTRACED,
        CLONE_VFORK, CLONE_VM, EBADF, EFAULT, EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE, EINVAL,
        ENOTTY, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
        FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE, FALLOC_FL_KEEP_SIZE,
        FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_ZERO_RANGE, FUTEX_CLOCK_REALTIME,
        FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI, FUTEX_FD, FUTEX_LOCK_PI, FUTEX_LOCK_PI2,
        FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT,
        FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP,
        F_OK, GRND_NONBLOCK, GRND_RANDOM, LINUX_REBOOT_CMD_CAD_OFF, MADV_COLD, MADV_COLLAPSE,
        MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE,
        MADV_HUGEPAGE, MADV_HWPOISON, MADV_KEEPONFORK, MADV_MERGEABLE, MADV_NOHUGEPAGE,
        MADV_NORMAL, MADV_PAGEOUT, MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_RANDOM,
        MADV_REMOVE, MADV_SEQUENTIAL, MADV_SOFT_OFFLINE, MADV_UNMERGEABLE, MADV_WILLNEED,
        MADV_WIPEONFORK, MAP_ANON, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_GROWSDOWN,
        MAP_HUGETLB, MAP_HUGE_16GB, MAP_HUGE_16MB, MAP_HUGE_1GB, MAP_HUGE_1MB, MAP_HUGE_256MB,
        MAP_HUGE_2GB, MAP_HUGE_2MB, MAP_HUGE_32MB, MAP_HUGE_512KB, MAP_HUGE_512MB, MAP_HUGE_64KB,
        MAP_HUGE_8MB, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE,
        MAP_SHARED, MAP_SHARED_VALIDATE, MAP_STACK, MAP_SYNC, MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT,
        MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, MS_ASYNC, MS_INVALIDATE, MS_SYNC, O_APPEND,
        O_ASYNC, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_LARGEFILE, O_NDELAY,
        O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TMPFILE, O_TRUNC, PRIO_PGRP,
        PRIO_PROCESS, PRIO_USER, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, PTRACE_ATTACH,
        PTRACE_CONT, PTRACE_DETACH, PTRACE_GETEVENTMSG, PTRACE_GETFPREGS, PTRACE_GETFPXREGS,
        PTRACE_GETREGS, PTRACE_GETREGSET, PTRACE_GETSIGINFO, PTRACE_INTERRUPT, PTRACE_KILL,
        PTRACE_LISTEN, PTRACE_PEEKDATA, PTRACE_PEEKSIGINFO, PTRACE_PEEKTEXT, PTRACE_PEEKUSER,
        PTRACE_POKEDATA, PTRACE_POKETEXT, PTRACE_POKEUSER, PTRACE_SEIZE, PTRACE_SETFPREGS,
        PTRACE_SETFPXREGS, PTRACE_SETOPTIONS, PTRACE_SETREGS, PTRACE_SETREGSET, PTRACE_SETSIGINFO,
        PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP, PTRACE_TRACEME,
        P_ALL, P_PGID, P_PID, P_PIDFD, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT,
        RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_LOCKS,
        RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
        RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK, RUSAGE_CHILDREN,
        RUSAGE_SELF, RUSAGE_THREAD, R_OK, SA_SIGINFO, SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_HOLE,
        SEEK_SET, SFD_CLOEXEC, SFD_NONBLOCK, SIG_BLOCK, SIG_DFL, SIG_IGN, SIG_SETMASK, SIG_UNBLOCK,
        S_IRGRP, S_IROTH, S_IRUSR, S_ISGID, S_ISUID, S_ISVTX, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP,
        S_IXOTH, S_IXUSR, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WSTOPPED, W_OK, X_OK, __WALL,
        __WCLONE, __WNOTHREAD,
    },
};
use syscalls::Sysno;

impl SyscallObject {
    pub(crate) fn one_line_error(errno: nix::errno::Errno) {
        // TODO! Deprecate this logic for more granularity
        write_general_text(" |=> ");
        write_text(errno.to_string().red());
    }
    // pub(crate) fn get_syscall_return(&mut self) -> Result<String, ()> {
    //     // self.displayable_return_ol()
    // }

    pub(crate) fn handle_pause_continue(&mut self) {
        if self.paused {
            write_text(" CONTINUED ".on_custom_color(*CONTINUED_COLOR));
        }
    }
    pub(crate) fn write_pid_sysname(&mut self) {
        use crate::syscall_object::SyscallState::*;

        if *FOLLOW_FORKS {
            // multi-threaded: pid always blue
            match self.state {
                Entering => {
                    // TODO!
                    // multithreaded syscalls:
                    //  - detect when the syscall is not paused,
                    //      and handle pid coloring similar to single thread
                    //  - detect when the syscall is paused,
                    //      dim the pid color in the first split,
                    //      and apply normal red/blue for the second split
                    write_text(self.tracee_pid.to_string().custom_color(*PID_NUMBER_COLOR));

                    // Colorized Syscall Name
                    write_text(" ".dimmed());
                    let category = SYSCATEGORIES_MAP.get(&self.sysno).unwrap();
                    write_text(SyscallObject::colorize_syscall_name(&self.sysno, category));
                    write_text(" - ".dimmed());
                }
                Exiting => {
                    if self.paused {
                        // Colorized PID
                        if let SyscallResult::Fail(_) = self.result {
                            write_text(self.tracee_pid.to_string().red());
                        } else {
                            write_text(self.tracee_pid.to_string().blue());
                        }

                        // Colorized Syscall Name
                        write_text(" ".dimmed());
                        let category = SYSCATEGORIES_MAP.get(&self.sysno).unwrap();

                        write_text(
                            SyscallObject::colorize_syscall_name(&self.sysno, category).dimmed(),
                        );
                        write_text(" - ".dimmed());
                        self.handle_pause_continue();
                    }
                }
            }
        } else {
            match self.state {
                Entering => {
                    write_text(self.tracee_pid.to_string().blue());
                    // Colorized Syscall Name
                    write_text(" ".dimmed());
                    let category = SYSCATEGORIES_MAP.get(&self.sysno).unwrap();
                    write_text(SyscallObject::colorize_syscall_name(&self.sysno, category));
                    write_text(" - ".dimmed());
                }
                Exiting => {
                    // Colorized PID
                    // correct prior speculation of the syscall as successful
                    // TODO!
                    // switch to VecDeque and simply use push_front()
                    if let SyscallResult::Fail(_) = self.result {
                        errorize_pid_color(self.tracee_pid.to_string().red());
                    }
                }
            }
        }
    }

    pub(crate) fn one_line_formatter(&mut self) -> Result<(), ()> {
        use crate::syscall_object::SyscallState::*;
        self.write_pid_sysname();

        //
        // ===============
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
            Sysno::mmap => {
                let flags_num = parse_as_int(registers[3]);
                let shared = (flags_num & MAP_SHARED) == MAP_SHARED;
                let private = (flags_num & MAP_PRIVATE) == MAP_PRIVATE;
                let shared_validate = (flags_num & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE;
                let anonymous = ((flags_num & MAP_ANON) == MAP_ANON)
                    || ((flags_num & MAP_ANONYMOUS) == MAP_ANONYMOUS);
                let huge_pages_used = (flags_num & MAP_HUGETLB) == MAP_HUGETLB;
                let populate = (flags_num & MAP_POPULATE) == MAP_POPULATE;
                let lock = (flags_num & MAP_LOCKED) == MAP_LOCKED;
                let fixed = (flags_num & MAP_FIXED) == MAP_FIXED;
                let non_blocking = (flags_num & MAP_NONBLOCK) == MAP_NONBLOCK;
                let no_reserve = (flags_num & MAP_NORESERVE) == MAP_NORESERVE;
                let stack = (flags_num & MAP_STACK) == MAP_STACK;
                let sync = (flags_num & MAP_SYNC) == MAP_SYNC;

                let prot_flags = parse_as_int(registers[2]);
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);
                let fd = registers[4] as RawFd;
                let addr = registers[0] as *const ();
                let address = parse_as_address(registers[0] as usize);
                let offset_num = parse_as_long(registers[5]);
                let offset = parse_as_signed_bytes(registers[5]);

                match self.state {
                    Entering => {
                        if !anonymous {
                            write_general_text("map ");
                        } else {
                            write_general_text("allocate ");
                        }
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        // BACKED BY FILE
                        //
                        //
                        //
                        if !anonymous {
                            write_general_text(" of the file: ");
                            let filename = parse_as_file_descriptor(registers[4], self.tracee_pid);
                            write_path_file(filename);
                            if offset_num > 0 {
                                write_general_text(" at an offset of ");
                                write_text(offset.to_string().custom_color(*OUR_YELLOW));
                            }
                        }

                        write_general_text(" as ");
                        // PRIVATE VS SHARED
                        //
                        //
                        //
                        // check shared_validate first because its 0x3 (shared and private are 0x1, and 0x2)
                        if shared_validate || shared {
                            write_text("shared memory".custom_color(*OUR_YELLOW));
                        // no need to check MAP_PRIVATE,
                        // its the last option at this point
                        // and mmap will fail if its not provided
                        } else if private {
                            write_text("private copy-on-write memory".custom_color(*OUR_YELLOW));
                        }

                        // HUGE PAGES
                        //
                        //
                        //
                        if huge_pages_used {
                            write_general_text(" using ");
                            if (flags_num & MAP_HUGE_64KB) == MAP_HUGE_64KB {
                                write_text("64 KB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_512KB) == MAP_HUGE_512KB {
                                write_text("512 KB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_1MB) == MAP_HUGE_1MB {
                                write_text("1 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_2MB) == MAP_HUGE_2MB {
                                write_text("2 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_8MB) == MAP_HUGE_8MB {
                                write_text("8 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_16MB) == MAP_HUGE_16MB {
                                write_text("16 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_32MB) == MAP_HUGE_32MB {
                                write_text("32 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_256MB) == MAP_HUGE_256MB {
                                write_text("256 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_512MB) == MAP_HUGE_512MB {
                                write_text("512 MB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_1GB) == MAP_HUGE_1GB {
                                write_text("1 GB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_2GB) == MAP_HUGE_2GB {
                                write_text("2 GB ".custom_color(*OUR_YELLOW));
                            } else if (flags_num & MAP_HUGE_16GB) == MAP_HUGE_16GB {
                                write_text("16 GB ".custom_color(*OUR_YELLOW));
                            }
                            write_text("hugepages".custom_color(*OUR_YELLOW));
                        }

                        // POPULATE
                        //
                        //
                        //
                        if populate && !non_blocking {
                            write_general_text(" ");
                            write_text("and prefault it".custom_color(*OUR_YELLOW));
                            // MAP_NON_BLOCK disables MAP_POPULATE since 2.5.46
                        }

                        let mut others = vec![];
                        if lock {
                            others.push("don't swap memory".custom_color(*OUR_YELLOW));
                        }
                        if no_reserve {
                            // we trust that there will be enough swap space at any time in the future
                            // Swap space is shared by all the processes, so there can never be a guarantee that there is enough of it
                            // preallocating it (more or less) gives a guaranty that the calling process will always have enough of it
                            others.push("don't reserve swap space".custom_color(*OUR_YELLOW));
                        }

                        if stack {
                            others.push(
                                "choose an address suitable for a stack".custom_color(*OUR_YELLOW),
                            );
                        }

                        if sync && shared_validate {
                            others.push(
                                "use Direct Access (DAX) for file writes".custom_color(*OUR_YELLOW),
                            );
                        }

                        if others.len() > 0 {
                            write_general_text(" (");
                            write_vanilla_commas(others);
                            write_general_text(")");
                        }

                        // ADDRESS
                        //
                        //
                        //
                        if addr.is_null() {
                            write_general_text(" at ");
                            write_text(
                                "an appropiate kernel chosen address".custom_color(*OUR_YELLOW),
                            );
                        } else if (flags_num & MAP_FIXED) == MAP_FIXED {
                            write_general_text(" starting ");
                            write_text("exactly at ".custom_color(*OUR_YELLOW));
                            write_text(address.custom_color(*OUR_YELLOW));
                        } else if (flags_num & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE {
                            write_general_text(" starting ");
                            write_text("exactly at ".custom_color(*OUR_YELLOW));
                            write_text(address.custom_color(*OUR_YELLOW));
                            write_text(
                                " and fail if a mapping already exists ".custom_color(*OUR_YELLOW),
                            );
                        } else {
                            write_general_text(" starting ");
                            write_text("around ".custom_color(*OUR_YELLOW));
                            write_text(address.custom_color(*OUR_YELLOW));
                        }

                        // MEMORY DIRECTION
                        //
                        //
                        //
                        if (flags_num & MAP_GROWSDOWN) == MAP_GROWSDOWN {
                            write_text(" growing down,".custom_color(*OUR_YELLOW));
                        }

                        // PROTECTION
                        //
                        //
                        //

                        let mut flags = vec![];
                        if (prot_flags & PROT_READ) == PROT_READ {
                            flags.push("reading".custom_color(*OUR_YELLOW));
                        }
                        if (prot_flags & PROT_WRITE) == PROT_WRITE {
                            flags.push("writing".custom_color(*OUR_YELLOW));
                        }
                        if (prot_flags & PROT_EXEC) == PROT_EXEC {
                            flags.push("execution".custom_color(*OUR_YELLOW));
                        }
                        if flags.is_empty() {
                            // TODO! guard pages note should be improved
                            write_text(" without protection (".custom_color(*OUR_YELLOW));
                            write_text("Guard Pages".custom_color(*PAGES_COLOR));
                            write_text(")".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text(" and allow ");
                            write_vanilla_commas(flags);
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("new mapping address: ".green());
                                let address = parse_as_address(syscall_return as usize);
                                write_text(address.custom_color(*OUR_YELLOW));
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
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }

            Sysno::brk => {
                let brk_address = registers[0];
                match self.state {
                    Entering => {
                        if brk_address == 0 {
                            write_general_text("get the current program break");
                        } else {
                            write_general_text("change program break to ");
                            let syscall_brk = parse_as_address(registers[0] as usize);
                            write_text(syscall_brk.custom_color(*OUR_YELLOW));
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            if brk_address == 0 {
                                write_text("current program break: ".green());
                                let address = parse_as_address(syscall_return as usize);
                                write_text(address.custom_color(*OUR_YELLOW));
                            } else {
                                let new_brk = syscall_return;
                                let mem_difference = get_mem_difference_from_previous(new_brk as _);
                                let mem_difference_bytes =
                                    BytesPagesRelevant::from_ceil(mem_difference as usize);
                                if mem_difference == 0 {
                                    write_general_text("no allocation or deallocation occured");
                                } else if mem_difference > 0 {
                                    write_general_text("allocated ");
                                    write_text(
                                        mem_difference_bytes.to_string().custom_color(*PAGES_COLOR),
                                    );
                                } else {
                                    write_general_text("deallocated ");
                                    write_text(
                                        mem_difference_bytes.to_string().custom_color(*PAGES_COLOR),
                                    );
                                }
                                write_text(", new program break: ".green());
                                write_text(
                                    parse_as_address(new_brk as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::close => match self.state {
                Entering => {
                    write_general_text("close the file: ");
                    let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                    write_path_file(filename);
                }
                Exiting => match self.result {
                    SyscallResult::Success(syscall_return) => {
                        write_general_text(" |=> ");
                        write_text("file closed".green());
                    }
                    SyscallResult::Fail(errno) => {
                        // TODO! granular
                        SyscallObject::one_line_error(errno);
                    }
                },
            },
            Sysno::open => {
                match self.state {
                    Entering => {
                        let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                        // TODO!
                        //
                        // fix open flags granularity
                        // also fix file mode granularity
                        write_general_text("open the file ");
                        write_path_file(filename);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successfully opened file".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }

            Sysno::stat => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get the stats of the file: ");
                        write_path_file(filename);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::fstat => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get the stats of the file: ");
                        write_path_file(filename);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::lstat => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get the stats of the file: ");
                        write_path_file(filename);
                        write_general_text(" and do not recurse symbolic links");
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::statfs => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get stats for the filesystem mounted in: ");
                        write_path_file(filename);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::fstatfs => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get stats for the filesystem that contains the file: ");
                        write_path_file(filename);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::newfstatat => {
                let dirfd = parse_as_int(registers[0]);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let flags = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("get the stats of the file: ");
                        write_possible_dirfd_file(dirfd as i32, filename, self.tracee_pid);
                        let mut flag_directive = vec![];
                        if (flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_EACCESS) == AT_EACCESS {
                            flag_directive.push(
                                "check using effective user & group ids".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_SYMLINK_FOLLOW) == AT_SYMLINK_FOLLOW {
                            flag_directive
                                .push("recurse symbolic links if found".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_NO_AUTOMOUNT) == AT_NO_AUTOMOUNT {
                            flag_directive.push("don't automount the basename of the path if its an automount directory".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if flag_directive.len() > 0 {
                            write_general_text(" (");
                            let mut flag_directive_iter = flag_directive.into_iter().peekable();
                            if flag_directive_iter.peek().is_some() {
                                write_text(flag_directive_iter.next().unwrap());
                            }
                            for entry in flag_directive_iter {
                                write_general_text(", ");
                                write_text(entry);
                            }
                            write_general_text(")");
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::statx => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let pathname = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let flags = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("get the stats of the file: ");
                        if pathname.starts_with('/') {
                            // absolute pathname
                            // dirfd is ignored
                            write_path_file(pathname);
                        } else {
                            if pathname.is_empty() && (flags & AT_EMPTY_PATH) > 0 {
                                // the pathname is empty
                                let dirfd_parsed =
                                    parse_as_file_descriptor(registers[0], self.tracee_pid);
                                // if pathname is empty and AT_EMPTY_PATH is given, dirfd is used
                                write_path_file(dirfd_parsed);
                            } else {
                                // A relative pathname, dirfd = CWD, or a normal directory
                                write_possible_dirfd_file(dirfd, pathname, self.tracee_pid);
                            }
                        }
                        let mut flag_directive = vec![];
                        if (flags & AT_NO_AUTOMOUNT) == AT_NO_AUTOMOUNT {
                            flag_directive.push("don't automount the basename of the path if its an automount directory".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW {
                            flag_directive.push(
                                "if the path is a symbolic link, get its stats, do not recurse it"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if flags == AT_STATX_SYNC_AS_STAT {
                            flag_directive.push(
                                "behave similar to the `stat` syscall".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_STATX_FORCE_SYNC) == AT_STATX_FORCE_SYNC {
                            flag_directive.push(
                                "force synchronization / guarantee up to date information"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_STATX_DONT_SYNC) == AT_STATX_DONT_SYNC {
                            flag_directive.push("don't force synchronization / retrieve whatever information is cached".custom_color(*OUR_YELLOW));
                        }
                        // if flags.contains(rustix::fs::AtFlags::EACCESS) {
                        //     flag_directive.push("check using effective user & group ids".custom_color(*OUR_YELLOW));
                        // }
                        // if flags.contains(rustix::fs::AtFlags::SYMLINK_FOLLOW) {
                        //     flag_directive.push("recurse symbolic links if found".custom_color(*OUR_YELLOW));
                        // }
                        write_directives(flag_directive);

                        // TODO!
                        // unnecessary information
                        // statx_mask is currently unhandled because it's unnecessary information
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("stats retrieved successfully".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::chown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = lower_32_bits(registers[1]);
                let group_given = lower_32_bits(registers[2]);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        // https://github.com/torvalds/linux/blob/cfb2e2c57aef75a414c0f18445c7441df5bc13be/fs/open.c#L768C1-L768C2
                        if owner_given != u32::MAX {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.to_str().unwrap();
                            write_general_text("change the owner of ");
                            write_path_file(filename);
                            write_general_text(" to ");
                            write_text(owner.green());
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text(", and its group to ");
                                write_text(group.green());
                            }
                        } else {
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text("change the group of the file: ");
                                write_path_file(filename);
                                write_general_text("to ");
                                write_text(group.green());
                            } else {
                                write_general_text(
                                    "[intentrace: redundant syscall (won't do anything)]",
                                );
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            // TODO!
                            // unnecessary details, consider removing
                            if owner_given != u32::MAX {
                                write_text("ownership".green());
                                if group_given != u32::MAX {
                                    write_text(" and group".green());
                                }
                                write_text(" changed".green());
                            } else {
                                if group_given != u32::MAX {
                                    write_text("group changed".green());
                                } else {
                                    write_text("successful".green());
                                }
                            }
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::fchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = lower_32_bits(registers[1]);
                let group_given = lower_32_bits(registers[2]);
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        // https://github.com/torvalds/linux/blob/cfb2e2c57aef75a414c0f18445c7441df5bc13be/fs/open.c#L768C1-L768C2
                        if owner_given != u32::MAX {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.to_str().unwrap();
                            write_general_text("change the owner of ");
                            write_path_file(filename);
                            write_general_text(" to ");
                            write_text(owner.green());
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text(", and its group to ");
                                write_text(group.green());
                            }
                        } else {
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text("change the group of the file: ");
                                write_path_file(filename);
                                write_general_text("to ");
                                write_text(group.green());
                            } else {
                                write_general_text(
                                    "[intentrace: redundant syscall (won't do anything)]",
                                );
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            // TODO!
                            // unnecessary details, consider removing
                            if owner_given != u32::MAX {
                                write_text("ownership".green());
                                if group_given != u32::MAX {
                                    write_text(" and group".green());
                                }
                                write_text(" changed".green());
                            } else {
                                if group_given != u32::MAX {
                                    write_text("group changed".green());
                                } else {
                                    write_text("successful".green());
                                }
                            }
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::lchown => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let owner_given = lower_32_bits(registers[1]);
                let group_given = lower_32_bits(registers[2]);
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        // https://github.com/torvalds/linux/blob/cfb2e2c57aef75a414c0f18445c7441df5bc13be/fs/open.c#L768C1-L768C2
                        if owner_given != u32::MAX {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.to_str().unwrap();
                            write_general_text("change the owner of ");
                            write_path_file(filename);
                            write_general_text(" to ");
                            write_text(owner.green());
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text(", and its group to ");
                                write_text(group.green());
                            }
                            write_general_text(" (");
                            write_text("don't recurse symbolic links".custom_color(*OUR_YELLOW));
                            write_general_text(")");
                        } else {
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text("change the group of the file: ");
                                write_path_file(filename);
                                write_general_text("to ");
                                write_text(group.green());
                                write_general_text(" (");
                                write_text(
                                    "don't recurse symbolic links".custom_color(*OUR_YELLOW),
                                );
                                write_general_text(")");
                            } else {
                                write_general_text(
                                    "[intentrace: redundant syscall (won't do anything)]",
                                );
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            // TODO!
                            // unnecessary details, consider removing
                            if owner_given != u32::MAX {
                                write_text("ownership".green());
                                if group_given != u32::MAX {
                                    write_text(" and group".green());
                                }
                                write_text(" changed".green());
                            } else {
                                if group_given != u32::MAX {
                                    write_text("group changed".green());
                                } else {
                                    write_text("successful".green());
                                }
                            }
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::fchownat => {
                use uzers::{Groups, Users, UsersCache};
                let mut cache = UsersCache::new();
                let dirfd = parse_as_int(registers[0]);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let owner_given = lower_32_bits(registers[2]);
                let group_given = lower_32_bits(registers[3]);
                let flags = parse_as_int(registers[4]);

                match self.state {
                    Entering => {
                        let flags_check = || {
                            let mut flag_directive = vec![];
                            if (flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW {
                                flag_directive.push(
                                    "operate on the symbolic link if found, do not recurse it"
                                        .custom_color(*OUR_YELLOW),
                                );
                            }
                            if (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH {
                                flag_directive.push(
                                    "operate on the anchor directory if pathname is empty"
                                        .custom_color(*OUR_YELLOW),
                                );
                            }
                            write_directives(flag_directive);
                        };
                        if owner_given != u32::MAX {
                            let get_user_by_uid = cache.get_user_by_uid(owner_given as _);
                            let user = get_user_by_uid.unwrap();
                            let name = user.name();
                            let owner = name.to_str().unwrap();
                            write_general_text("change the owner of ");
                            write_possible_dirfd_file(dirfd, filename, self.tracee_pid);
                            write_general_text(" to ");
                            write_text(owner.green());
                            if group_given != u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text(", and its group to ");
                                write_text(group.green());
                            }
                            flags_check();
                        } else {
                            if group_given == u32::MAX {
                                let get_user_by_uid = cache.get_user_by_uid(group_given as _);
                                let user = get_user_by_uid.unwrap();
                                let group = user.name().to_str().unwrap();
                                write_general_text("change the group of the file: ");
                                write_path_file(filename);
                                write_general_text("to ");
                                write_text(group.green());
                                flags_check();
                            } else {
                                write_general_text(
                                    "[intentrace: redundant syscall (won't do anything)]",
                                );
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            // TODO!
                            // unnecessary details, consider removing
                            if owner_given != u32::MAX {
                                write_text("ownership".green());
                                if group_given != u32::MAX {
                                    write_text(" and group".green());
                                }
                                write_text(" changed".green());
                            } else {
                                if group_given != u32::MAX {
                                    write_text("group changed".green());
                                } else {
                                    write_text("successful".green());
                                }
                            }
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::madvise => {
                // addr, len, adv
                let len = parse_as_bytes_pages_ceil(registers[1] as usize);
                let address = parse_as_address(registers[0] as usize);
                let advice = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        match advice {
                            MADV_NORMAL => {
                                write_general_text("provide default treatment for ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }

                            MADV_RANDOM => {
                                write_general_text("expect ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be referenced in random order");
                            }
                            MADV_SEQUENTIAL => {
                                write_general_text("expect ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be referenced in sequential order");
                            }
                            MADV_WILLNEED => {
                                write_general_text("expect ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be accessed in the future");
                            }
                            MADV_DONTNEED => {
                                write_text("do not expect the".custom_color(*OUR_YELLOW));
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be accessed in the future");
                            }
                            MADV_REMOVE => {
                                // equivalent to punching a hole in the corresponding range
                                write_general_text("free");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_DONTFORK => {
                                write_general_text("do not allow ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be available to children from ");
                                write_text("fork()".blue());
                            }
                            MADV_DOFORK => {
                                write_general_text("allow ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to be available to children from ");
                                write_text("fork()".blue());
                                write_general_text(" ");
                                write_text("(Undo MADV_DONTFORK)".custom_color(*OUR_YELLOW));
                            }
                            MADV_HWPOISON => {
                                // treat subsequent references to those pages like a hardware memory corruption
                                write_general_text("poison ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_MERGEABLE => {
                                // KSM merges only private anonymous pages
                                write_general_text("enable KSM (Kernel Samepage Merging) for ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_UNMERGEABLE => {
                                write_general_text(
                                    "unmerge all previous KSM merges from MADV_MERGEABLE in ",
                                );
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_SOFT_OFFLINE => {
                                write_text("migrate".custom_color(*OUR_YELLOW));
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(
                                    " to new healthy pages (soft-offline the memory)",
                                );
                            }
                            MADV_HUGEPAGE => {
                                write_text("enable".custom_color(*OUR_YELLOW));
                                write_general_text(" transparent huge pages (THP) on ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_NOHUGEPAGE => {
                                write_text("disable".custom_color(*OUR_YELLOW));
                                write_general_text(" transparent huge pages (THP) on ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_COLLAPSE => {
                                // TODO!
                                // citation needed
                                write_general_text("perform a synchronous collapse of ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(
                                    " that's mapped into transparent huge pages (THP)",
                                );
                            }
                            MADV_DONTDUMP => {
                                write_general_text("exclude ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" from core dumps");
                            }
                            MADV_DODUMP => {
                                write_general_text("include ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" in core dumps ");
                                write_text("(Undo MADV_DONTDUMP)".custom_color(*OUR_YELLOW));
                            }
                            MADV_FREE => {
                                write_general_text("mark ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" as no longer required and ok to free");
                            }
                            MADV_WIPEONFORK => {
                                write_general_text("zero-fill the range of ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to any child from ");
                                write_text("fork()".blue());
                            }
                            MADV_KEEPONFORK => {
                                write_general_text("keep the range of ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" to any child from ");
                                write_text("fork()".blue());
                                write_general_text(" ");
                                write_text("(Undo MADV_WIPEONFORK)".custom_color(*OUR_YELLOW));
                            }
                            MADV_COLD => {
                                // This makes the pages a more probable reclaim target during memory pressure
                                write_general_text("deactivate ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text("  (make more probable to reclaim)");
                            }
                            MADV_PAGEOUT => {
                                // This is done to free up memory occupied by these pages.
                                // If a page is anonymous, it will be swapped out.
                                // If a page  is  file-backed and dirty, it will be written back to the backing storage
                                write_general_text("page out ");
                                // "page out" is more intuitive, "reclaim"sleading
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                            }
                            MADV_POPULATE_READ => {
                                write_general_text("prefault ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" while avoiding memory access ");
                                write_text("(simulate reading)".custom_color(*OUR_YELLOW));
                            }
                            MADV_POPULATE_WRITE => {
                                write_general_text("prefault ");
                                write_text(len.custom_color(*OUR_YELLOW));
                                write_general_text(" of memory starting from ");
                                write_text(address.custom_color(*OUR_YELLOW));
                                write_general_text(" while avoiding memory access ");
                                write_text("(simulate writing)".custom_color(*OUR_YELLOW));
                            }
                            unknown_flag => {
                                write_general_text("[intentrace: unknown madvise flag]")
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory advice registered".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::munmap => {
                let address = parse_as_address(registers[0] as usize);
                let len = parse_as_bytes_pages_ceil(registers[1] as usize);
                match self.state {
                    Entering => {
                        write_general_text("unmap ");
                        write_text(len.custom_color(*OUR_YELLOW));
                        write_general_text(" from memory starting at ");
                        write_text(address.custom_color(*OUR_YELLOW));
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successfully unmapped region".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::msync => {
                let address = parse_as_address(registers[0] as usize);
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);
                let flags = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("flush all changes made on ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" of memory starting from ");
                        write_text(address.custom_color(*OUR_YELLOW));
                        write_general_text(" back to the filesystem");
                        if (flags & MS_SYNC) == MS_SYNC {
                            write_general_text(" (");
                            write_text("block until completion".custom_color(*OUR_YELLOW));
                        } else if (flags & MS_ASYNC) == MS_ASYNC {
                            write_general_text(" (");
                            write_text(
                                "schedule the update, but return immediately"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & MS_INVALIDATE) == MS_INVALIDATE {
                            // this is used to propagate
                            write_general_text(" (");
                            write_text(
                                ", and invalidate other mappings of the file to propagate these changes"
                                    .custom_color(*OUR_YELLOW),
                            );
                            write_general_text(")");
                        } else {
                            write_general_text(")");
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successfully flushed data".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mprotect => {
                let address = parse_as_address(registers[0] as usize);
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);
                let prot_flags = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        // PROTECTION
                        //
                        //
                        //
                        if prot_flags == PROT_NONE {
                            // Guard pages for buffer overflows
                            // ... allocation of additional inaccessible memory during memory allocation operations
                            // is a technique for mitigating against exploitation of heap buffer overflows.
                            // These guard pages are unmapped pages placed between all memory allocations
                            // of one page or larger. The guard page causes a segmentation fault upon any access.
                            write_general_text("prevent ");
                            write_text("all access".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text("allow ");
                            let mut flags = vec![];
                            if (prot_flags & PROT_READ) == PROT_READ {
                                flags.push("reading".custom_color(*OUR_YELLOW))
                            }
                            if (prot_flags & PROT_WRITE) == PROT_WRITE {
                                flags.push("writing".custom_color(*OUR_YELLOW))
                            }
                            if (prot_flags & PROT_EXEC) == PROT_EXEC {
                                flags.push("execution".custom_color(*OUR_YELLOW))
                            }
                            write_vanilla_commas(flags);
                        }
                        // AMOUNT OF BYTES
                        //
                        //
                        //
                        write_general_text(" on ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" of memory ");
                        // ADDRESS
                        //
                        //
                        //
                        write_general_text("starting from ");
                        write_text(address.custom_color(*OUR_YELLOW));
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory protection modified".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::lseek => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let offset_num = parse_as_long(registers[1]);
                let offset = parse_as_signed_bytes(registers[1]);
                let whence = parse_as_int(registers[2]);

                match self.state {
                    Entering => {
                        match whence {
                            SEEK_SET => {
                                if offset_num == 0 {
                                    write_general_text("move the file pointer of the file: ");
                                    write_path_file(filename);
                                    write_general_text(" to ");
                                    write_text(
                                        "the beginning of the file".custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                    write_text(
                                        "from the beginning of the file".custom_color(*OUR_YELLOW),
                                    );
                                }
                            }
                            SEEK_CUR => {
                                write_general_text("move the file pointer of the file: ");
                                write_path_file(filename);
                                write_general_text(" ");
                                if offset_num == 0 {
                                    // write_general_text.push("[intentrace: redundant syscall (won't do anything)]");

                                    write_general_text("to ");
                                    write_text(
                                        "the current file pointer".custom_color(*OUR_YELLOW),
                                    );
                                } else if offset_num > 0 {
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                    write_text(" forwards".custom_color(*OUR_YELLOW));
                                } else {
                                    write_text((&offset[1..]).custom_color(*OUR_YELLOW));
                                    write_text(" backwards".custom_color(*OUR_YELLOW));
                                }
                            }
                            SEEK_END => {
                                write_general_text("move the file pointer of the file: ");
                                write_path_file(filename);
                                write_general_text(" ");

                                if offset_num == 0 {
                                    write_general_text("to ");
                                    write_text("the end of the file".custom_color(*OUR_YELLOW));
                                } else if offset_num > 0 {
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                    write_general_text(" after ");
                                    write_text("the end of the file".custom_color(*OUR_YELLOW));
                                } else {
                                    write_text((&offset[1..]).custom_color(*OUR_YELLOW));
                                    write_general_text(" before ");
                                    write_text("the end of the file".custom_color(*OUR_YELLOW));
                                }
                            }
                            SEEK_DATA => {
                                write_general_text("move the file pointer of the file: ");
                                write_path_file(filename);
                                write_general_text(" to ");
                                write_text("the nearest data block".custom_color(*OUR_YELLOW));
                                write_general_text(" you find ");
                                if offset_num == 0 {
                                    write_text(
                                        "at the beginning of the file".custom_color(*OUR_YELLOW),
                                    );
                                } else if offset_num > 0 {
                                    write_text("after ".custom_color(*OUR_YELLOW));
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                } else {
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                    // this should be an error
                                    write_text(
                                        " before the beginning of the file "
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                            }
                            SEEK_HOLE => {
                                write_general_text("move the file pointer of the file: ");
                                write_path_file(filename);
                                write_general_text(" to ");
                                write_text("the nearest data hole".custom_color(*OUR_YELLOW));
                                write_general_text(" you find ");
                                if offset_num == 0 {
                                    write_text(
                                        "at the beginning of the file".custom_color(*OUR_YELLOW),
                                    );
                                } else if offset_num > 0 {
                                    write_text("after ".custom_color(*OUR_YELLOW));
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                } else {
                                    write_text(offset.custom_color(*OUR_YELLOW));
                                    // TODO! test this
                                    write_text(
                                        " before the beginning of the file "
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("new offset location: ".green());
                            let offset = parse_as_signed_bytes(syscall_return);
                            write_text(offset.blue());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mlock => {
                let address = parse_as_address(registers[0] as usize);
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);
                match self.state {
                    Entering => {
                        write_general_text("prevent swapping of memory on ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" starting from: ");
                        write_text(address.custom_color(*OUR_YELLOW));
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory range is now unswappable".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mlock2 => {
                let address = parse_as_address(registers[0] as usize);
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);
                let bytes_num = registers[1];
                let flags = registers[2];
                match self.state {
                    Entering => {
                        write_general_text("prevent swapping of memory on ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" starting from: ");
                        write_text(address.custom_color(*OUR_YELLOW));

                        // 1 = MLOCK_ONFAULT
                        if (flags & 1) == 1 {
                            write_general_text(" (");
                            // this allow non-resident pages to get locked later when they are faulted
                            write_text("only lock resident-pages, only lock non-resident pages once they're faulted".custom_color(*OUR_YELLOW));
                            write_general_text(")");
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory range is now unswappable".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::munlock => {
                let address = parse_as_address(registers[0] as usize);
                let bytes_num = registers[1];
                let bytes = parse_as_bytes_pages_ceil(registers[1] as usize);

                match self.state {
                    Entering => {
                        write_general_text("allow swapping of memory on ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" starting from: ");
                        write_text(address.custom_color(*OUR_YELLOW));
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory range is now swappable".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::munlockall => {
                match self.state {
                    Entering => {
                        write_general_text(
                            "allow the entire memory of the calling process to be swappable",
                        );
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory range is now swappable".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mremap => {
                // TODO! current mremap logic is not good and needs rewriting
                let old_address_num = registers[0];
                let old_address = parse_as_address(registers[0] as usize);
                let old_len_num = registers[1];
                let old_len = parse_as_bytes_pages_ceil(registers[1] as usize);
                let new_len_num = registers[2];
                let new_len = parse_as_bytes_pages_ceil(registers[2] as usize);
                let flags = parse_as_int(registers[0]);
                let new_address_num = registers[4];
                let new_address = parse_as_address(registers[4] as usize);
                match self.state {
                    Entering => {
                        if new_len_num > old_len_num {
                            write_general_text("expand the memory region of ");
                            write_text(old_len.custom_color(*OUR_YELLOW));
                            write_text(" starting from: ".custom_color(*OUR_YELLOW));
                            write_text(old_address.custom_color(*OUR_YELLOW));
                        } else if new_len_num < old_len_num {
                            write_general_text("shrink the memory region of ");
                            write_text(old_len.custom_color(*OUR_YELLOW));
                            write_text(" starting from: ".custom_color(*OUR_YELLOW));
                            write_text(old_address.custom_color(*OUR_YELLOW));
                        } else if new_len_num == old_len_num {
                            if old_address_num == new_address_num {
                                write_text("[intentrace Notice: syscall no-op]".blink());
                            } else {
                                write_general_text("move the memory region of ");
                                write_text(old_len.custom_color(*OUR_YELLOW));
                                write_text(" starting from: ".custom_color(*OUR_YELLOW));
                                write_text(old_address.custom_color(*OUR_YELLOW));
                            }
                        }
                        if (flags & MREMAP_FIXED) == MREMAP_FIXED
                            && (flags & MREMAP_MAYMOVE) == MREMAP_MAYMOVE
                        {
                            write_general_text(" (");
                            write_text("move the mapping to ".custom_color(*OUR_YELLOW));
                            write_text(new_address.custom_color(*OUR_YELLOW));
                            write_text(
                                " and unmap any previous mapping if found"
                                    .custom_color(*OUR_YELLOW),
                            );
                            write_general_text(")");
                        } else if (flags & MREMAP_MAYMOVE) == MREMAP_MAYMOVE {
                            write_general_text(" (");
                            write_text("move the mapping to a different address if you can not expand at current address".custom_color(*OUR_YELLOW));
                            write_general_text(")");
                        } else if (flags & MREMAP_DONTUNMAP) == MREMAP_DONTUNMAP
                            && (flags & MREMAP_MAYMOVE) == MREMAP_MAYMOVE
                        {
                            // can be used only with private anonymous mappings
                            // while it doesnt unmap the previous mapping, any access to it will result in a page fault.
                            write_general_text(" (");
                            write_text("don't unmap the previous range".custom_color(*OUR_YELLOW));
                            write_general_text(")");
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successful".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mincore => {
                // TODO! current mremap logic is not good and needs rewriting
                let address_num = registers[0];
                let address = parse_as_address(registers[0] as usize);
                let length_num = registers[1];
                let length = parse_as_bytes_pages_ceil(registers[1] as usize);

                match self.state {
                    Entering => {
                        write_general_text("populate a vector of bytes representing ");
                        write_text(length.custom_color(*OUR_YELLOW));
                        write_text(
                            " of the process's memory starting from: ".custom_color(*OUR_YELLOW),
                        );
                        write_text(address.custom_color(*OUR_YELLOW));
                        write_general_text(
                            " indicating resident and non-resident pages in each byte",
                        );
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successful".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::mlockall => {
                let flags_num = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("prevent swapping of ");

                        match (
                            (flags_num & MCL_CURRENT) == MCL_CURRENT,
                            (flags_num & MCL_FUTURE) == MCL_FUTURE,
                        ) {
                            (true, true) => {
                                write_text(
                                    "all current and future mapped pages".custom_color(*OUR_YELLOW),
                                );
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    write_general_text(" (only lock resident-pages for current and future mappings, lock non-resident pages whenever they're faulted)");
                                }
                            }
                            (true, false) => {
                                write_text("all currently mapped pages".custom_color(*OUR_YELLOW));
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    write_general_text(" (only lock currently resident-pages, only lock non-resident pages once they're faulted)");
                                }
                            }
                            (false, true) => {
                                write_text("all future mapped pages ".custom_color(*OUR_YELLOW));
                                if (flags_num & MCL_ONFAULT) == MCL_ONFAULT {
                                    // this allow non-resident pages to get locked later when they are faulted
                                    write_general_text(" (do not lock future pages the moment they're mapped, only lock whenever they're faulted)");
                                }
                            }
                            (false, false) => {
                                // println!("{flags:?}");
                            }
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("memory range is now unswappable".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::read => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let bytes_to_read = registers[2];
                let bytes = parse_as_unsigned_bytes(registers[2]);

                match self.state {
                    Entering => {
                        write_general_text("read ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" from the file: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // parse syscall_return per type similar to args (on demand)
                                // ssize_t (read's return type) is i64
                                write_general_text(" |=> ");
                                // no need to convert to isize here
                                let bytes = syscall_return;
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                if bytes == 0 {
                                    write_text("read ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (end of file)".green());
                                } else if bytes < bytes_to_read {
                                    write_text("read ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (fewer than requested)".green());
                                } else {
                                    write_text("read all ".green());
                                    write_text(bytes_to_read.to_string().custom_color(*OUR_YELLOW));
                                    write_text(" Bytes".custom_color(*OUR_YELLOW));
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::write => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let bytes_to_read = registers[2];
                let bytes_to_write = registers[2];
                match self.state {
                    Entering => {
                        write_general_text("write ");
                        write_text(parse_as_unsigned_bytes(registers[2]).custom_color(*OUR_YELLOW));
                        write_general_text(" into the file: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                let bytes_num = parse_as_ssize_t(syscall_return as usize);
                                write_general_text(" |=> ");
                                // TODO!
                                // scrutinize
                                // the reason casting bytes_to_write from usize to isize here isnt troublesome
                                // is because linux limits the read write limits to PTRDIFF_MAX
                                // which is equal to isize::MAX anyways
                                if bytes_num < parse_as_ssize_t(bytes_to_write as usize) {
                                    write_text("wrote ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (fewer than requested)".green());
                                } else {
                                    write_text("wrote all ".green());
                                    write_text(
                                        bytes_to_write.to_string().custom_color(*OUR_YELLOW),
                                    );
                                    write_text(" Bytes".custom_color(*OUR_YELLOW));
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pread64 => {
                let bytes = parse_as_unsigned_bytes(registers[2]);
                let bytes_to_read = registers[2];
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let offset = parse_as_signed_bytes(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("read ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" from the file: ");
                        write_path_file(filename);
                        write_general_text(" at an offset of ");
                        write_text(offset.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                // no need to convert to isize here
                                let bytes = syscall_return;
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                if bytes == 0 {
                                    write_text("read ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (end of file)".green());
                                } else if bytes < bytes_to_read {
                                    write_text("read ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (fewer than requested)".green());
                                } else {
                                    write_text("read all ".green());
                                    write_text(bytes_to_read.to_string().custom_color(*OUR_YELLOW));
                                    write_text(" Bytes".custom_color(*OUR_YELLOW));
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pwrite64 => {
                let bytes = parse_as_unsigned_bytes(registers[3]);
                let bytes_to_write = registers[2];
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let offset = parse_as_signed_bytes(registers[3]);

                match self.state {
                    Entering => {
                        write_general_text("write ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" into the file: ");
                        write_path_file(filename);
                        write_general_text(" at an offset of ");
                        write_text(offset.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                let bytes_num = parse_as_ssize_t(syscall_return as usize);
                                write_general_text(" |=> ");
                                // TODO!
                                // scrutinize
                                // the reason casting bytes_to_write from usize to isize here isnt troublesome
                                // is because linux limits the read write limits to PTRDIFF_MAX
                                // which is equal to isize::MAX anyways
                                if bytes_num < parse_as_ssize_t(bytes_to_write as usize) {
                                    write_text("wrote ".green());
                                    write_text(bytes_string.custom_color(*OUR_YELLOW));
                                    write_text(" (fewer than requested)".green());
                                } else {
                                    write_text("wrote all ".green());
                                    write_text(
                                        bytes_to_write.to_string().custom_color(*OUR_YELLOW),
                                    );
                                    write_text(" Bytes".custom_color(*OUR_YELLOW));
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::readv => {
                let number_of_iovecs = registers[2];
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("read from ");
                        write_text(number_of_iovecs.to_string().custom_color(*OUR_YELLOW));
                        if number_of_iovecs == 1 {
                            write_general_text(" region of memory from the file: ");
                        } else {
                            write_general_text(" scattered regions of memory from the file: ");
                        }
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                write_general_text(" |=> ");
                                write_text("read ".green());
                                write_text(bytes_string.custom_color(*OUR_YELLOW));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::writev => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let number_of_iovecs = registers[2];

                match self.state {
                    Entering => {
                        write_general_text("write into ");
                        write_text(number_of_iovecs.to_string().custom_color(*OUR_YELLOW));
                        if number_of_iovecs == 1 {
                            write_general_text(" region of memory of the file: ");
                        } else {
                            write_general_text(" scattered regions of memory of the file: ");
                        }
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                write_general_text(" |=> ");
                                write_text("wrote ".green());
                                write_text(bytes_string.custom_color(*OUR_YELLOW));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::preadv => {
                let number_of_iovecs = registers[2];
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let offset = parse_as_signed_bytes(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("read from ");
                        write_text(number_of_iovecs.to_string().custom_color(*OUR_YELLOW));
                        if number_of_iovecs == 1 {
                            write_general_text(" region of memory from the file: ");
                        } else {
                            write_general_text(" scattered regions of memory from the file: ");
                        }
                        write_path_file(filename);
                        write_general_text(" at an offset of ");
                        write_text(offset.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                write_general_text(" |=> ");
                                write_text("read ".green());
                                write_text(bytes_string.custom_color(*OUR_YELLOW));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pwritev => {
                let number_of_iovecs = registers[2];
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let offset = parse_as_signed_bytes(registers[3]);

                match self.state {
                    Entering => {
                        write_general_text("write into ");
                        write_text(number_of_iovecs.to_string().custom_color(*OUR_YELLOW));
                        if number_of_iovecs == 1 {
                            write_general_text(" region of memory of the file: ");
                        } else {
                            write_general_text(" scattered regions of memory of the file: ");
                        }
                        write_path_file(filename);
                        write_general_text(" at an offset of ");
                        write_text(offset.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_string = Readers_Writers::parse_return(syscall_return);
                                write_general_text(" |=> ");
                                write_text("wrote ".green());
                                write_text(bytes_string.custom_color(*OUR_YELLOW));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pipe => {
                match self.state {
                    Entering => {
                        write_general_text("create a pipe for inter-process communication");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                match read_one_word(registers[0] as usize, self.tracee_pid) {
                                    Some(pipe_fds) => {
                                        write_text("created the pipe".green());
                                        // TODO!
                                        // this errors with NotFound
                                        // commented for now
                                        //
                                        // write_text("created the pipe: ".green());
                                        // let pipes: [i32; 2] = unsafe {
                                        //     std::mem::transmute::<usize, [i32; 2]>(pipe_fds)
                                        // };
                                        // write_text("read end: ".custom_color(*OUR_YELLOW));
                                        // write_text(
                                        //     parse_as_file_descriptor(
                                        //         pipes[0] as u64,
                                        //         self.tracee_pid,
                                        //     )
                                        //     .custom_color(*PAGES_COLOR),
                                        // );
                                        // write_text(", write end: ".custom_color(*OUR_YELLOW));
                                        // write_text(
                                        //     parse_as_file_descriptor(
                                        //         pipes[1] as u64,
                                        //         self.tracee_pid,
                                        //     )
                                        //     .custom_color(*PAGES_COLOR),
                                        // );
                                    }
                                    None => write_text("created the pipe".green()),
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pipe2 => {
                let flags = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        write_general_text("create a pipe for inter-process communication");
                        // TODO!
                        // open flags granularity
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                match read_one_word(registers[0] as usize, self.tracee_pid) {
                                    Some(pipe_fds) => {
                                        write_text("created the pipe: ".green());
                                        let pipes: [i32; 2] = unsafe {
                                            std::mem::transmute::<usize, [i32; 2]>(pipe_fds)
                                        };
                                        write_text("read end: ".custom_color(*OUR_YELLOW));
                                        write_text(
                                            parse_as_file_descriptor(
                                                pipes[0] as u64,
                                                self.tracee_pid,
                                            )
                                            .custom_color(*PAGES_COLOR),
                                        );
                                        write_text(", write end: ".custom_color(*OUR_YELLOW));
                                        write_text(
                                            parse_as_file_descriptor(
                                                pipes[1] as u64,
                                                self.tracee_pid,
                                            )
                                            .custom_color(*PAGES_COLOR),
                                        );
                                    }
                                    None => write_text("created the pipe".green()),
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::dup => {
                let file_descriptor = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("duplicate the file descriptor: ");
                        write_path_file(file_descriptor);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let file =
                                    parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("created a new duplicate file descriptor: ".green());
                                write_path_file(file);
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::dup2 => {
                let file_to_be_duplicated = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let file_duplicate = parse_as_int(registers[1]);

                match self.state {
                    Entering => {
                        write_general_text("duplicate the file descriptor: ");
                        write_path_file(file_to_be_duplicated);
                        write_general_text(" using the fd: ");
                        write_text(file_duplicate.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(
                            ", and close and overrwrite the fd if its already being used",
                        );
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let file =
                                    parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("created a new duplicate file descriptor: ".green());
                                write_path_file(file);
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::dup3 => {
                let file_to_be_duplicated = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let file_duplicate = parse_as_int(registers[1]);
                let dup_flag = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("duplicate the file descriptor: ");
                        write_path_file(file_to_be_duplicated);
                        write_general_text(" using the fd: ");
                        write_text(file_duplicate.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(
                            ", and close and overrwrite the fd if its already being used",
                        );
                        if (dup_flag & O_CLOEXEC) == O_CLOEXEC {
                            write_parenthesis("close the file on the next exec syscall");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let file =
                                    parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("created a new duplicate file descriptor: ".green());
                                write_path_file(file);
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::mkdir => {
                let path = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        fn extract_final_dentry_index(path: &str) -> usize {
                            for (index, chara) in path.chars().rev().enumerate() {
                                if chara == '/' {
                                    return path.len() - index;
                                }
                            }
                            unreachable!()
                        }
                        // TODO!
                        // scrutinize for edge cases
                        //

                        if path.starts_with('/') {
                            let final_dentry_starting_index = extract_final_dentry_index(&path);
                            write_general_text("create a new directory ");
                            write_text(
                                path[final_dentry_starting_index..].custom_color(*OUR_YELLOW),
                            );
                            write_general_text(" inside: ");
                            write_text(
                                path[..final_dentry_starting_index].custom_color(*OUR_YELLOW),
                            );
                        } else if path.starts_with("./") || path.starts_with("../") {
                            // TODO!
                            // design decision: path math or truthfulness?
                            // currently both this and the above branch do similar work
                            // consider getting the tracee's CWD in this branch using procfs similar to
                            // and then do the 'path math' for a better output
                            //
                            // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                            //     .unwrap()
                            //     .cwd()
                            //     .unwrap();

                            let final_dentry_starting_index = extract_final_dentry_index(&path);
                            write_general_text("create a new directory ");
                            write_text(
                                path[final_dentry_starting_index..].custom_color(*OUR_YELLOW),
                            );
                            write_general_text(" inside: ");
                            write_text(
                                path[..final_dentry_starting_index].custom_color(*OUR_YELLOW),
                            );
                        } else {
                            write_general_text("create a new directory ");
                            write_text(path.custom_color(*OUR_YELLOW));
                            write_general_text(" inside the current working directory");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("directory created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::mkdirat => {
                // If  the pathname given in pathname is relative,
                // then it is interpreted relative to the directory
                // referred to by the file descriptor dirfd
                // (rather than relative to the current working directory
                // of the calling process, as is done by mkdir()
                // for a relative pathname).

                // If pathname is relative and dirfd is the special value AT_FDCWD,
                // then pathname is interpreted relative to the current working directory
                // of the calling process (like mkdir()).

                // If pathname is absolute, then dirfd is ignored.

                let dirfd = parse_as_int(registers[0]) as i32;
                let path = string_from_pointer(registers[1] as usize, self.tracee_pid);

                match self.state {
                    Entering => {
                        fn extract_final_dentry_index(path: &str) -> usize {
                            for (index, chara) in path.chars().rev().enumerate() {
                                if chara == '/' {
                                    return path.len() - index;
                                }
                            }
                            unreachable!()
                        }
                        if path.starts_with('/') {
                            let final_dentry_starting_index = extract_final_dentry_index(&path);
                            write_general_text("create a new directory ");
                            write_text(
                                path[final_dentry_starting_index..].custom_color(*OUR_YELLOW),
                            );
                            write_general_text(" inside: ");
                            write_text(
                                path[..final_dentry_starting_index].custom_color(*OUR_YELLOW),
                            );
                        } else if path.starts_with("./") || path.starts_with("../") {
                            // TODO!
                            // design decision: path math or truthfulness?
                            // currently both this and the above branch do similar work
                            // consider getting the tracee's CWD in this branch using procfs similar to
                            // and then do the 'path math' for a better output
                            //
                            // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                            //     .unwrap()
                            //     .cwd()
                            //     .unwrap();

                            let final_dentry_starting_index = extract_final_dentry_index(&path);
                            write_general_text("create a new directory ");
                            write_text(
                                path[final_dentry_starting_index..].custom_color(*OUR_YELLOW),
                            );
                            write_general_text(" inside: ");
                            write_text(
                                path[..final_dentry_starting_index].custom_color(*OUR_YELLOW),
                            );
                            if !dirfd == AT_FDCWD {
                                write_general_text("(");
                                write_text("relative to: ".custom_color(*OUR_YELLOW));
                                let dirfd_resolved = find_fd_for_tracee(dirfd, self.tracee_pid)
                                    .unwrap_or("COULDN'T LOCATE FILE DESCRIPTOR".to_owned());
                                write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                write_general_text(")");
                            }
                        } else {
                            write_general_text("create a new directory ");
                            write_text(path.custom_color(*OUR_YELLOW));
                            write_general_text(" inside the current working directory");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("directory created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::link => {
                let oldpath = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let newpath = string_from_pointer(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        // If newpath exists, it will not be overwritten
                        // it should be impossible to tell after this syscall
                        // which hard link was the original
                        write_general_text("create a new hard link at: ");
                        write_text(newpath.custom_color(*OUR_YELLOW));
                        write_general_text(" for the file: ");
                        write_text(oldpath.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("hard link created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::linkat => {
                let olddirfd = parse_as_int(registers[0]);
                let oldpath = string_from_pointer(registers[1] as usize, self.tracee_pid);

                let newdirfd = parse_as_int(registers[2]);
                let newpath = string_from_pointer(registers[3] as usize, self.tracee_pid);
                let flags = parse_as_int(registers[4]);
                match self.state {
                    Entering => {
                        // If newpath exists, it will not be overwritten
                        // it should be impossible to tell after this syscall
                        // which hard link was the original
                        write_general_text("create a new hard link at: ");
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        // same path rules (faccessat2, mkdir, mkdirat, readlinkat)
                        if newpath.starts_with('/') {
                            write_text(newpath.custom_color(*OUR_YELLOW));
                        } else if newpath.starts_with("./") || newpath.starts_with("../") {
                            // TODO!
                            // design decision: path math or truthfulness?
                            // currently both this and the above branch do similar work
                            // consider getting the tracee's CWD in this branch using procfs similar to
                            // and then do the 'path math' for a better output
                            //
                            // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                            //     .unwrap()
                            //     .cwd()
                            //     .unwrap();
                            write_text(newpath.custom_color(*OUR_YELLOW));
                            if !newdirfd == AT_FDCWD {
                                write_general_text("(");
                                write_text("relative to: ".custom_color(*OUR_YELLOW));
                                let dirfd_resolved = find_fd_for_tracee(newdirfd, self.tracee_pid)
                                    .unwrap_or("COULDN'T LOCATE FILE DESCRIPTOR".to_owned());
                                write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                write_general_text(")");
                            }
                        }
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //

                        write_general_text(" for the file: ");
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        // same path rules (faccessat2, mkdir, mkdirat, readlinkat)
                        if oldpath.starts_with('/') {
                            write_text(oldpath.custom_color(*OUR_YELLOW));
                        } else if oldpath.starts_with("./") || oldpath.starts_with("../") {
                            // TODO!
                            // design decision: path math or truthfulness?
                            // currently both this and the above branch do similar work
                            // consider getting the tracee's CWD in this branch using procfs similar to
                            // and then do the 'path math' for a better output
                            //
                            // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                            //     .unwrap()
                            //     .cwd()
                            //     .unwrap();
                            write_text(oldpath.custom_color(*OUR_YELLOW));
                            if !olddirfd == AT_FDCWD {
                                write_general_text("(");
                                write_text("relative to: ".custom_color(*OUR_YELLOW));
                                let dirfd_resolved = find_fd_for_tracee(olddirfd, self.tracee_pid)
                                    .unwrap_or("COULDN'T LOCATE FILE DESCRIPTOR".to_owned());
                                write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                write_general_text(") ");
                            }
                        }
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        let mut flag_directive = vec![];
                        if (flags & AT_SYMLINK_FOLLOW) == AT_SYMLINK_FOLLOW {
                            flag_directive
                                .push("recurse symbolic links if found".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(flag_directive);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("hard link created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::unlink => {
                let path = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("unlink and possibly delete the file: ");
                        write_path_file(path);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("unlinking successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    } // caution: the file is deleted at this point
                }
            }
            Sysno::unlinkat => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let path = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let flag = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("unlink and possibly delete the file: ");
                        write_possible_dirfd_file(dirfd, path, self.tracee_pid);

                        if (flag & AT_REMOVEDIR) == AT_REMOVEDIR {
                            write_general_text(" (");
                            write_text("perform the same operation as ".custom_color(*OUR_YELLOW));
                            write_text("`rmdir`".blue());
                            write_general_text(")");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("unlinking successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    } // caution: the file is deleted at this point
                }
            }
            Sysno::rmdir => {
                let directory = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("delete the directory: ");
                        write_path_file(directory);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("directory deleted".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::symlink => {
                let target = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let symlink = string_from_pointer(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("create the symlink: ");
                        write_path_file(symlink);

                        write_general_text(" and link it with: ");
                        write_path_file(target);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("symlink created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::symlinkat => {
                let target = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let dirfd = parse_as_int(registers[0]) as i32;
                let symlink = string_from_pointer(registers[2] as usize, self.tracee_pid);

                match self.state {
                    Entering => {
                        write_general_text("create the symlink: ");
                        write_possible_dirfd_file(dirfd, symlink, self.tracee_pid);
                        write_general_text(" and link it with: ");
                        write_path_file(target);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("symlink created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::readlink => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get the target path of the symbolic link: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("target retrieved: ".green());
                                match read_string_specific_length(
                                    registers[1] as usize,
                                    self.tracee_pid,
                                    syscall_return as usize,
                                ) {
                                    Some(target) => write_path_file(target),
                                    None => {
                                        write_text(
                                            "[intentrace: could not get target]"
                                                .blink()
                                                .bright_black(),
                                        );
                                    }
                                };
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::readlinkat => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("get the target path of the symbolic link: ");
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        // same path rules (faccessat2, mkdir, mkdirat, readlinkat)
                        if filename.starts_with('/') {
                            write_text(filename.custom_color(*OUR_YELLOW));
                        } else if filename.starts_with("./") || filename.starts_with("../") {
                            // TODO!
                            // design decision: path math or truthfulness?
                            // currently both this and the above branch do similar work
                            // consider getting the tracee's CWD in this branch using procfs similar to
                            // and then do the 'path math' for a better output
                            //
                            // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                            //     .unwrap()
                            //     .cwd()
                            //     .unwrap();
                            write_text(filename.custom_color(*OUR_YELLOW));
                            if !dirfd == AT_FDCWD {
                                write_general_text("(");
                                write_text("relative to: ".custom_color(*OUR_YELLOW));
                                let dirfd_resolved = find_fd_for_tracee(dirfd, self.tracee_pid)
                                    .unwrap_or("COULDN'T LOCATE FILE DESCRIPTOR".to_owned());
                                write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                write_general_text(")");
                            }
                        }
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                        //
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("target retrieved: ".green());
                                let target =
                                    string_from_pointer(registers[2] as usize, self.tracee_pid);
                                write_path_file(target);
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }

            Sysno::access => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let access_mode = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        if (access_mode & F_OK) == F_OK {
                            write_general_text("check if the file: ");
                            write_path_file(filename);
                            write_text(" exists".custom_color(*OUR_YELLOW));
                        } else {
                            let mut checks = vec![];

                            if (access_mode & R_OK) == R_OK {
                                checks.push("read".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & W_OK) == W_OK {
                                checks.push("write".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & X_OK) == X_OK {
                                checks.push("execute".custom_color(*OUR_YELLOW));
                            }
                            if !checks.is_empty() {
                                write_general_text("check if the process is allowed to ");
                                write_vanilla_commas(checks);
                                write_general_text(" the file: ");
                                write_path_file(filename);
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("check is positive".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::faccessat => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let access_mode = parse_as_int(registers[2]);
                let flags = parse_as_int(registers[3]);

                match self.state {
                    Entering => {
                        if (access_mode & F_OK) == F_OK {
                            write_general_text("check if the file: ");
                            write_path_file(filename);
                            write_text(" exists".custom_color(*OUR_YELLOW));
                        } else {
                            let mut checks = vec![];

                            if (access_mode & R_OK) == R_OK {
                                checks.push("read".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & W_OK) == W_OK {
                                checks.push("write".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & X_OK) == X_OK {
                                checks.push("execute".custom_color(*OUR_YELLOW));
                            }
                            if !checks.is_empty() {
                                write_general_text("check if the process is allowed to ");
                                write_vanilla_commas(checks);
                                write_general_text(" the file: ");
                                write_path_file(filename);
                            }
                        }
                        let mut flag_directive = vec![];
                        if (flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_EACCESS) == AT_EACCESS {
                            flag_directive.push(
                                "check using effective user & group ids".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_SYMLINK_FOLLOW) == AT_SYMLINK_FOLLOW {
                            flag_directive
                                .push("recurse symbolic links if found".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_NO_AUTOMOUNT) == AT_NO_AUTOMOUNT {
                            flag_directive.push(
                                    "don't automount the basename of the path if its an automount directory"
                                        .custom_color(*OUR_YELLOW),
                                );
                        }
                        if (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(flag_directive);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("check is positive".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::faccessat2 => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let dirfd_parsed = find_fd_for_tracee(dirfd, self.tracee_pid);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let access_mode = parse_as_int(registers[2]);
                let flags = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        if (access_mode & F_OK) == F_OK {
                            write_general_text("check if the file: ");
                            //
                            //
                            //
                            //
                            //
                            //
                            //
                            // same path rules (faccessat2, mkdir, mkdirat, readlinkat)
                            if filename.starts_with('/') {
                                write_text(filename.custom_color(*OUR_YELLOW));
                            } else if filename.starts_with("./") || filename.starts_with("../") {
                                // TODO!
                                // design decision: path math or truthfulness?
                                // currently both this and the above branch do similar work
                                // consider getting the tracee's CWD in this branch using procfs similar to
                                // and then do the 'path math' for a better output
                                //
                                // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                                //     .unwrap()
                                //     .cwd()
                                //     .unwrap();
                                write_text(filename.custom_color(*OUR_YELLOW));
                                if !dirfd == AT_FDCWD {
                                    write_general_text("(");
                                    write_text("relative to: ".custom_color(*OUR_YELLOW));
                                    let dirfd_resolved = find_fd_for_tracee(dirfd, self.tracee_pid)
                                        .unwrap_or("COULDN'T LOCATE FILE DESCRIPTOR".to_owned());
                                    write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                    write_general_text(")");
                                }
                            }
                            //
                            //
                            //
                            //
                            //
                            //
                            //
                            write_text(" exists".custom_color(*OUR_YELLOW));
                        } else {
                            let mut checks = vec![];

                            if (access_mode & R_OK) == R_OK {
                                checks.push("read".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & W_OK) == W_OK {
                                checks.push("write".custom_color(*OUR_YELLOW));
                            }
                            if (access_mode & X_OK) == X_OK {
                                checks.push("execute".custom_color(*OUR_YELLOW));
                            }
                            if !checks.is_empty() {
                                write_general_text("check if the process is allowed to ");
                                write_vanilla_commas(checks);
                                write_general_text(" the file: ");
                                //
                                //
                                //
                                //
                                //
                                //
                                //
                                // same path rules (faccessat2, mkdir, mkdirat, readlinkat)
                                if filename.starts_with('/') {
                                    write_text(filename.custom_color(*OUR_YELLOW));
                                } else if filename.starts_with("./") || filename.starts_with("../")
                                {
                                    // TODO!
                                    // design decision: path math or truthfulness?
                                    // currently both this and the above branch do similar work
                                    // consider getting the tracee's CWD in this branch using procfs similar to
                                    // and then do the 'path math' for a better output
                                    //
                                    // let cwd = procfs::process::Process::new(self.tracee_pid.into())
                                    //     .unwrap()
                                    //     .cwd()
                                    //     .unwrap();
                                    write_text(filename.custom_color(*OUR_YELLOW));
                                    if !dirfd == AT_FDCWD {
                                        write_general_text("(");
                                        write_text("relative to: ".custom_color(*OUR_YELLOW));
                                        let dirfd_resolved =
                                            find_fd_for_tracee(dirfd, self.tracee_pid).unwrap_or(
                                                "COULDN'T LOCATE FILE DESCRIPTOR".to_owned(),
                                            );
                                        write_text(dirfd_resolved.custom_color(*OUR_YELLOW));
                                        write_general_text(")");
                                    }
                                }
                                //
                                //
                                //
                                //
                                //
                                //
                                //
                                //
                                //
                            }
                        }
                        let mut flag_directive = vec![];
                        if (flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW {
                            flag_directive.push(
                                "operate on the symbolic link if found, do not recurse it"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_EACCESS) == AT_EACCESS {
                            flag_directive.push(
                                "check using effective user & group ids".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & AT_SYMLINK_FOLLOW) == AT_SYMLINK_FOLLOW {
                            flag_directive
                                .push("recurse symbolic links if found".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_NO_AUTOMOUNT) == AT_NO_AUTOMOUNT {
                            flag_directive.push("don't automount the basename of the path if its an automount directory".custom_color(*OUR_YELLOW));
                        }
                        if (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH {
                            flag_directive.push(
                                "operate on the anchor directory if pathname is empty"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(flag_directive);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("check is positive".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            // TODO! granular
            // check if the file was moved only or renamed only or moved and renamed at the same time
            Sysno::rename => {
                let old_path = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let new_path = string_from_pointer(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("move the file: ");
                        write_path_file(old_path);
                        write_general_text(" to: ");
                        write_path_file(new_path);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                // TODO! granular
                                write_text("file moved".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::renameat => {
                let old_dirfd = parse_as_int(registers[0]);
                let old_filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let new_dirfd = parse_as_int(registers[2]);
                let new_filename = string_from_pointer(registers[3] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("move the file: ");
                        write_possible_dirfd_file(old_dirfd, old_filename, self.tracee_pid);

                        write_general_text(" to: ");
                        write_possible_dirfd_file(new_dirfd, new_filename, self.tracee_pid);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                // TODO! granular
                                write_text("file moved".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::renameat2 => {
                let old_dirfd = parse_as_int(registers[0]);
                let old_filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let new_dirfd = parse_as_int(registers[2]);
                let new_filename = string_from_pointer(registers[3] as usize, self.tracee_pid);
                let flags = lower_32_bits(registers[4]);
                match self.state {
                    Entering => {
                        write_general_text("move the file: ");
                        write_possible_dirfd_file(old_dirfd, old_filename, self.tracee_pid);

                        write_general_text(" to: ");
                        write_possible_dirfd_file(new_dirfd, new_filename, self.tracee_pid);

                        let mut directives = vec![];
                        if (flags & RENAME_EXCHANGE) == RENAME_EXCHANGE {
                            directives
                                .push("exchange the paths atomically".custom_color(*OUR_YELLOW))
                        }
                        if (flags & RENAME_NOREPLACE) == RENAME_NOREPLACE {
                            directives
                                .push("error if the new path exists".custom_color(*OUR_YELLOW));
                        }
                        if (flags & RENAME_WHITEOUT) == RENAME_WHITEOUT {
                            directives
                                .push("white-out the original file".custom_color(*OUR_YELLOW));
                        }
                        write_directives(directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                // TODO! granular
                                write_text("file moved".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::openat => {
                let dirfd = parse_as_int(registers[0]);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let flags_num = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        // TODO!
                        //
                        // fix open flags granularity
                        // also fix file mode granularity
                        if (flags_num & O_TMPFILE) == O_TMPFILE {
                            write_general_text("create an unnamed temporary file in the path: ");
                        } else {
                            write_general_text("open the file: ");
                        }
                        write_possible_dirfd_file(dirfd as i32, filename, self.tracee_pid);

                        let mut directives = vec![];
                        if (flags_num & O_APPEND) == O_APPEND {
                            directives
                                .push("open the file in append mode".custom_color(*OUR_YELLOW));
                        }
                        if (flags_num & O_ASYNC) == O_ASYNC {
                            directives.push("enable signal-driven I/O".custom_color(*OUR_YELLOW));
                        }
                        if (flags_num & O_CLOEXEC) == O_CLOEXEC {
                            directives.push(
                                "close the file descriptor on the next exec syscall"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_CREAT) == O_CREAT {
                            directives.push(
                                "create the file if it does not exist".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_DIRECT) == O_DIRECT {
                            directives.push("use direct file I/O".custom_color(*OUR_YELLOW));
                        }
                        if (flags_num & O_DIRECTORY) == O_DIRECTORY {
                            directives.push(
                                "fail if the path is not a directory".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_DSYNC) == O_DSYNC {
                            directives.push("ensure writes are completely teransferred to hardware before return".custom_color(*OUR_YELLOW));
                        }
                        if (flags_num & O_EXCL) == O_EXCL {
                            directives.push("ensure O_CREAT fails if the file already exists or is a symbolic link".custom_color(*OUR_YELLOW));
                        }
                        if flags_num == O_LARGEFILE {
                            directives.push(
                                "allow files larger than `off_t` and up to `off64_t`"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_NOATIME) == O_NOATIME {
                            directives.push(
                                "do not update the file last access time on read"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_NOCTTY) == O_NOCTTY {
                            directives
                                .push("do not use the file as the process's controlling terminal if its a terminal device".custom_color(*OUR_YELLOW));
                        }
                        if (flags_num & O_NOFOLLOW) == O_NOFOLLOW {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "fail if the base of the file is a symbolic link"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_NONBLOCK) == O_NONBLOCK
                            || (flags_num & O_NDELAY) == O_NDELAY
                        {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "open the file in non-blocking mode".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_PATH) == O_PATH {
                            // TODO! change this to have better wording, change `base`
                            directives.push(
                                "return a `shallow` file descriptor".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags_num & O_SYNC) == O_SYNC {
                            directives.push("ensure writes are completely teransferred to hardware before return".custom_color(*OUR_YELLOW));
                        }
                        write_directives(directives);

                        if (flags_num & O_TRUNC) == O_TRUNC {
                            write_text(
                                "truncate the file's length to zero".custom_color(*OUR_YELLOW),
                            );
                        }
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successfully opened file".green());
                        }
                        SyscallResult::Fail(errno) => {
                            // TODO! granular
                            SyscallObject::one_line_error(errno);
                        }
                    },
                }
            }
            Sysno::creat => {
                let file = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("create a new file: ");
                        write_path_file(file);
                        write_general_text(", or rewrite it if it exists");
                        // TODO!
                        // mode granularity
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("file created".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::getcwd => {
                match self.state {
                    Entering => {
                        write_general_text("get the current working directory");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let cwd =
                                    string_from_pointer(syscall_return as usize, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("path retrieved: ".green());
                                write_text(cwd.custom_color(*OUR_YELLOW));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::chdir => {
                let directory = string_from_pointer(registers[0] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("changes the current working directory to: ");
                        write_path_file(directory);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("curent working directory changed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fchdir => {
                let directory = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("changes the current working directory to: ");
                        write_path_file(directory);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("curent working directory changed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::chmod => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let mode = registers[1] as u32;
                match self.state {
                    Entering => {
                        write_general_text("change the mode of the file: ");
                        write_path_file(filename);
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("mode changed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fchmod => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let mode = registers[1] as u32;
                match self.state {
                    Entering => {
                        write_general_text("change the mode of the file: ");
                        write_path_file(filename);
                        self.mode_matcher(mode);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("mode changed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fchmodat => {
                let dirfd = parse_as_int(registers[0]) as i32;
                let dirfd_parsed = find_fd_for_tracee(dirfd, self.tracee_pid);
                let filename = string_from_pointer(registers[1] as usize, self.tracee_pid);
                let mode = registers[1] as u32;
                let flag = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("change the mode of the file: ");
                        write_possible_dirfd_file(dirfd, filename, self.tracee_pid);
                        self.mode_matcher(mode);
                        write_general_text(" and ");
                        if flag == AT_SYMLINK_NOFOLLOW {
                            write_text("do not recurse symlinks".custom_color(*OUR_YELLOW));
                        }
                        // TODO!
                        // AT_SYMLINK_FOLLOW?
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("mode changed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::sync => {
                match self.state {
                    Entering => {
                        write_general_text("flush all pending filesystem data and metadata writes");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("all writes flushed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::syncfs => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("flush all pending filesystem data and metadata writes for the filesystem that contains the file: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successfully flushed data".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fsync => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text(
                            "flush all pending data and metadata writes for the file: ",
                        );
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("all writes flushed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fdatasync => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text("flush all pending data and critical metadata writes (ignore non-critical metadata) for the file: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("all writes flushed".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }

            Sysno::truncate => {
                let filename = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let length = parse_as_signed_bytes(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("change the size of the file: ");
                        write_path_file(filename);
                        write_general_text(" to precisely ");
                        write_text(length.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::ftruncate => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let length = parse_as_signed_bytes(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("change the size of the file: ");
                        write_path_file(filename);
                        write_general_text(" to precisely ");
                        write_text(length.custom_color(*OUR_YELLOW));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }

            Sysno::select => {
                // select() is limited to monitoring file descriptors less than 1024,
                // which is too low for modern applications.
                // poll() or epoll() should be used instead
                // they don't have this limitation.

                let highest_fd = parse_as_int(registers[0]);
                let readfds = registers[1];
                let writefds = registers[2];
                let exceptfds = registers[3];
                let timeout = registers[4];
                match self.state {
                    Entering => {
                        write_general_text("block all ");
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push("read-waiting".custom_color(*OUR_YELLOW));
                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         registers[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push("write-waiting".custom_color(*OUR_YELLOW));
                        }
                        if exceptfds != 0 {
                            blockers.push("error-waiting".custom_color(*OUR_YELLOW));
                        }
                        write_anding(blockers);
                        write_general_text(" file descriptors lower than ");
                        write_text(highest_fd.to_string().blue());

                        if timeout == 0 {
                            write_general_text(", and ");
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        } else {
                            let timeval = read_bytes_as_struct::<16, timeval>(
                                registers[4] as usize,
                                self.tracee_pid as _,
                            )
                            .unwrap();
                            write_general_text(", and timeout ");
                            write_timeval(timeval.tv_sec, timeval.tv_usec);
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let select_return = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if select_return == 0 {
                                    write_text("timed out before any events".green());
                                } else if select_return > 0 {
                                    write_text(select_return.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::pselect6 => {
                let highest_fd = parse_as_int(registers[0]);
                let readfds = registers[1];
                let writefds = registers[2];
                let exceptfds = registers[3];
                let timeout = registers[4];
                let signal_mask = registers[5];
                match self.state {
                    Entering => {
                        write_general_text("block for events on all ");
                        let mut blockers = vec![];
                        if readfds != 0 {
                            blockers.push("read-waiting".custom_color(*OUR_YELLOW));

                            // TODO! possible granularity, likely not useful
                            // let reads =
                            //     read_bytes_as_struct::<128, nix::sys::select::FdSet>(
                            //         registers[1] as usize,
                            //         self.child as _,
                            //     )
                            //     .unwrap();
                            // for fd in reads. {
                            //     SyscallObject::read_bytes::<1024>(fd,self.child)
                            // }
                        }
                        if writefds != 0 {
                            blockers.push("write-waiting".custom_color(*OUR_YELLOW));
                        }
                        if exceptfds != 0 {
                            blockers.push("error-waiting".custom_color(*OUR_YELLOW));
                        }
                        write_anding(blockers);
                        write_general_text(" file descriptors lower than ");
                        write_text(highest_fd.to_string().blue());
                        if signal_mask != 0 {
                            write_general_text(", and ");
                            write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }

                        if timeout == 0 {
                            write_general_text(", and ");
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        } else {
                            let timespec = read_bytes_as_struct::<16, timespec>(
                                registers[4] as usize,
                                self.tracee_pid as _,
                            )
                            .unwrap();
                            write_general_text(", and timeout ");
                            write_timespec(timespec.tv_sec, timespec.tv_nsec);
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let select_return = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if select_return == 0 {
                                    write_text("timed out before any events".green());
                                } else if select_return > 0 {
                                    write_text(select_return.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::poll => {
                let nfds = registers[1];
                // 0 => return immediately
                // -n => timeout indefinitely
                // n => timeout for n
                let timeout = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("block for new events on ");
                        write_text(nfds.to_string().blue());
                        write_general_text(" provided file descriptors, ");
                        write_general_text("and ");
                        if timeout < 0 {
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        } else if timeout == 0 {
                            write_text("don't wait (return immediately)".custom_color(*OUR_YELLOW));
                        } else {
                            write_text("wait for ".custom_color(*OUR_YELLOW));
                            write_text(timeout.to_string().blue());
                            write_text(" milliseconds".custom_color(*OUR_YELLOW));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let num_fds = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if num_fds == 0 {
                                    write_text("timed out before any events".green());
                                } else {
                                    write_text(num_fds.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::ppoll => {
                let nfds = registers[1];
                let timespec = registers[2];
                let signal_mask = registers[3];

                match self.state {
                    Entering => {
                        write_general_text("block for new events on the ");
                        write_text(nfds.to_string().blue());
                        write_general_text(" provided file descriptors");

                        if signal_mask != 0 {
                            write_general_text(", or ");
                            write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if timespec != 0 {
                            write_general_text(", and timeout ");
                            if let Some(timespec) = read_bytes_as_struct::<TIMESPEC_SIZE, timespec>(
                                timespec as usize,
                                self.tracee_pid as _,
                            ) {
                                write_timespec(timespec.tv_sec, timespec.tv_nsec);
                            } else {
                                write_text(
                                    "[intentrace: could not get timeout]".blink().bright_black(),
                                );
                            }
                        } else {
                            write_general_text(", and ");
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let num_fds = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if num_fds == 0 {
                                    write_text("timed out before any events".green());
                                } else {
                                    write_text(num_fds.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_create => {
                // the size argument is ignored since 2.6, but must be greater than zero.
                let size = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("create an epoll instance with a capacity of ");
                        write_text(size.to_string().custom_color(*OUR_YELLOW));
                        write_general_text(" file descriptors");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let epoll_descriptor = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("epoll instance created with descriptor: ".green());
                                write_text(epoll_descriptor.to_string().custom_color(*PAGES_COLOR));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_create1 => {
                let flag = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("create a new epoll instance ");
                        if (flag & EPOLL_CLOEXEC) == EPOLL_CLOEXEC {
                            write_general_text(" (");
                            write_text(
                                "close the epoll descriptor on the next exec syscall"
                                    .custom_color(*OUR_YELLOW),
                            );
                            write_general_text(")");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let epoll_descriptor = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("epoll instance created with descriptor: ".green());
                                write_text(epoll_descriptor.to_string().custom_color(*PAGES_COLOR));
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_wait => {
                let epoll_instance = parse_as_int(registers[0]);
                // maxevents must be greater than zero
                let max_events = parse_as_int(registers[2]);
                // 0 => return immediately
                // -n => timeout indefinitely
                // n => timeout for n
                let timeout = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        write_general_text("block until a maximum of ");
                        write_text(max_events.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" events occur on epoll instance: ");
                        write_text(epoll_instance.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" and ");
                        if timeout < 0 {
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        } else if timeout == 0 {
                            write_text("don't wait (return immediately)".custom_color(*OUR_YELLOW));
                        } else {
                            write_text("wait for ".custom_color(*OUR_YELLOW));
                            write_text(timeout.to_string().blue());
                            write_text(" milliseconds".custom_color(*OUR_YELLOW));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let num_fds = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if num_fds == 0 {
                                    write_text("timed out before any events".green());
                                } else {
                                    write_text(num_fds.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_pwait => {
                let epoll_instance = parse_as_int(registers[0]);

                // maxevents must be greater than zero
                let max_events = parse_as_int(registers[2]);
                // 0 => return immediately
                // -n => timeout indefinitely
                // n => timeout for n
                let timeout = parse_as_int(registers[3]);
                let signal_mask = registers[4];
                match self.state {
                    Entering => {
                        write_general_text("block until a maximum of ");
                        write_text(max_events.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" events occur on epoll instance: ");
                        write_text(epoll_instance.to_string().custom_color(*PAGES_COLOR));
                        if signal_mask != 0 {
                            write_general_text(", or ");
                            write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }

                        write_general_text(" and ");
                        if timeout < 0 {
                            write_text("wait forever".custom_color(*OUR_YELLOW));
                        } else if timeout == 0 {
                            write_text("don't wait (return immediately)".custom_color(*OUR_YELLOW));
                        } else {
                            write_text("wait for ".custom_color(*OUR_YELLOW));
                            write_text(timeout.to_string().blue());
                            write_text(" milliseconds".custom_color(*OUR_YELLOW));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let num_fds = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if num_fds == 0 {
                                    write_text("timed out before any events".green());
                                } else {
                                    write_text(num_fds.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_pwait2 => {
                let epoll_instance = parse_as_int(registers[0]);
                // maxevents must be greater than zero
                let max_events = parse_as_int(registers[2]);
                // timespec
                let timeout = parse_as_int(registers[3]);
                let signal_mask = registers[4];
                match self.state {
                    Entering => {
                        write_general_text("block until a maximum of ");
                        write_text(max_events.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" events occur on epoll instance: ");
                        write_text(epoll_instance.to_string().custom_color(*PAGES_COLOR));
                        if signal_mask != 0 {
                            write_general_text(", or ");
                            write_text(
                                "any signal from the provided signal mask"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }

                        if timeout != 0 {
                            write_general_text(", and timeout ");
                            if let Some(timespec) = read_bytes_as_struct::<TIMESPEC_SIZE, timespec>(
                                timeout as usize,
                                self.tracee_pid as _,
                            ) {
                                write_timespec(timespec.tv_sec, timespec.tv_nsec);
                            } else {
                                write_text(
                                    "[intentrace: could not get timeout]".blink().bright_black(),
                                );
                            }
                        } else {
                            write_text(" and wait forever".custom_color(*OUR_YELLOW));
                        }

                        write_general_text(" ");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let num_fds = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if num_fds == 0 {
                                    write_text("timed out before any events".green());
                                } else {
                                    write_text(num_fds.to_string().blue());
                                    write_text(" file descriptors with new events".green());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::epoll_ctl => {
                let epoll_instance = parse_as_int(registers[0]);
                let operation = parse_as_int(registers[1]);
                let file_descriptor = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        if (operation & EPOLL_CTL_ADD) == EPOLL_CTL_ADD {
                            write_text("add".custom_color(*OUR_YELLOW));
                            write_general_text(" file descriptor ");
                            write_text(file_descriptor.to_string().blue());
                            write_general_text(" to ");
                        } else if (operation & EPOLL_CTL_DEL) == EPOLL_CTL_DEL {
                            write_text("remove".custom_color(*OUR_YELLOW));
                            write_general_text(" file descriptor ");
                            write_text(file_descriptor.to_string().blue());
                            write_general_text(" from ");
                        } else if (operation & EPOLL_CTL_MOD) == EPOLL_CTL_MOD {
                            write_text("modify the settings of ".custom_color(*OUR_YELLOW));
                            write_general_text(" file descriptor ");
                            write_text(file_descriptor.to_string().blue());
                            write_general_text(" in ");
                        }
                        write_general_text("epoll instance: ");
                        write_text(epoll_instance.to_string().custom_color(*PAGES_COLOR));
                        // TODO!
                        //
                        // events struct is currently ignored
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_text("Successfull".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::ioctl => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let operation = registers[1];
                match self.state {
                    Entering => {
                        write_general_text("perform operation ");
                        write_text(
                            format!("#{}", operation.to_string()).custom_color(*PAGES_COLOR),
                        );
                        write_general_text(" on the device: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("operation successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => {
                                write_general_text(" |=> ");
                                match errno {
                                    Errno::EBADF => {
                                        write_text("file descriptor invalid".red());
                                    }
                                    Errno::EFAULT => {
                                        write_text("argp is inaccessible".red());
                                    }
                                    Errno::EINVAL => {
                                        write_text("either op or argp is invalid".red());
                                    }
                                    Errno::ENOTTY => {
                                        write_text("operation incompatible with the file descriptor, or the file descriptor is not a TTY".red());
                                    }
                                    _ => SyscallObject::one_line_error(errno),
                                }
                            }
                        }
                    }
                }
            }
            Sysno::fcntl => {
                let filename = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let operation = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        write_general_text("perform operation ");
                        write_text(format!("#{}", operation.to_string()).custom_color(*OUR_YELLOW));
                        write_general_text(" on the file: ");
                        write_path_file(filename);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("operation successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
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

                let operation = parse_as_int(registers[0]);
                let addr = registers[1];

                match self.state {
                    Entering => {
                        if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                            if addr == 0 {
                                write_general_text(
                                    "disable the `cpuid` instruction for the calling thread",
                                );
                            } else {
                                write_general_text(
                                    "enable the `cpuid` instruction for the calling thread",
                                );
                            }
                        } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                            write_general_text(
                                "check whether the `cpuid` instruction is enabled or disabled",
                            );
                        } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                            write_general_text("Set the 64-bit base for the FS register to ");
                            write_text(addr.to_string().custom_color(*PAGES_COLOR));
                        } else if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                            write_general_text(
                                "retrieve the calling thread's 64-bit FS register value",
                            );
                        } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                            write_general_text("Set the 64-bit base for the GS register to ");
                            write_text(addr.to_string().custom_color(*PAGES_COLOR));
                        } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                            write_general_text(
                                "retrieve the calling thread's 64-bit GS register value",
                            );
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");

                                if (operation & ARCH_SET_CPUID) == ARCH_SET_CPUID {
                                    if addr == 0 {
                                        write_text(
                                            "successfully disabled the `cpuid` instruction".green(),
                                        );
                                    } else {
                                        write_text(
                                            "successfully enabled the `cpuid` instruction".green(),
                                        );
                                    }
                                } else if (operation & ARCH_GET_CPUID) == ARCH_GET_CPUID {
                                    if addr == 0 {
                                        write_text("the `cpuid` instruction is disabled".green());
                                    } else {
                                        write_text("the `cpuid` instruction is enabled".green());
                                    }
                                } else if (operation & ARCH_SET_FS) == ARCH_SET_FS {
                                    write_text("FS register modified".green());
                                } else if (operation & ARCH_GET_FS) == ARCH_GET_FS
                                    || (operation & ARCH_GET_GS) == ARCH_GET_GS
                                {
                                    let parsed_register =
                                        match read_one_word(addr as usize, self.tracee_pid) {
                                            Some(word) => lower_64_bits(word)
                                                .to_string()
                                                .custom_color(*PAGES_COLOR),
                                            None => "[intentrace: could not get pid]"
                                                .blink()
                                                .bright_black(),
                                        };
                                    if (operation & ARCH_GET_FS) == ARCH_GET_FS {
                                        write_text("retrieved value of the FS register: ".green());
                                        write_text(parsed_register);
                                    } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                                        write_text("retrieved value of the GS register ".green());
                                        write_text(parsed_register);
                                    }
                                } else if (operation & ARCH_SET_GS) == ARCH_SET_GS {
                                    write_text("GS register modified".green());
                                } else if (operation & ARCH_GET_GS) == ARCH_GET_GS {
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::sched_yield => {
                match self.state {
                    Entering => {
                        write_general_text(
                            "relinquish the CPU, and move to the end of the scheduler queue",
                        );
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successfully yielded CPU".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::rt_sigaction => {
                let signal_number = parse_as_int(registers[0]);
                let signal_action = registers[1] as *const ();
                let old_signal_action = registers[2] as *const ();

                match self.state {
                    Entering => {
                        // a rt_sigaction call must only use one of the first two arguments, never both

                        // struct sigaction {

                        // either:
                        // 1- SIG_DFL flag: means use the default action.
                        // 2- SIG_IGN flag: means ignore this signal.
                        // 3- A pointer to a signal handling function.
                        //      This function receives the signal number as its only argument.
                        //          void (*sa_handler)(int);

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
                        //     let sigaction = read_bytes_as_struct::<152, sigaction>(
                        //         registers[1] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("sigaction",sigaction);
                        // }

                        // if !old_signal_action.is_null() {
                        //     let old_sigaction = read_bytes_as_struct::<152, sigaction>(
                        //         registers[2] as usize,
                        //         self.child as _,
                        //     )
                        //     .unwrap();
                        //     pp!("old_sigaction",old_sigaction);
                        // }

                        let signal_as_string = parse_as_signal(signal_number);

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

                        // second is non-NULL: new action for signal signum is installed from act.
                        // second is NULL: query current signal handler
                        // third is non-NULL: previous action is saved in oldact.
                        // second and third is NULL: check whether a given signal is valid for the current machine
                        if !signal_action.is_null() {
                            match read_bytes_as_struct::<SIGACTION_SIZE, sigaction>(
                                registers[1] as usize,
                                self.tracee_pid as _,
                            ) {
                                Some(sigaction) => match sigaction.sa_sigaction {
                                    SIG_DFL => {
                                        write_general_text("change the process's handler for ");
                                        write_text(signal_as_string.custom_color(*PAGES_COLOR));
                                        write_general_text(" to the default handler");
                                    }
                                    SIG_IGN => {
                                        write_general_text("ignore the signal: ");
                                        write_text(signal_as_string.custom_color(*PAGES_COLOR));
                                        write_general_text(" for the process");
                                    }
                                    _ => {
                                        write_general_text("change the process's handler for ");
                                        write_text(signal_as_string.custom_color(*PAGES_COLOR));
                                        write_general_text(" to the provided action");
                                    }
                                },
                                None => {
                                    write_general_text("change the process's handler for ");
                                    write_text(signal_as_string.custom_color(*PAGES_COLOR));
                                    write_general_text(" to the provided action");
                                }
                            };
                            if !old_signal_action.is_null() {
                                write_general_text(", and retrieve the current signal handler");
                            }

                            // TODO!
                            // granularity on sigaction.sa_flags
                            //
                            //
                        } else {
                            if !old_signal_action.is_null() {
                                write_general_text("retrieve the current signal handler");
                            } else {
                                write_general_text("check if the current machine supports: ");
                                write_text(signal_as_string.custom_color(*OUR_YELLOW));
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::rt_sigprocmask => {
                let how = parse_as_int(registers[0]);
                let set = registers[1];
                let old_set = registers[2];
                match self.state {
                    Entering => {
                        if set == 0 {
                            if old_set != 0 {
                                write_general_text(
                                    "retrieve the proccess's current list of blocked signals",
                                );
                            } else {
                                write_text(
                                    "[intentrace: redundant syscall (won't do anything)]".blink(),
                                );
                            }
                        } else {
                            match how {
                                SIG_BLOCK => {
                                    write_general_text("add the provided signals to the proccess's list of blocked signals");
                                }
                                SIG_UNBLOCK => {
                                    write_general_text("remove the provided signals from the proccess's list of blocked signals");
                                }
                                SIG_SETMASK => {
                                    write_general_text("replace the proccess's list of blocked signals with the signals provided");
                                }
                                _ => {}
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                if set == 0 {
                                    if !old_set != 0 {
                                        write_text("retrieved blocked signals".green());
                                    } else {
                                        write_text(
                                            "[intentrace: redundant syscall (won't do anything)]"
                                                .blink(),
                                        );
                                    }
                                } else {
                                    match how {
                                        SIG_BLOCK => {
                                            write_text("signals added".green());
                                        }
                                        SIG_UNBLOCK => {
                                            write_text("signals removed".green());
                                        }
                                        SIG_SETMASK => {
                                            write_text("successfully replaced".green());
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::rt_sigsuspend => {
                match self.state {
                    Entering => {
                        // TODO!
                        // rephrase, too long
                        write_general_text("replace the process' signal mask temporarily using the provided mask, and wait until a signal arrives that invokes a signal handler or one that terminates the thread");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => unreachable!(),
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                // this syscall always errors with EINTR,
                                // as a result it will display an error (red)
                                // but by definition the syscall is successful
                                // because it waits for interruptions
                                // this should be communicated correctly
                                // communicate that this is intentional
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::sigaltstack => {
                let new_stack_null = registers[0] == 0;
                let old_stack_null = registers[1] == 0;

                match self.state {
                    Entering => match (new_stack_null, old_stack_null) {
                        (true, true) => {
                            write_text(
                                "[intentrace: redundant syscall (won't do anything)]".blink(),
                            );
                        }
                        (true, false) => {
                            write_general_text("replace the current signal stack with a new one");
                        }
                        (false, true) => {
                            write_general_text("retrieve the current signal stack");
                        }
                        (false, false) => {
                            write_general_text("retrieve the current signal stack and then replace it with a new one,",
                        );
                        }
                    },
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            match (new_stack_null, old_stack_null) {
                                (true, true) => {
                                    write_text("successful".green());
                                }
                                (true, false) => {
                                    write_text("successfully replaced".green());
                                }
                                (false, true) => {
                                    write_text("signal stack retrieved".green());
                                }
                                (false, false) => {
                                    write_text(
                                        "signal stack replaced and old signal stack retrieved"
                                            .green(),
                                    );
                                }
                            }
                        }
                        // TODO! granular
                        SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                    },
                }
            }
            Sysno::rt_sigreturn => match self.state {
                Entering => {
                    write_general_text("return from signal handler and cleanup");
                }
                Exiting => match self.result {
                    SyscallResult::Success(syscall_return) => unreachable!(),
                    SyscallResult::Fail(errno) => unreachable!(),
                },
            },
            Sysno::rt_sigpending => match self.state {
                Entering => {
                    write_general_text(
                        "return the signals pending for delivery for the calling thread",
                    );
                }
                Exiting => match self.result {
                    SyscallResult::Success(syscall_return) => {
                        write_general_text(" |=> ");
                        write_text("pending signals returned".green());
                    }
                    SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                },
            },
            Sysno::rt_sigtimedwait => {
                let timeout = registers[2];
                match self.state {
                    Entering => {
                        // TODO! use the timespec struct
                        let duration = read_bytes_as_struct::<TIMESPEC_SIZE, timespec>(
                            timeout as usize,
                            self.tracee_pid as _,
                        )
                        .unwrap();
                        write_general_text("stop the calling process until one of the provided signals is pending, or ");
                        write_timespec_non_relative(duration.tv_sec, duration.tv_nsec);
                        write_general_text(" passes");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("Successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::rt_sigqueueinfo => {
                let thread_group = parse_as_int(registers[0]);
                let signal_number = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        let signal_as_string = parse_as_signal(signal_number);
                        write_general_text("send the attached data and ");
                        write_text(signal_as_string.custom_color(*OUR_YELLOW));
                        write_general_text(" to the thread group: ");
                        write_text(thread_group.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("data and signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::rt_tgsigqueueinfo => {
                let thread_group = parse_as_int(registers[0]);
                let thread = parse_as_int(registers[1]);
                let signal_number = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        let signal_as_string = parse_as_signal(signal_number);
                        write_general_text("send the attached data and ");
                        write_text(signal_as_string.custom_color(*OUR_YELLOW));
                        write_general_text(" to thread: ");
                        write_text(thread.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" in thread group: ");
                        write_text(thread_group.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("data and signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::pidfd_send_signal => {
                let pidfd = parse_as_int(registers[0]);
                let signal_number = parse_as_int(registers[1]);
                let flags = parse_as_int(registers[3]);
                match self.state {
                    Entering => {
                        let signal_as_string = parse_as_signal(signal_number);
                        write_general_text("send a ");
                        write_text(signal_as_string.custom_color(*OUR_YELLOW));
                        write_general_text(" signal to the process associated with the pidfd: ");
                        write_text(pidfd.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::signalfd => {
                let fd = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        if fd == -1 {
                            write_general_text("create a new file descriptor for receiving signals using the provided signal mask");
                        } else {
                            write_general_text("use file descriptor: ");
                            write_text(fd.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(
                                " to receive signals using the provided signal mask",
                            );
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let signalfd = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("signalfd created: ".green());
                                write_text(signalfd.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::signalfd4 => {
                let fd = parse_as_int(registers[0]);
                let flags = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        if fd == -1 {
                            write_general_text("create a new file descriptor for receiving signals using the provided signal mask");
                        } else {
                            write_general_text("use file descriptor: ");
                            write_text(fd.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(
                                " to receive signals using the provided signal mask",
                            );
                        }
                        let mut flag_directives = vec![];
                        if (flags & SFD_NONBLOCK) == SFD_NONBLOCK {
                            flag_directives.push(
                                "use the file on non blocking mode".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & SFD_CLOEXEC) == SFD_CLOEXEC {
                            flag_directives.push(
                                "close the file with the next exec syscall"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(flag_directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let signalfd = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("signalfd created: ".green());
                                write_text(signalfd.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }

            Sysno::kill => {
                let pid = parse_as_int(registers[0]);
                let signal_number = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        if signal_number == 0 {
                            // this is a way to check if a process is alive or dead, (sending signal 0 -not a real signal-)
                            // TODO!
                            // decide if its better to communicate the intention (checking if a process exists)
                            // or to be explicit and state that a null signal was sent
                            // this needs to be rephrased
                            write_general_text("send a null signal to process: ");
                            write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(" (check if the process exists)");
                        } else {
                            write_general_text("send ");
                            let signal_as_string = parse_as_signal(signal_number);
                            write_text(signal_as_string.custom_color(*PAGES_COLOR));

                            if pid > 0 {
                                write_general_text(" to process: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            } else if pid == 0 {
                                write_general_text(" to all processes in this process group");
                            } else if pid == -1 {
                                write_general_text(" to all processes that the calling process has permissions to send to");
                            } else if pid < -1 {
                                write_general_text(" to process group: ");
                                write_text((pid * -1).to_string().custom_color(*PAGES_COLOR));
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::tgkill => {
                let thread_group = parse_as_int(registers[0]);
                let thread = parse_as_int(registers[1]);
                let signal_number = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        let signal_as_string = parse_as_signal(signal_number);
                        write_general_text("send ");
                        write_text(signal_as_string.custom_color(*PAGES_COLOR));
                        write_general_text(" to thread: ");
                        write_text(thread.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(" in thread group: ");
                        write_text(thread_group.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::tkill => {
                let thread = parse_as_int(registers[0]);
                let signal_number = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        let signal_as_string = parse_as_signal(signal_number);
                        write_general_text("send ");
                        write_text(signal_as_string.custom_color(*PAGES_COLOR));
                        write_general_text(" to thread: ");
                        write_text(thread.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("signal sent".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::pause => {
                match self.state {
                    Entering => {
                        write_general_text("pause execution until a signal terminates the process or triggers a handler");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => unreachable!(),
                            SyscallResult::Fail(errno) => {
                                // TODO!
                                // getting here means a termination signal/signal handler was triggered
                                // this path always errors
                                // see rt_sigsuspend, similar situation
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::gettid => {
                match self.state {
                    Entering => {
                        write_general_text("get the thread id of the calling thread");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let thread = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("thread id retrieved: ".green());
                                write_text(thread.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getpid => {
                match self.state {
                    Entering => {
                        write_general_text("get the process id of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let pid = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("process id retrieved: ".green());
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getppid => {
                match self.state {
                    Entering => {
                        write_general_text("get the process id of the parent process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let pid = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("parent process id retrieved: ".green());
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::get_robust_list => {
                let process_id = parse_as_int(registers[0]);
                let len_ptr = registers[2];
                match self.state {
                    Entering => {
                        write_general_text("get the list of the robust futexes for ");
                        if process_id == 0 {
                            write_text("the calling thread".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text("thread: ");
                            write_text(process_id.to_string().custom_color(*PAGES_COLOR));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("list retrieved with length ".green());
                                let parsed_length =
                                    match read_one_word(len_ptr as usize, self.tracee_pid) {
                                        Some(word) => lower_64_bits(word)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                        None => "[intentrace: could not get robust list length]"
                                            .blink()
                                            .bright_black(),
                                    };
                                write_text(parsed_length.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::set_robust_list => {
                let address = parse_as_address(registers[0] as usize);
                let length_of_list = registers[1];
                match self.state {
                    Entering => {
                        write_general_text(
                            "set the calling thread's robust futexes list to the list at ",
                        );
                        write_text(address.custom_color(*OUR_YELLOW));
                        write_general_text(" with length ");
                        write_text(length_of_list.to_string().custom_color(*PAGES_COLOR));
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successfully set robust list".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::setpgid => {
                let process_id = parse_as_int(registers[0]);
                let new_pgid = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        if process_id == 0 {
                            write_general_text("set the process group ID of ");
                            write_text("the calling thread".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text("set the process group ID of process: ");
                            write_text(process_id.to_string().custom_color(*PAGES_COLOR));
                        }
                        if new_pgid == 0 {
                            write_general_text(" to: ");
                            write_text("the calling process' ID".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text(" to: ");
                            write_text(new_pgid.to_string().custom_color(*PAGES_COLOR));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getpgid => {
                let process_id = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        if process_id == 0 {
                            write_general_text("get the process group ID of ");
                            write_text("the calling thread".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text("get the process group ID of process: ");
                            write_text(process_id.to_string().custom_color(*PAGES_COLOR));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let pgid = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("group id retrieved: ".green());
                                write_text(pgid.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getpgrp => {
                match self.state {
                    Entering => {
                        write_general_text("get the process group ID of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let pgid = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("group id retrieved: ".green());
                                write_text(pgid.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getrandom => {
                let bytes_num = registers[1];
                let bytes = parse_as_unsigned_bytes(registers[1]);
                let random_flags = lower_32_bits(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("get ");
                        write_text(bytes.custom_color(*OUR_YELLOW));
                        write_general_text(" of random bytes from the ");
                        if (random_flags & GRND_RANDOM) == GRND_RANDOM {
                            write_text("random source".custom_color(*OUR_YELLOW));
                            write_general_text(" and ");
                            if (random_flags & GRND_NONBLOCK) == GRND_NONBLOCK {
                                write_text(
                                    "do not block if the random source is empty"
                                        .custom_color(*OUR_YELLOW),
                                );
                            } else {
                                write_text(
                                    "block if the random source is empty".custom_color(*OUR_YELLOW),
                                );
                            }
                        } else {
                            write_text("urandom source".custom_color(*OUR_YELLOW));
                            write_general_text(" and ");
                            if (random_flags & GRND_NONBLOCK) == GRND_NONBLOCK {
                                write_text(
                                    "do not block if the random source is empty"
                                        .custom_color(*OUR_YELLOW),
                                );
                            } else {
                                write_text(
                                    "block if the random source is empty".custom_color(*OUR_YELLOW),
                                );
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let bytes_retrieved = parse_as_ssize_t(syscall_return as usize);
                                write_general_text(" |=> ");
                                if bytes_retrieved == 0 {
                                    write_text("retrieved ".green());
                                    write_text(
                                        bytes_retrieved.to_string().custom_color(*PAGES_COLOR),
                                    );
                                    // TODO!
                                    // scrutinize
                                    // the reason casting bytes_num from usize to isize here isnt troublesome
                                    // is because linux limits the read write limits to PTRDIFF_MAX
                                    // which is equal to isize::MAX anyways
                                } else if bytes_retrieved < parse_as_ssize_t(bytes_num as usize) {
                                    write_text("retrieved ".green());
                                    write_text(
                                        bytes_retrieved.to_string().custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" (fewer than requested)".green());
                                } else {
                                    write_text("retrieved all ".green());
                                    write_text(
                                        bytes_retrieved.to_string().custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" (complete)".green());
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::setrlimit => {
                let resource = lower_32_bits(registers[0]);
                let rlim = registers[1];
                match self.state {
                    Entering => {
                        write_general_text("set the process's ");
                        write_general_text(" limits for ");
                        self.resource_matcher(resource);
                        let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                            rlim as usize,
                            self.tracee_pid as _,
                        )
                        .unwrap();
                        write_general_text(" to ");
                        match resource {
                            RLIMIT_AS => {
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_CORE => {
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_CPU => {
                                // maximum time in seconds to use in the CPU
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" seconds".custom_color(*OUR_YELLOW));
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" seconds".custom_color(*OUR_YELLOW));
                            }
                            RLIMIT_DATA => {
                                // maximum data segment size
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_FSIZE => {
                                // maximum allowed size of files to creates
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_NOFILE => {
                                // maximum allowed open file descriptors
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" fds".custom_color(*OUR_YELLOW));
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" fds".custom_color(*OUR_YELLOW));
                            }
                            RLIMIT_STACK => {
                                // maximum stack size
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_LOCKS => {
                                // maximum number of flock() locks and fcntl() leases
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_MEMLOCK => {
                                // maximum amount of memory that can be locked
                                // affects mlock
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_MSGQUEUE => {
                                // maximum number of bytes to use on message queues
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_NICE => {
                                // maximum nice value
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_NPROC => {
                                // maximum number of threads
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" threads".custom_color(*OUR_YELLOW));
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" threads".custom_color(*OUR_YELLOW));
                            }
                            RLIMIT_RSS => {
                                // maximum RSS memory
                                // affects madvise
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    Bytes::from(rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_RTPRIO => {
                                // real-time priority
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            RLIMIT_RTTIME => {
                                // Specifies a limit (in microseconds) on the amount of CPU time
                                // that a process scheduled under a real-time scheduling policy
                                // may consume without making a blocking system call.
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                            }
                            RLIMIT_SIGPENDING => {
                                // maximum number of queued pending signals
                                write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" signals".custom_color(*OUR_YELLOW));
                                write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                write_text(
                                    (rlimit.rlim_cur as usize)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                                write_text(" signals".custom_color(*OUR_YELLOW));
                            }
                            _ => {}
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getrlimit => {
                let resource = lower_32_bits(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("get the soft and hard limits for the process's ");
                        self.resource_matcher(resource);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                                    registers[3] as usize,
                                    self.tracee_pid as _,
                                )
                                .unwrap();
                                match resource {
                                    RLIMIT_AS => {
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_CORE => {
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_CPU => {
                                        // maximum time in seconds to use in the CPU
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" seconds".green());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" seconds".green());
                                    }
                                    RLIMIT_DATA => {
                                        // maximum data segment size
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_FSIZE => {
                                        // maximum allowed size of files to creates
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_NOFILE => {
                                        // maximum allowed open file descriptors
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" fds".green());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" fds".green());
                                    }
                                    RLIMIT_STACK => {
                                        // maximum stack size
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_LOCKS => {
                                        // maximum number of flock() locks and fcntl() leases
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                    }
                                    RLIMIT_MEMLOCK => {
                                        // maximum amount of memory that can be locked
                                        // affects mlock
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_MSGQUEUE => {
                                        // maximum number of bytes to use on message queues
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_NICE => {
                                        // maximum nice value
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                    }
                                    RLIMIT_NPROC => {
                                        // maximum number of threads
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" threads".green());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" threads".green());
                                    }
                                    RLIMIT_RSS => {
                                        // maximum RSS memory
                                        // affects madvise
                                        write_text("soft limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                        write_text(", hard limit: ".green());
                                        write_text(
                                            Bytes::from(rlimit.rlim_cur as usize)
                                                .to_string()
                                                .blue(),
                                        );
                                    }
                                    RLIMIT_RTPRIO => {
                                        // real-time priority
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                    }
                                    RLIMIT_RTTIME => {
                                        // Specifies a limit (in microseconds) on the amount of CPU time
                                        // that a process scheduled under a real-time scheduling policy
                                        // may consume without making a blocking system call.
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" micro-seconds".green());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" micro-seconds".green());
                                    }
                                    RLIMIT_SIGPENDING => {
                                        // maximum number of queued pending signals
                                        write_text("soft limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" signals".green());
                                        write_text(", hard limit: ".green());
                                        write_text((rlimit.rlim_cur as usize).to_string().blue());
                                        write_text(" signals".green());
                                    }
                                    _ => {}
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::prlimit64 => {
                let pid = parse_as_int(registers[0]);
                let resource = lower_32_bits(registers[1]);
                let new_limit = registers[2] as *const ();
                let old_limit = registers[3] as *const ();
                let pid_of_self = pid == 0;
                match self.state {
                    Entering => match (!old_limit.is_null(), !new_limit.is_null()) {
                        (true, true) => {
                            write_general_text("set ");
                            if pid_of_self {
                                write_text("the calling process's".custom_color(*OUR_YELLOW));
                            } else {
                                write_text("process ".custom_color(*OUR_YELLOW));
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text("'s");
                            }
                            write_general_text(" limits for ");
                            self.resource_matcher(resource);
                            let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                                registers[2] as usize,
                                self.tracee_pid as _,
                            )
                            .unwrap();
                            write_general_text(" to ");
                            match resource {
                                RLIMIT_AS => {
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_CORE => {
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_CPU => {
                                    // maximum time in seconds to use in the CPU
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" seconds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" seconds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_DATA => {
                                    // maximum data segment size
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_FSIZE => {
                                    // maximum allowed size of files to creates
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NOFILE => {
                                    // maximum allowed open file descriptors
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" fds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" fds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_STACK => {
                                    // maximum stack size
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_LOCKS => {
                                    // maximum number of flock() locks and fcntl() leases
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_MEMLOCK => {
                                    // maximum amount of memory that can be locked
                                    // affects mlock
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_MSGQUEUE => {
                                    // maximum number of bytes to use on message queues
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NICE => {
                                    // maximum nice value
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NPROC => {
                                    // maximum number of threads
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" threads".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" threads".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_RSS => {
                                    // maximum RSS memory
                                    // affects madvise
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_RTPRIO => {
                                    // real-time priority
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_RTTIME => {
                                    // Specifies a limit (in microseconds) on the amount of CPU time
                                    // that a process scheduled under a real-time scheduling policy
                                    // may consume without making a blocking system call.
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_SIGPENDING => {
                                    // maximum number of queued pending signals
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" signals".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" signals".custom_color(*OUR_YELLOW));
                                }
                                _ => {}
                            }
                            write_text(", and get the old limits".custom_color(*OUR_YELLOW));
                        }
                        (true, false) => {
                            write_general_text("get the soft and hard limits for ");
                            if pid_of_self {
                                write_text("the calling process's".custom_color(*OUR_YELLOW));
                            } else {
                                write_text("process ".custom_color(*OUR_YELLOW));
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text("'s");
                            }
                            write_general_text(" ");
                            self.resource_matcher(resource);
                        }
                        (false, true) => {
                            write_general_text("set ");
                            if pid_of_self {
                                write_text("the calling process's".custom_color(*OUR_YELLOW));
                            } else {
                                write_text("process ".custom_color(*OUR_YELLOW));
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text("'s");
                            }
                            write_general_text(" limits for ");
                            self.resource_matcher(resource);
                            let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                                registers[2] as usize,
                                self.tracee_pid as _,
                            )
                            .unwrap();
                            write_general_text(" to ");
                            match resource {
                                RLIMIT_AS => {
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_CORE => {
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_CPU => {
                                    // maximum time in seconds to use in the CPU
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" seconds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" seconds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_DATA => {
                                    // maximum data segment size
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_FSIZE => {
                                    // maximum allowed size of files to creates
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NOFILE => {
                                    // maximum allowed open file descriptors
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" fds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" fds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_STACK => {
                                    // maximum stack size
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_LOCKS => {
                                    // maximum number of flock() locks and fcntl() leases
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_MEMLOCK => {
                                    // maximum amount of memory that can be locked
                                    // affects mlock
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_MSGQUEUE => {
                                    // maximum number of bytes to use on message queues
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NICE => {
                                    // maximum nice value
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_NPROC => {
                                    // maximum number of threads
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" threads".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" threads".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_RSS => {
                                    // maximum RSS memory
                                    // affects madvise
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        Bytes::from(rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_RTPRIO => {
                                    // real-time priority
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                }
                                RLIMIT_RTTIME => {
                                    // Specifies a limit (in microseconds) on the amount of CPU time
                                    // that a process scheduled under a real-time scheduling policy
                                    // may consume without making a blocking system call.
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" micro-seconds".custom_color(*OUR_YELLOW));
                                }
                                RLIMIT_SIGPENDING => {
                                    // maximum number of queued pending signals
                                    write_text("soft limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" signals".custom_color(*OUR_YELLOW));
                                    write_text(", hard limit: ".custom_color(*OUR_YELLOW));
                                    write_text(
                                        (rlimit.rlim_cur as usize)
                                            .to_string()
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    write_text(" signals".custom_color(*OUR_YELLOW));
                                }
                                _ => {}
                            }
                        }
                        (false, false) => {
                            // TODO!
                            // investigate
                            write_general_text("do not retrieve or set any soft/hard limits ");
                            write_general_text(
                                "[intentrace: redundant syscall (won't do anything)]",
                            );
                        }
                    },
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                match (!old_limit.is_null(), !new_limit.is_null()) {
                                    (true, true) => {
                                        write_text("successfully set new limits, ".green());

                                        let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                                            registers[3] as usize,
                                            self.tracee_pid as _,
                                        )
                                        .unwrap();
                                        match resource {
                                            RLIMIT_AS => {
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_CORE => {
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_CPU => {
                                                // maximum time in seconds to use in the CPU
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" seconds".green());
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" seconds".green());
                                            }
                                            RLIMIT_DATA => {
                                                // maximum data segment size
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_FSIZE => {
                                                // maximum allowed size of files to creates
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NOFILE => {
                                                // maximum allowed open file descriptors
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" fds".green());
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" fds".green());
                                            }
                                            RLIMIT_STACK => {
                                                // maximum stack size
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_LOCKS => {
                                                // maximum number of flock() locks and fcntl() leases
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_MEMLOCK => {
                                                // maximum amount of memory that can be locked
                                                // affects mlock
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_MSGQUEUE => {
                                                // maximum number of bytes to use on message queues
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NICE => {
                                                // maximum nice value
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NPROC => {
                                                // maximum number of threads
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" threads".green());
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" threads".green());
                                            }
                                            RLIMIT_RSS => {
                                                // maximum RSS memory
                                                // affects madvise
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_RTPRIO => {
                                                // real-time priority
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_RTTIME => {
                                                // Specifies a limit (in microseconds) on the amount of CPU time
                                                // that a process scheduled under a real-time scheduling policy
                                                // may consume without making a blocking system call.
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" micro-seconds".green());
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" micro-seconds".green());
                                            }
                                            RLIMIT_SIGPENDING => {
                                                // maximum number of queued pending signals
                                                write_text("previous soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" signals".green());
                                                write_text(", previous hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" signals".green());
                                            }
                                            _ => {}
                                        }
                                    }
                                    (true, false) => {
                                        let rlimit = read_bytes_as_struct::<RLIMIT_SIZE, rlimit>(
                                            registers[3] as usize,
                                            self.tracee_pid as _,
                                        )
                                        .unwrap();
                                        match resource {
                                            RLIMIT_AS => {
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_CORE => {
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_CPU => {
                                                // maximum time in seconds to use in the CPU
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" seconds".green());
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" seconds".green());
                                            }
                                            RLIMIT_DATA => {
                                                // maximum data segment size
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_FSIZE => {
                                                // maximum allowed size of files to creates
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NOFILE => {
                                                // maximum allowed open file descriptors
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" fds".green());
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" fds".green());
                                            }
                                            RLIMIT_STACK => {
                                                // maximum stack size
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_LOCKS => {
                                                // maximum number of flock() locks and fcntl() leases
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_MEMLOCK => {
                                                // maximum amount of memory that can be locked
                                                // affects mlock
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_MSGQUEUE => {
                                                // maximum number of bytes to use on message queues
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NICE => {
                                                // maximum nice value
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_NPROC => {
                                                // maximum number of threads
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" threads".green());
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" threads".green());
                                            }
                                            RLIMIT_RSS => {
                                                // maximum RSS memory
                                                // affects madvise
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    Bytes::from(rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_RTPRIO => {
                                                // real-time priority
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                            }
                                            RLIMIT_RTTIME => {
                                                // Specifies a limit (in microseconds) on the amount of CPU time
                                                // that a process scheduled under a real-time scheduling policy
                                                // may consume without making a blocking system call.
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" micro-seconds".green());
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" micro-seconds".green());
                                            }
                                            RLIMIT_SIGPENDING => {
                                                // maximum number of queued pending signals
                                                write_text("soft limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" signals".green());
                                                write_text(", hard limit: ".green());
                                                write_text(
                                                    (rlimit.rlim_cur as usize)
                                                        .to_string()
                                                        .custom_color(*PAGES_COLOR),
                                                );
                                                write_text(" signals".green());
                                            }
                                            _ => {}
                                        }
                                    }
                                    (false, true) => {
                                        write_text("successfully set soft and hard limits".green());
                                    }
                                    (false, false) => {
                                        write_text("successful".green());
                                    }
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getrusage => {
                let resource = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("get resource usage metrics for ");
                        match resource {
                            RUSAGE_SELF => {
                                write_text("the calling process (sum of resource usage for all threads in the process)".custom_color(*OUR_YELLOW));
                            }
                            RUSAGE_CHILDREN => {
                                write_text("all the terminated children and further descendants of the calling process".custom_color(*OUR_YELLOW));
                            }
                            RUSAGE_THREAD => {
                                write_text("the calling thread".custom_color(*OUR_YELLOW));
                            }
                            _ => todo!(),
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                // display important values from the rusage struct
                                // struct rusage {
                                //     struct timeval ru_utime; /* user CPU time used */
                                //     struct timeval ru_stime; /* system CPU time used */
                                //     long   ru_maxrss;        /* maximum resident set size */
                                //     long   ru_ixrss;         /* integral shared memory size */
                                //     long   ru_idrss;         /* integral unshared data size */
                                //     long   ru_isrss;         /* integral unshared stack size */
                                //     long   ru_minflt;        /* page reclaims (soft page faults) */
                                //     long   ru_majflt;        /* page faults (hard page faults) */
                                //     long   ru_nswap;         /* swaps */
                                //     long   ru_inblock;       /* block input operations */
                                //     long   ru_oublock;       /* block output operations */
                                //     long   ru_msgsnd;        /* IPC messages sent */
                                //     long   ru_msgrcv;        /* IPC messages received */
                                //     long   ru_nsignals;      /* signals received */
                                //     long   ru_nvcsw;         /* voluntary context switches */
                                //     long   ru_nivcsw;        /* involuntary context switches */
                                // };
                                write_general_text(" |=> ");
                                write_text("successfully retrieved".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::sysinfo => {
                match self.state {
                    Entering => {
                        write_general_text(
                            "retrieve general system statistics (memory, swap usage, uptime, number of processes)",
                        );
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                // display important values from the sysinfo struct
                                // struct sysinfo {
                                //     long uptime;             /* Seconds since boot */
                                //     unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
                                //     unsigned long totalram;  /* Total usable main memory size */
                                //     unsigned long freeram;   /* Available memory size */
                                //     unsigned long sharedram; /* Amount of shared memory */
                                //     unsigned long bufferram; /* Memory used by buffers */
                                //     unsigned long totalswap; /* Total swap space size */
                                //     unsigned long freeswap;  /* Swap space still available */
                                //     unsigned short procs;    /* Number of current processes */
                                //     char _f[22];             /* Pads structure to 64 bytes */
                                // };
                                write_general_text(" |=> ");
                                write_text("successfully retrieved".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::times => {
                match self.state {
                    Entering => {
                        write_general_text(
                            "get time metrics for the calling process and its children",
                        );
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let clock_ticks = parse_as_int(registers[0]);
                                write_general_text(" |=> ");
                                // ~ because its not exactly system boot time
                                //
                                write_text("clock ticks since ~system boot time: ".green());
                                write_text(clock_ticks.to_string().custom_color(*PAGES_COLOR));
                                // TODO!
                                // grannular
                                // tms struct contains usertime and systemtime
                                // for parent and children (sum for all children)
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::sched_setaffinity => {
                let thread_id = parse_as_int(registers[0]);
                let cpus =
                    read_affinity_from_child(registers[2] as usize, self.tracee_pid).unwrap();
                match self.state {
                    Entering => {
                        if !cpus.is_empty() {
                            write_general_text("restrict ");
                            if thread_id == 0 {
                                write_text("the calling thread".custom_color(*OUR_YELLOW));
                            } else {
                                write_text("thread ".custom_color(*OUR_YELLOW));
                                write_text(thread_id.to_string().custom_color(*PAGES_COLOR));
                            }
                            write_general_text(" to only run on ");
                            let mut cpu_iter = cpus.into_iter();
                            write_text(
                                format!("[CPU {}]", cpu_iter.next().unwrap())
                                    .custom_color(*PAGES_COLOR),
                            );
                            for cpu in cpu_iter {
                                write_text(", ".custom_color(*OUR_YELLOW));
                                write_text(format!("[CPU {}]", cpu).custom_color(*PAGES_COLOR));
                            }
                        } else {
                            // to make it error if it happens
                            unreachable!()
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("thread successfully locked".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::sched_getaffinity => {
                let thread_id = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("retrieve the cores that ");
                        if thread_id == 0 {
                            write_text("the calling thread".custom_color(*OUR_YELLOW));
                        } else {
                            write_text("thread ".custom_color(*OUR_YELLOW));
                            write_text(thread_id.to_string().custom_color(*PAGES_COLOR));
                        }
                        write_general_text(" is allowed to run on");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("cores allowed: ".green());
                                let cpus = read_affinity_from_child(
                                    registers[2] as usize,
                                    self.tracee_pid,
                                )
                                .unwrap();
                                if cpus.is_empty() {
                                    write_general_text("None");
                                } else {
                                    let mut cpu_iter = cpus.into_iter();
                                    write_text(
                                        format!("[CPU {}]", cpu_iter.next().unwrap())
                                            .custom_color(*PAGES_COLOR),
                                    );
                                    for cpu in cpu_iter {
                                        write_text(", ".green());
                                        write_text(
                                            format!("[CPU {}]", cpu).custom_color(*PAGES_COLOR),
                                        );
                                    }
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::exit => {
                let status = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("exit the calling process with status: ");
                        if status < 0 {
                            write_text(status.to_string().red());
                        } else {
                            write_text(status.to_string().custom_color(*PAGES_COLOR));
                        }
                        //
                        //
                        // Exiting path added here
                        //
                        //
                        write_general_text(" |=> ");
                        // write_text("exit does not return".purple());
                        write_exiting(self.tracee_pid);
                        flush_buffer();
                        empty_buffer();
                        // write_text("process exited with status ".green());
                        // write_text(status.to_string().custom_color(*PAGES_COLOR));
                    }
                    _ => unreachable!(),
                }
            }
            Sysno::exit_group => {
                let status = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("exit all threads in the group with status: ");
                        if status < 0 {
                            write_text(status.to_string().red());
                        } else {
                            write_text(status.to_string().custom_color(*PAGES_COLOR));
                        }
                        //
                        //
                        // Exiting path added here
                        //
                        //
                        write_general_text(" |=> ");
                        write_exiting(self.tracee_pid);
                        flush_buffer();
                        empty_buffer();
                        // write_text("exit_group does not return".purple());
                        // print_exiting(self.tracee_pid);
                        // write_text("all threads in the group exited with status ".green());
                        // write_text(status.to_string().blue());
                    }
                    _ => unreachable!(),
                }
            }

            Sysno::ptrace => {
                let operation = lower_32_bits(registers[1]);
                match self.state {
                    Entering => {
                        match operation {
                            PTRACE_TRACEME => write_general_text(
                                "allow this process to be trace by its parent process",
                            ),
                            PTRACE_PEEKTEXT => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);

                                write_general_text("read one word at address: ");
                                write_text(addr.custom_color(*OUR_YELLOW));
                                write_general_text(" from the TEXT area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_PEEKDATA => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);

                                write_general_text("read one word at address: ");

                                write_text(addr.custom_color(*OUR_YELLOW));
                                write_general_text(" from the DATA area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_PEEKUSER => {
                                //
                                // Read a word at the address addr in the tracee's memory,
                                //
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);

                                write_general_text("read one word at address: ");
                                write_text(addr.custom_color(*OUR_YELLOW));
                                write_general_text(" from the USER area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_POKETEXT => {
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);
                                let data = parse_as_address(registers[3] as usize);

                                write_general_text("copy the word: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                                write_general_text(" to the TEXT area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" at the address: ");
                                write_text(addr.custom_color(*OUR_YELLOW));
                            }
                            PTRACE_POKEDATA => {
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);
                                let data = parse_as_address(registers[3] as usize);

                                write_general_text("copy the word: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                                write_general_text(" to the DATA area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" at the address: ");
                                write_text(addr.custom_color(*OUR_YELLOW));
                            }
                            PTRACE_POKEUSER => {
                                let addr = parse_as_address(registers[2] as usize);
                                let pid = parse_as_int(registers[1]);
                                let data = parse_as_address(registers[3] as usize);

                                write_general_text("copy the word: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                                write_general_text(" to the USER area of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" at the address: ");
                                write_text(addr.custom_color(*OUR_YELLOW));
                            }
                            PTRACE_GETREGS => {
                                let data = parse_as_address(registers[3] as usize);
                                let pid = parse_as_int(registers[1]);
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                write_general_text("copy the registers of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" into address: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                                write_general_text(" of this process's memory");
                            }
                            PTRACE_GETFPREGS => {
                                let data = parse_as_address(registers[3] as usize);
                                let pid = parse_as_int(registers[1]);
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                write_general_text(
                                    "copy the floating point registers of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" into address: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                                write_general_text(" of this process's memory");
                            }
                            PTRACE_SETREGS => {
                                // Modify the tracee's general-purpose registers, from the address data in the tracer.
                                let data = parse_as_address(registers[3] as usize);
                                let pid = parse_as_int(registers[1]);
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                write_general_text(
                                    "replace the registers of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" with the registers at: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                            }
                            PTRACE_SETFPREGS => {
                                // Modify the tracee's floating-point registers, from the address data in the tracer.
                                let data = parse_as_address(registers[3] as usize);
                                let pid = parse_as_int(registers[1]);
                                // Copy  the  tracee's  general-purpose  or floating-point registers, respectively, to the address data in the tracer.
                                write_general_text(
                                    "replace the floating point registers of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" with the registers at: ");
                                write_text(data.custom_color(*OUR_YELLOW));
                            }
                            PTRACE_ATTACH => {
                                let pid = parse_as_int(registers[1]);
                                // Attach to the process specified in pid, making it a tracee of the calling process.
                                // the tracee is sent a SIGSTOP, but will not necessarily have stopped by the completion of this call
                                write_general_text(
                                    "attach to and start tracing the process with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_SEIZE => {
                                let pid = parse_as_int(registers[1]);
                                // Attach to the process specified in pid, making it a tracee of the calling process.
                                // Unlike PTRACE_ATTACH, PTRACE_SEIZE does not stop the process.
                                // Only a PTRACE_SEIZEd process can accept PTRACE_INTERRUPT and PTRACE_LISTEN commands.
                                write_general_text(
                                    "attach to and start tracing the process with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" without stopping it");
                            }
                            PTRACE_INTERRUPT => {
                                let pid = parse_as_int(registers[1]);
                                // Stop a tracee.
                                // Currently, there's no way to trap a running ptracee short of sending a
                                // signal which has various side effects.  This patch implements
                                // PTRACE_INTERRUPT which traps ptracee without any signal or job control related side effect.
                                // https://lore.kernel.org/lkml/1308043218-23619-4-git-send-email-tj@kernel.org/
                                // PTRACE_INTERRUPT only works on tracees attached by PTRACE_SEIZE.
                                write_general_text("stop the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" without sending a signal");
                            }
                            PTRACE_DETACH => {
                                let pid = parse_as_int(registers[1]);
                                // Continue the stopped tracee like PTRACE_CONT, but first detach from it.
                                // Under Linux, a tracee can be detached in this way regardless of which  method  was  used  to initiate tracing.
                                write_general_text(
                                    "detach from and continue the execution of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_CONT => {
                                let pid = parse_as_int(registers[1]);
                                let data = parse_as_int(registers[3]);
                                write_general_text(
                                    "continue the execution of the stopped tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                if data > 0 {
                                    write_general_text(" and deliver the signal: ");
                                    let signal_as_string = parse_as_signal(data);
                                    write_text(signal_as_string.custom_color(*PAGES_COLOR));
                                }
                            }
                            PTRACE_LISTEN => {
                                let pid = parse_as_int(registers[1]);
                                // continue the stopped tracee, but prevent it from executing.
                                // The resulting state of the tracee is similar to a process which has been stopped by a SIGSTOP (or other stopping signal).
                                // See the "group-stop" subsection for additional information.
                                // PTRACE_LISTEN works only on tracees attached by PTRACE_SEIZE.
                                write_general_text("continue running the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" without resuming execution");
                            }
                            PTRACE_KILL => {
                                let pid = parse_as_int(registers[1]);
                                // requires the tracee to be in signal-delivery-stop
                                // otherwise it may not work (i.e., may complete successfully but won't kill the tracee)
                                // Send the tracee a SIGKILL to terminate it
                                write_general_text("terminate the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" with a ");
                                write_text("SIGKILL".custom_color(*OUR_YELLOW));
                                write_general_text(" signal");
                            }
                            PTRACE_SINGLESTEP => {
                                let pid = parse_as_int(registers[1]);
                                // Continue a stopped tracee like PTRACE_CONT, but the tracee now stops after execution of a single instruction
                                write_general_text(
                                    "continue the execution of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" and stop again after one instruction");
                            }
                            PTRACE_SYSCALL => {
                                let pid = parse_as_int(registers[1]);
                                // Continue a stopped tracee like PTRACE_CONT, but the tracee now stops at the next entry to or exit from a system call
                                write_general_text(
                                    "continue the execution of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(
                                    " and stop again after the next syscall entry/exit",
                                );
                            }
                            PTRACE_SETOPTIONS => {
                                // TODO!
                                // consider providing more information similar to clone3?
                                let pid = parse_as_int(registers[1]);
                                write_general_text(
                                    "set the tracing options for the process with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_GETEVENTMSG => {
                                let pid = parse_as_int(registers[1]);
                                // Retrieve a message about the ptrace event that just happened (as an unsigned long)
                                // For PTRACE_EVENT_EXIT, this is the tracee's exit status
                                // For PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE, and PTRACE_EVENT_CLONE, this is the PID of the new process
                                // For PTRACE_EVENT_SECCOMP, this is the seccomp(2) filter's SECCOMP_RET_DATA associated with the triggered rule (addr is ignored)
                                write_general_text(
                                    "retrieve additional information about the most recent event from the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_GETREGSET => {
                                let pid = parse_as_int(registers[1]);
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
                                write_general_text(
                                    "retrieve the registers of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_SETREGSET => {
                                let pid = parse_as_int(registers[1]);
                                // Modify the tracee's registers
                                // The meaning of addr and data is analogous to PTRACE_GETREGSET
                                write_general_text("modify the registers of the tracee with pid: ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_GETSIGINFO => {
                                let pid = parse_as_int(registers[1]);
                                // PTRACE_GETSIGINFO
                                // get information about the signal that caused the stop.
                                // Copies a siginfo_t structure (see sigaction(2)) from the tracee to the address data in the tracer.
                                //  	(addr is ignored.)
                                //   PTRACE_GETSIGINFO
                                // can be used to retrieve a siginfo_t structure which corresponds to the delivered signal.

                                write_general_text(
                                    "retrieve information about the signal that stopped the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_SETSIGINFO => {
                                let pid = parse_as_int(registers[1]);
                                // PTRACE_SETSIGINFO
                                // Set signal information: copy a siginfo_t structure from the address data in the tracer to the tracee. This will affect only signals that would normally be delivered to the tracee and were caught by the tracer. It may be difficult to tell these normal signals from synthetic signals generated by ptrace() itself (addr is ignored)

                                //  PTRACE_SETSIGINFO may be used to modify it.
                                //  If PTRACE_SETSIGINFO has been used to alter siginfo_t,
                                //  the si_signo field and the sig parameter in the restarting command must match, otherwise the result is undefined.

                                write_general_text(
                                    "modify information about the signal to be delivered to the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                            PTRACE_PEEKSIGINFO => {
                                let pid = parse_as_int(registers[1]);
                                // Retrieve siginfo_t structures without removing signals from a queue
                                // struct ptrace_peeksiginfo_args {
                                //  	u64 off; 	/* Ordinal position in queue at which to start copying signals */
                                //  	u32 flags; /* PTRACE_PEEKSIGINFO_SHARED or 0 */
                                //  	s32 nr; 	 /* Number of signals to copy */
                                // };

                                // by default signals are read from the specific thread's own queue
                                // but if PTRACE_PEEKSIGINFO_SHARED is used then process-wide signal queue is read
                                write_general_text(
                                    "retrieve information about a signal from the signal queue of the tracee with pid: ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                                write_general_text(" without removing it from the queue");
                            }
                            //
                            PTRACE_SYSEMU => unimplemented!(),
                            PTRACE_SYSEMU_SINGLESTEP => unimplemented!(),
                            PTRACE_GETFPXREGS => unimplemented!(),
                            PTRACE_SETFPXREGS => unimplemented!(),
                            _ => todo!(),
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                match operation {
                                    PTRACE_TRACEME => {
                                        write_text(
                                            "process can be traced by its parent now".green(),
                                        );
                                    }
                                    PTRACE_PEEKTEXT => {
                                        write_text("successfully read one word".green());
                                    }
                                    PTRACE_PEEKDATA => {
                                        write_text("successfully read one word".green());
                                    }
                                    PTRACE_PEEKUSER => {
                                        write_text("successfully read one word".green());
                                    }
                                    PTRACE_POKETEXT => {
                                        write_text("successfully copied one word".green());
                                    }
                                    PTRACE_POKEDATA => {
                                        write_text("successfully copied one word".green());
                                    }
                                    PTRACE_POKEUSER => {
                                        write_text("successfully copied one word".green());
                                    }
                                    PTRACE_GETREGS => {
                                        write_text("registers copied".green());
                                    }
                                    PTRACE_GETFPREGS => {
                                        write_text("registers copied".green());
                                    }
                                    PTRACE_SETREGS => {
                                        write_text("registers modifed".green());
                                    }
                                    PTRACE_SETFPREGS => {
                                        write_text("registers modifed".green());
                                    }
                                    PTRACE_ATTACH => {
                                        write_text("process attached".green());
                                    }
                                    PTRACE_SEIZE => {
                                        write_text("process seized".green());
                                    }
                                    PTRACE_INTERRUPT => {
                                        write_text("tracee stopped".green());
                                    }
                                    PTRACE_DETACH => {
                                        write_text(
                                            "detached from the process and execution continued"
                                                .green(),
                                        );
                                    }
                                    PTRACE_CONT => {
                                        write_text("execution continued".green());
                                    }
                                    PTRACE_LISTEN => {
                                        write_text("tracee continued".green());
                                    }
                                    PTRACE_KILL => {
                                        write_text("tracee terminated".green());
                                    }
                                    PTRACE_SINGLESTEP => {
                                        write_text("execution continued".green());
                                    }
                                    PTRACE_SYSCALL => {
                                        write_text("execution continued".green());
                                    }
                                    PTRACE_SETOPTIONS => {
                                        write_text("options set".green());
                                    }
                                    PTRACE_GETEVENTMSG => {
                                        write_text("information retrieved".green());
                                    }
                                    PTRACE_GETREGSET => {
                                        write_text("registers retrieved".green());
                                    }
                                    PTRACE_SETREGSET => {
                                        write_text("registers modified".green());
                                    }
                                    PTRACE_GETSIGINFO => {
                                        write_text("signal information retrieved".green());
                                    }
                                    PTRACE_SETSIGINFO => {
                                        write_text("signal information modified".green());
                                    }
                                    PTRACE_PEEKSIGINFO => {
                                        write_text("signal information retrieved".green());
                                    }
                                    //
                                    PTRACE_SYSEMU => unimplemented!(),
                                    PTRACE_SYSEMU_SINGLESTEP => unimplemented!(),
                                    PTRACE_GETFPXREGS => unimplemented!(),
                                    PTRACE_SETFPXREGS => unimplemented!(),
                                    _ => todo!(),
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::rseq => {
                // TODO!
                // scrutinize
                let rseq_flag = registers[2];
                let registering = rseq_flag == 0;
                match self.state {
                    Entering => {
                        if registering {
                            write_general_text("register a per-thread shared data structure between kernel and user-space",
                    );
                        } else {
                            write_general_text("unregister a previously registered per-thread shared data structure",
                    );
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                if registering {
                                    write_text("successfully registered".green());
                                } else {
                                    write_text("successfully unregistered".green());
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::uname => {
                match self.state {
                    Entering => {
                        write_general_text("retrieve general system information");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("successfully retrieved".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getuid => {
                match self.state {
                    Entering => {
                        write_general_text("get the real user ID of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let user_id = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("real user ID retrieved: ".green());
                                write_text(user_id.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::geteuid => {
                match self.state {
                    Entering => {
                        write_general_text("get the effective user ID of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let effective_user_id = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("effective user ID retrieved: ".green());
                                write_text(
                                    effective_user_id.to_string().custom_color(*PAGES_COLOR),
                                );
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getgid => {
                match self.state {
                    Entering => {
                        write_general_text("get the real group ID of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let real_group_id = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("real group ID retrieved: ".green());
                                write_text(real_group_id.to_string().custom_color(*PAGES_COLOR));
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getegid => {
                match self.state {
                    Entering => {
                        write_general_text("get the effective group ID of the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let effective_group_id = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("effective group ID retrieved: ".green());
                                write_text(
                                    effective_group_id.to_string().custom_color(*PAGES_COLOR),
                                );
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::shutdown => {
                // let socket = parse_as_int(registers[0]);
                let socket = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let shutdown_how_num = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        if shutdown_how_num == 0 {
                            // SHUT_RD = 0
                            write_general_text("stop incoming reception of data into the socket: ");
                            write_text(socket.custom_color(*PAGES_COLOR));
                        } else if shutdown_how_num == 1 {
                            // SHUT_WR = 1
                            write_general_text(
                                "stop outgoing transmission of data from the socket: ",
                            );
                            write_text(socket.custom_color(*PAGES_COLOR));
                        } else if shutdown_how_num == 2 {
                            // SHUT_RDWR = 2
                            write_general_text("terminate incoming and outgoing data communication with the socket: ");
                            write_text(socket.custom_color(*PAGES_COLOR));
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::futex => {
                let uaddr_address = parse_as_address(registers[0] as usize);
                let futex_op = parse_as_int(registers[1]);
                let val = lower_32_bits(registers[2]);
                // timespec_or_val2
                let timespec_or_val2 = registers[3];
                let uaddr2_address = parse_as_address(registers[4] as usize);
                let val3 = lower_32_bits(registers[5]);
                match self.state {
                    Entering => {
                        // TODO!
                        // timeout information currently isnt handled

                        // futex flags have an operation part and an options part
                        //
                        // this mask gets rid of the options
                        let operations_only_mask = 0b01111111;
                        if (futex_op & operations_only_mask) == FUTEX_WAIT {
                            write_text(
                                "block and wait for FUTEX_WAKE if comparison succeeds"
                                    .custom_color(*OUR_YELLOW),
                            );
                        } else if (futex_op & operations_only_mask) == FUTEX_WAKE {
                            write_general_text("wake a maximum of ");
                            write_text(val.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(" waiters waiting on the futex at ");
                            write_text(uaddr_address.custom_color(*OUR_YELLOW));
                        } else if (futex_op & operations_only_mask) == FUTEX_FD {
                            write_general_text("create a file descriptor for the futex at ");
                            write_text(uaddr_address.custom_color(*OUR_YELLOW));
                            write_general_text(" to use with asynchronous syscalls");
                        } else if (futex_op & operations_only_mask) == FUTEX_CMP_REQUEUE {
                            write_general_text("if comparison succeeds wake a maximum of ");
                            write_text(val.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(" waiters waiting on the futex at ");
                            write_text(uaddr_address.custom_color(*OUR_YELLOW));
                            write_general_text(" and requeue a maximum of ");
                            write_text(
                                lower_32_bits(timespec_or_val2)
                                    .to_string()
                                    .custom_color(*PAGES_COLOR),
                            );
                            write_general_text(" from the remaining waiters to the futex at ");
                            write_text(uaddr2_address.custom_color(*OUR_YELLOW));
                        } else if (futex_op & operations_only_mask) == FUTEX_REQUEUE {
                            write_general_text("without comparing wake a maximum of ");
                            write_text(val.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(" waiters waiting on the futex at ");
                            write_text(uaddr_address.custom_color(*OUR_YELLOW));
                            write_general_text(" and requeue a maximum of ");
                            write_text(
                                lower_32_bits(timespec_or_val2)
                                    .to_string()
                                    .custom_color(*PAGES_COLOR),
                            );
                            write_general_text(" from the remaining waiters to the futex at ");
                            write_text(uaddr2_address.custom_color(*OUR_YELLOW));
                        } else if (futex_op & operations_only_mask) == FUTEX_WAKE_OP {
                            write_general_text("operate on 2 futexes at the same time");
                        } else if (futex_op & operations_only_mask) == FUTEX_WAIT_BITSET {
                            write_general_text("if comparison succeeds block and wait for FUTEX_WAKE and register a bitmask for selective waiting");
                        } else if (futex_op & operations_only_mask) == FUTEX_WAKE_BITSET {
                            write_general_text("wake a maximum of ");
                            write_text(val.to_string().custom_color(*PAGES_COLOR));
                            write_general_text(" waiters waiting on the futex at ");
                            write_text(uaddr_address.custom_color(*OUR_YELLOW));
                            write_text(
                                " from the provided waiters bitmask".custom_color(*OUR_YELLOW),
                            );
                        } else if (futex_op & operations_only_mask) == FUTEX_LOCK_PI {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_op & operations_only_mask) == FUTEX_LOCK_PI2 {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_op & operations_only_mask) == FUTEX_TRYLOCK_PI {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_op & operations_only_mask) == FUTEX_UNLOCK_PI {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_op & operations_only_mask) == FUTEX_CMP_REQUEUE_PI {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else if (futex_op & operations_only_mask) == FUTEX_WAIT_REQUEUE_PI {
                            write_general_text("priority-inheritance futex operation ");
                            write_text("[intentrace: needs granularity]".bright_black());
                        } else {
                            write_text("[intentrace: unknown flag]".bright_black());
                        }
                        // TODO! Priority-inheritance futexes
                        let mut directives = vec![];
                        if (futex_op & FUTEX_PRIVATE_FLAG) == FUTEX_PRIVATE_FLAG {
                            directives.push(
                                "only use futex between threads of the same process"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (futex_op & FUTEX_CLOCK_REALTIME) == FUTEX_CLOCK_REALTIME {
                            directives.push(
                                "measure timeout using the CLOCK_REALTIME"
                                    .custom_color(*OUR_YELLOW),
                            );
                        } else {
                            directives.push(
                                "measure timeout using CLOCK_MONOTONIC".custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::set_tid_address => {
                let thread_address = registers[0];
                match self.state {
                    Entering => {
                        write_general_text("set `clear_child_tid` for the calling thread to ");
                        let thread_id =
                            match read_one_word(thread_address as usize, self.tracee_pid) {
                                Some(word) => parse_as_int(lower_64_bits(word))
                                    .to_string()
                                    .custom_color(*PAGES_COLOR),
                                None => "[intentrace: could not read thread_id]"
                                    .blink()
                                    .bright_black(),
                            };
                        write_text(thread_id);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("thread id of the calling thread: ".green());
                                let callers_thread_id = parse_as_int(syscall_return);
                                write_text(
                                    callers_thread_id.to_string().custom_color(*PAGES_COLOR),
                                );
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::eventfd => {
                let initval = parse_as_int(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("create a file descriptor for notifications/waiting");
                        write_general_text(" (");
                        write_general_text("initialize the count value to: ");
                        write_text(initval.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(")");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let file_descriptor =
                                    parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("created the eventfd: ".green());
                                write_path_file(file_descriptor);
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::eventfd2 => {
                let initval = parse_as_int(registers[0]);
                let flags = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        // TODO!
                        // revise wording
                        // write_general_text("create a file descriptor for notifications/waiting");
                        write_general_text("create an eventfd with the count value set to: ");
                        // write_general_text(" (");
                        // write_general_text("initialize the count value to: ");
                        write_text(initval.to_string().custom_color(*PAGES_COLOR));
                        // write_general_text(")");
                        let mut directives = vec![];
                        if (flags & EFD_CLOEXEC) == EFD_CLOEXEC {
                            directives.push(
                                "close the file with the next exec syscall"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & EFD_NONBLOCK) == EFD_NONBLOCK {
                            directives.push(
                                "use the file on non blocking mode".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & EFD_SEMAPHORE) == EFD_SEMAPHORE {
                            directives.push(
                                "utilize semaphore-like semantics when reading"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let file_descriptor =
                                    parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                write_general_text(" |=> ");
                                write_text("created the eventfd: ".green());
                                write_path_file(file_descriptor);
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::waitid => {
                let id_type = lower_32_bits(registers[0]);
                let id = parse_as_int(registers[1]);
                let options = parse_as_int(registers[3]);
                let rusage = registers[4] as *const ();
                match self.state {
                    Entering => {
                        match id_type {
                            P_ALL => {
                                write_general_text("wait until any child ");
                            }
                            P_PGID => {
                                if id == 0 {
                                    write_general_text(
                                        "wait until any child in the current process group ",
                                    );
                                } else {
                                    write_general_text("wait until any child process with PGID ");
                                    write_text(id.to_string().custom_color(*PAGES_COLOR));
                                }
                            }
                            P_PID => {
                                write_general_text("wait until child process ");
                                write_text(id.to_string().custom_color(*PAGES_COLOR));
                            }
                            P_PIDFD => {
                                write_general_text("wait until child with PIDFD ");
                                write_text(id.to_string().custom_color(*PAGES_COLOR));
                            }
                            _ => unreachable!(),
                        }
                        write_general_text(" ");
                        let mut options_ticked = vec![];
                        if (options & WEXITED) == WEXITED {
                            options_ticked.push("exits".custom_color(*OUR_YELLOW));
                        }
                        if (options & WSTOPPED) == WSTOPPED {
                            options_ticked.push("is stopped by a signal".custom_color(*OUR_YELLOW));
                        }
                        if (options & WCONTINUED) == WCONTINUED {
                            options_ticked.push("is resumed by ".custom_color(*OUR_YELLOW));
                            options_ticked.push("SIGCONT".custom_color(*PAGES_COLOR));
                        }
                        write_oring(options_ticked);

                        let mut options_directives = vec![];

                        if (options & __WNOTHREAD) == __WNOTHREAD {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            options_directives.push(
                                "only wait on this thread's children".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (options & __WALL) == __WALL {
                            /// Wait on all children, regardless of type
                            options_directives
                                .push("wait on all children".custom_color(*OUR_YELLOW));
                        }
                        if (options & __WCLONE) == __WCLONE {
                            /// Wait for "clone" children only.
                            options_directives
                                .push("wait for clone children only".custom_color(*OUR_YELLOW));
                        }
                        if (options & WNOWAIT) == WNOWAIT {
                            options_directives.push(
                                "return immediately if no child exited".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (options & WNOHANG) == WNOHANG {
                            options_directives.push(
                                "leave the child in a waitable state".custom_color(*OUR_YELLOW),
                            );
                        }
                        if !rusage.is_null() {
                            options_directives.push(
                                "retrieve child resource usage data".custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(options_directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("Successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::wait4 => {
                let pid = parse_as_int(registers[0]);
                let wstatus_address = registers[1];
                let options = parse_as_int(registers[2]);
                match self.state {
                    Entering => {
                        let mut options_ticked = vec![];
                        if (options & WEXITED) == WEXITED {
                            options_ticked.push("exits".custom_color(*OUR_YELLOW));
                        }
                        if (options & WSTOPPED) == WSTOPPED {
                            options_ticked.push("is stopped by a signal".custom_color(*OUR_YELLOW));
                        }
                        if (options & WCONTINUED) == WCONTINUED {
                            options_ticked.push("is resumed by ".custom_color(*OUR_YELLOW));
                            options_ticked.push("SIGCONT".custom_color(*PAGES_COLOR));
                        }

                        if options_ticked.is_empty() {
                            if pid < -1 {
                                write_general_text(
                                    "wait for state change in any child with process group ID ",
                                );
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            } else if pid == -1 {
                                write_general_text("wait for state change in any child");
                            } else if pid == 0 {
                                write_general_text("wait for state change in any child with a similar process group ID",
                                );
                            } else {
                                write_general_text("wait for state change in child process ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }
                        } else {
                            if pid < -1 {
                                write_general_text("wait until any child with process group ID ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            } else if pid == -1 {
                                write_general_text("wait until any child");
                            } else if pid == 0 {
                                write_general_text(
                                    "wait until any child with a similar process group ID",
                                );
                            } else {
                                write_general_text("wait until child process ");
                                write_text(pid.to_string().custom_color(*PAGES_COLOR));
                            }

                            write_general_text(" ");
                            write_oring(options_ticked);
                        }

                        let mut directives = vec![];
                        if (options & __WNOTHREAD) == __WNOTHREAD {
                            /// Don't wait on children of other threads in this group
                            /// Do not wait for children of other threads in the same thread group.
                            directives.push(
                                "only wait on this thread's children".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (options & __WALL) == __WALL {
                            /// Wait on all children, regardless of type
                            directives.push("wait on all children".custom_color(*OUR_YELLOW));
                        }
                        if (options & __WCLONE) == __WCLONE {
                            /// Wait for "clone" children only.
                            directives
                                .push("wait for clone children only".custom_color(*OUR_YELLOW));
                        }
                        write_directives(directives);

                        let mut retrieves = vec![];
                        if wstatus_address != 0 {
                            retrieves.push("exit status".custom_color(*OUR_YELLOW));
                        }
                        let rusage = registers[3];
                        if rusage != 0 {
                            retrieves.push("resource usage metrics".custom_color(*OUR_YELLOW));
                        }

                        if !retrieves.is_empty() {
                            write_general_text(" (");
                            write_general_text("retrieve the child's ");
                            write_anding(retrieves);
                            write_general_text(")");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let child_pid = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                if wstatus_address == 0 {
                                    write_text("successful".green());
                                } else {
                                    match read_one_word(wstatus_address as usize, self.tracee_pid) {
                                        Some(word) => {
                                            let wstatus = parse_as_int(word as u64);
                                            // TODO! this is a workaround because nix's waitstatus resolver errors with EINVAL very often
                                            if nix::libc::WIFEXITED(wstatus) {
                                                let status = nix::libc::WEXITSTATUS(wstatus);
                                                write_text(
                                                    "process exited with status code: ".green(),
                                                );
                                                write_text(status.to_string().blue());
                                            } else if nix::libc::WIFSIGNALED(wstatus) {
                                                let signal = parse_as_signal(wstatus);
                                                write_text("process was killed by ".green());
                                                write_text(signal.to_string().blue());
                                                if nix::libc::WCOREDUMP(wstatus) {
                                                    write_general_text(" ");
                                                    write_text("(core dumped)".green());
                                                }
                                            } else if nix::libc::WIFSTOPPED(wstatus) {
                                                // TODO! Granularity needed here, this is currently a workaround
                                                write_text("process was stopped".green());
                                                // write_text("process was stopped by ".green());
                                                // write_text(signal.to_string().blue());
                                            } else {
                                                write_text(
                                                    "process was resumed from a stop state by "
                                                        .green(),
                                                );
                                                write_text("SIGCONT".blue());
                                            }

                                            // let wait_status = nix::sys::wait::WaitStatus::from_raw(
                                            //     Pid::from_raw(child_pid),
                                            //     wstatus,
                                            // )
                                            // .unwrap();
                                            // match wait_status {
                                            //     nix::sys::wait::WaitStatus::Exited(
                                            //         pid,
                                            //         status_code,
                                            //     ) => {
                                            //         write_text(
                                            //             "process exited with status code: ".green(),
                                            //         );
                                            //         write_text(status_code.to_string().blue());
                                            //     }
                                            //     nix::sys::wait::WaitStatus::Signaled(
                                            //         pid,
                                            //         signal,
                                            //         core_dump,
                                            //     ) => {
                                            //         write_text("process was killed by ".green());
                                            //         write_text(signal.to_string().blue());
                                            //         if core_dump {
                                            //             write_general_text(" ");
                                            //             write_text("(core dumped)".green());
                                            //         }
                                            //     }
                                            //     nix::sys::wait::WaitStatus::Stopped(
                                            //         pid,
                                            //         signal,
                                            //     ) => {
                                            //         write_text("process was stopped by ".green());
                                            //         write_text(signal.to_string().blue());
                                            //     }
                                            //     nix::sys::wait::WaitStatus::PtraceEvent(
                                            //         pid,
                                            //         signal,
                                            //         ptrace_event,
                                            //     ) => {
                                            //         write_text("process was stopped by a ".green());
                                            //         write_text(signal.to_string().blue());
                                            //         write_general_text(" signal due to ");
                                            //         let ptrace: nix::sys::ptrace::Event =
                                            //             unsafe { mem::transmute(ptrace_event) };
                                            //         write_text(format!("{:?}", ptrace).green());
                                            //     }
                                            //     nix::sys::wait::WaitStatus::PtraceSyscall(pid) => {
                                            //         write_text("process stopped by ".green());
                                            //         write_text("PTRACE_O_TRACESYSGOOD".blue());
                                            //         write_text(
                                            //             " while executing a syscall".green(),
                                            //         );
                                            //     }
                                            //     nix::sys::wait::WaitStatus::Continued(pid) => {
                                            //         write_text(
                                            //             "process was resumed from a stop state by "
                                            //                 .green(),
                                            //         );
                                            //         write_text("SIGCONT".blue());
                                            //     }
                                            //     nix::sys::wait::WaitStatus::StillAlive => {
                                            //         write_text(
                                            //             "no state changes to report".green(),
                                            //         );
                                            //     }
                                            // }
                                        }
                                        None => write_text(
                                            "[intentrace: could not get wstatus]"
                                                .blink()
                                                .bright_black(),
                                        ),
                                    };
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::clone3 => {
                // TODO!
                // sometimes register[0] isn't a pointer, investigate later
                match self.state {
                    Entering => {
                        match read_bytes_as_struct::<CLONE3_ARGS_SIZE, clone_args>(
                            registers[0] as usize,
                            self.tracee_pid as _,
                        ) {
                            Some(cl_args) => {
                                let flags = parse_as_int(cl_args.flags);
                                if (flags & CLONE_VM) == CLONE_VM {
                                    write_general_text("spawn a new thread with a ");

                                    write_text(
                                        SyscallObject::style_bytes_page_aligned_ceil(
                                            cl_args.stack_size,
                                        )
                                        .custom_color(*OUR_YELLOW),
                                    );
                                    write_general_text(" stack starting at ");
                                    write_text(
                                        format!("0x{:x}", cl_args.stack).custom_color(*OUR_YELLOW),
                                    );
                                    // directives.push("run in the same memory space".custom_color(*OUR_YELLOW));
                                } else {
                                    write_general_text("spawn a new child process");
                                    // directives.push("copy the memory space".custom_color(*OUR_YELLOW));
                                }

                                // share with parent
                                //
                                //
                                //
                                //

                                let mut shares = vec![];
                                if (flags & CLONE_FILES) == CLONE_FILES {
                                    shares.push(
                                        "the file descriptor table".custom_color(*OUR_YELLOW),
                                    );
                                }

                                //  else {
                                //     shares.push("copy the file descriptor table".custom_color(*OUR_YELLOW));
                                // }

                                if (flags & CLONE_FS) == CLONE_FS {
                                    shares.push("filesystem information".custom_color(*OUR_YELLOW));
                                }

                                // else {
                                //     shares.push("copy filesystem information".custom_color(*OUR_YELLOW));
                                // }

                                // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                                // }

                                if (flags & CLONE_IO) == CLONE_IO {
                                    shares.push("I/O context".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_SIGHAND) == CLONE_SIGHAND {
                                    shares.push(
                                        "the table of signal handlers".custom_color(*OUR_YELLOW),
                                    );
                                }
                                //  else {
                                //     shares.push("copy the signal handlers table".custom_color(*OUR_YELLOW));
                                // }
                                if (flags & CLONE_SYSVSEM) == CLONE_SYSVSEM {
                                    shares.push("sem-adj values".custom_color(*OUR_YELLOW));
                                }
                                //  else {
                                //     shares.push("don't share sem-adj values".custom_color(*OUR_YELLOW));
                                // }

                                if !shares.is_empty() {
                                    write_general_text(" (");
                                    write_general_text("share ");
                                    write_anding(shares);
                                    write_general_text(")");
                                }

                                // execute in new
                                //
                                //
                                //
                                //
                                let mut executes = vec![];

                                if (flags & CLONE_NEWCGROUP) == CLONE_NEWCGROUP {
                                    executes.push("CGroup namespace".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_NEWIPC) == CLONE_NEWIPC {
                                    executes.push("IPC namespace".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_NEWNET) == CLONE_NEWNET {
                                    executes.push("network namespace".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_NEWNS) == CLONE_NEWNS {
                                    executes.push("mount namespace".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_NEWPID) == CLONE_NEWPID {
                                    executes.push("PID namespace".custom_color(*OUR_YELLOW));
                                }
                                // if clone_flags.contains(clone3::Flags::NEWTIME) {
                                // }
                                if (flags & CLONE_NEWUSER) == CLONE_NEWUSER {
                                    executes.push("user namespace".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_NEWUTS) == CLONE_NEWUTS {
                                    executes.push("UTS namespace".custom_color(*OUR_YELLOW));
                                }

                                if !executes.is_empty() {
                                    write_general_text(" (");
                                    write_general_text("execute in a new ");
                                    write_anding(executes);
                                    write_general_text(")");
                                }

                                let mut directives = vec![];

                                if (flags & CLONE_PARENT) == CLONE_PARENT {
                                    directives
                                        .push("inherit the same parent".custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_PARENT_SETTID) == CLONE_PARENT_SETTID {
                                    directives.push(
                                        "store the child TID in the parent's memory"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                                // It is currently not possible to use this flag together with CLONE_THREAD. This
                                // means that the process identified by the PID file descriptor will always be a
                                // thread group leader.
                                if (flags & CLONE_PIDFD) == CLONE_PIDFD {
                                    directives.push(
                                        "return a PIDFD for the child".custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_PTRACE) == CLONE_PTRACE {
                                    directives.push(
                                        "allow ptracing if parent is ptraced"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_SETTLS) == CLONE_SETTLS {
                                    directives.push(
                                        "modify the thread local storage descriptor"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_THREAD) == CLONE_THREAD {
                                    directives.push(
                                        "place in the same thread group".custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    directives.push(
                                        "place in a new thread group".custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_UNTRACED) == CLONE_UNTRACED {
                                    directives.push(
                                        "prevent forcing of CLONE_PTRACE".custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_VFORK) == CLONE_VFORK {
                                    directives.push(
                                        "suspend parent execution as with vFork"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_CHILD_CLEARTID) == CLONE_CHILD_CLEARTID {
                                    directives.push(
                                "clear TID on the child's memory on exit and wake the associated futex"
                                    .custom_color(*OUR_YELLOW));
                                }
                                if (flags & CLONE_CHILD_SETTID) == CLONE_CHILD_SETTID {
                                    directives.push(
                                        "store the child TID in child's memory"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }
                                if (flags & CLONE_CLEAR_SIGHAND) == CLONE_CLEAR_SIGHAND {
                                    directives.push(
                                        "default all inherited signal handlers"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                }

                                write_directives(directives);
                            }
                            None => {
                                write_text(
                                    "[intentrace: could not get cl_args]".blink().bright_black(),
                                );
                            }
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let child_thread_id = parse_as_long(syscall_return);

                                write_general_text(" |=> ");
                                write_text("thread id of the child: ".green());
                                write_text(child_thread_id.to_string().custom_color(*PAGES_COLOR));
                                match read_bytes_as_struct::<CLONE3_ARGS_SIZE, clone_args>(
                                    registers[0] as usize,
                                    self.tracee_pid as _,
                                ) {
                                    Some(cl_args) => {
                                        let flags = parse_as_int(cl_args.flags);
                                        if (flags & CLONE_VM) == CLONE_VM {
                                            write_text(new_thread());
                                        } else {
                                            write_text(new_process());
                                        }
                                    }
                                    None => {
                                        write_text(
                                            "[intentrace: could not get cl_args]"
                                                .blink()
                                                .bright_black(),
                                        );
                                    }
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::clone => {
                // TODO!
                // revise
                // this argument is unsigned long but largest clone flag is capturable by i32
                // so its safe to parse as int
                // the linux kernel clears the upper 32 bits anyways
                // so its safe for intentrace to clear them as well
                let flags = parse_as_int(registers[0]);
                let stack = registers[1];

                match self.state {
                    Entering => {
                        if (flags & CLONE_VM) == CLONE_VM {
                            write_general_text("spawn a new thread at stack address ");
                            write_text(format!("0x{:x}", stack).custom_color(*OUR_YELLOW));
                            // directives.push("run in the same memory space".custom_color(*OUR_YELLOW));
                        } else {
                            write_general_text("spawn a new child process");
                            // directives.push("copy the memory space".custom_color(*OUR_YELLOW));
                        }

                        // share with parent
                        //
                        //
                        //
                        //

                        let mut shares = vec![];
                        if (flags & CLONE_FILES) == CLONE_FILES {
                            shares.push("the file descriptor table".custom_color(*OUR_YELLOW));
                        }

                        //  else {
                        //     shares.push("copy the file descriptor table".custom_color(*OUR_YELLOW));
                        // }

                        if (flags & CLONE_FS) == CLONE_FS {
                            shares.push("filesystem information".custom_color(*OUR_YELLOW));
                        }

                        // else {
                        //     shares.push("copy filesystem information".custom_color(*OUR_YELLOW));
                        // }

                        // if clone_flags.contains(clone3::Flags::INTO_CGROUP) {
                        // }

                        if (flags & CLONE_IO) == CLONE_IO {
                            shares.push("I/O context".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_SIGHAND) == CLONE_SIGHAND {
                            shares.push("the table of signal handlers".custom_color(*OUR_YELLOW));
                        }
                        //  else {
                        //     shares.push("copy the signal handlers table".custom_color(*OUR_YELLOW));
                        // }
                        if (flags & CLONE_SYSVSEM) == CLONE_SYSVSEM {
                            shares.push("sem-adj values".custom_color(*OUR_YELLOW));
                        }
                        //  else {
                        //     shares.push("don't share sem-adj values".custom_color(*OUR_YELLOW));
                        // }

                        if !shares.is_empty() {
                            write_general_text(" (");
                            write_general_text("share ");
                            write_anding(shares);
                            write_general_text(")");
                        }

                        // execute in new
                        //
                        //
                        //
                        //
                        let mut executes = vec![];

                        if (flags & CLONE_NEWCGROUP) == CLONE_NEWCGROUP {
                            executes.push("CGroup namespace".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_NEWIPC) == CLONE_NEWIPC {
                            executes.push("IPC namespace".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_NEWNET) == CLONE_NEWNET {
                            executes.push("network namespace".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_NEWNS) == CLONE_NEWNS {
                            executes.push("mount namespace".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_NEWPID) == CLONE_NEWPID {
                            executes.push("PID namespace".custom_color(*OUR_YELLOW));
                        }
                        // (flags & CLONE_NEWTIME) ==CLONE_NEWTIME{
                        // }
                        if (flags & CLONE_NEWUSER) == CLONE_NEWUSER {
                            executes.push("user namespace".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_NEWUTS) == CLONE_NEWUTS {
                            executes.push("UTS namespace".custom_color(*OUR_YELLOW));
                        }

                        if !executes.is_empty() {
                            write_general_text(" (");
                            write_general_text("execute in a new ");
                            write_anding(executes);
                            write_general_text(")");
                        }

                        let mut directives = vec![];

                        if (flags & CLONE_PARENT) == CLONE_PARENT {
                            directives.push("inherit the same parent".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_PARENT_SETTID) == CLONE_PARENT_SETTID {
                            directives.push(
                                "store the child TID in the parent's memory"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        // It is currently not possible to use this flag together with CLONE_THREAD. This
                        // means that the process identified by the PID file descriptor will always be a
                        // thread group leader.
                        if (flags & CLONE_PIDFD) == CLONE_PIDFD {
                            directives
                                .push("return a PIDFD for the child".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_PTRACE) == CLONE_PTRACE {
                            directives.push(
                                "allow ptracing if parent is ptraced".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & CLONE_SETTLS) == CLONE_SETTLS {
                            directives.push(
                                "modify the thread local storage descriptor"
                                    .custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & CLONE_THREAD) == CLONE_THREAD {
                            directives
                                .push("place in the same thread group".custom_color(*OUR_YELLOW));
                        } else {
                            directives
                                .push("place in a new thread group".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_UNTRACED) == CLONE_UNTRACED {
                            directives
                                .push("prevent forcing of CLONE_PTRACE".custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_VFORK) == CLONE_VFORK {
                            directives.push(
                                "suspend parent execution as with vFork".custom_color(*OUR_YELLOW),
                            );
                        }
                        // CLONE_CHILD_CLEARTID, for instance, is designed to support pthread_join.
                        // What it essentially does is zero the value at ctid,
                        // then wake up threads that have called a futex_wait on that address.
                        // Thus, pthread_join can be implemented by simply checking to see if ctid is zero
                        // (and returning immediately with the status if it is),
                        // then doing a futex_wait if necessary (assuming proper synchronization).

                        if (flags & CLONE_CHILD_CLEARTID) == CLONE_CHILD_CLEARTID {
                            directives.push(
                        "clear TID on the child's memory on exit and wake the associated futex"
                            .custom_color(*OUR_YELLOW));
                        }
                        if (flags & CLONE_CHILD_SETTID) == CLONE_CHILD_SETTID {
                            directives.push(
                                "store the child TID in child's memory".custom_color(*OUR_YELLOW),
                            );
                        }
                        if (flags & CLONE_CLEAR_SIGHAND) == CLONE_CLEAR_SIGHAND {
                            directives.push(
                                "default all inherited signal handlers".custom_color(*OUR_YELLOW),
                            );
                        }
                        write_directives(directives);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let child_thread_id = parse_as_long(syscall_return);
                                write_general_text(" |=> ");
                                write_text("thread id of the child: ".green());
                                write_text(child_thread_id.to_string().custom_color(*PAGES_COLOR));
                                if (flags & CLONE_VM) == CLONE_VM {
                                    write_text(new_thread());
                                } else {
                                    write_text(new_process());
                                }
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::fork => {
                match self.state {
                    Entering => {
                        write_general_text(
                            "create a new child process by duplicating the calling process",
                        );
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let child_process = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("child process created: ".green());
                                write_text(child_process.to_string().custom_color(*PAGES_COLOR));
                                write_text(new_process());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::vfork => {
                match self.state {
                    Entering => {
                        write_general_text("create a new child process with copy-on-write memory, (suspend execution until child terminates or calls an exec* syscall)");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                let child_process = parse_as_int(syscall_return);
                                write_general_text(" |=> ");
                                write_text("child process created: ".green());
                                write_text(child_process.to_string().custom_color(*PAGES_COLOR));
                                write_text(new_process());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::execve => {
                let program_name = string_from_pointer(registers[0] as usize, self.tracee_pid);
                let arguments = get_array_of_strings(registers[1] as usize, self.tracee_pid);
                match self.state {
                    Entering => {
                        write_general_text(
                            "replace the current program with the following program and its arguments: ",
                        );
                        write_path_file(program_name);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successful".green());
                            }
                            // TODO! granular
                            SyscallResult::Fail(errno) => SyscallObject::one_line_error(errno),
                        }
                    }
                }
            }
            Sysno::nanosleep => {
                // The value of the nanoseconds field must be in the range [0, 999999999]
                let remaining = registers[1];
                match self.state {
                    Entering => {
                        let duration = read_bytes_as_struct::<TIMESPEC_SIZE, timespec>(
                            registers[0] as usize,
                            self.tracee_pid as _,
                        )
                        .unwrap();
                        write_general_text("suspend execution for ");
                        write_timespec_non_relative(duration.tv_sec, duration.tv_nsec);
                    }
                    Exiting => match self.result {
                        SyscallResult::Success(syscall_return) => {
                            write_general_text(" |=> ");
                            write_text("successful".green());
                        }
                        // TODO! granular
                        SyscallResult::Fail(errno) => {
                            if remaining != 0 && errno == Errno::EINTR {
                                write_text("syscall interrupted by a signal handler, ".red());
                                let remaining_time =
                                    read_bytes_as_struct::<TIMESPEC_SIZE, timespec>(
                                        registers[0] as usize,
                                        self.tracee_pid as _,
                                    )
                                    .unwrap();
                                write_text("sleep-time remaining: ".red());
                                write_timespec_non_relative(
                                    remaining_time.tv_sec,
                                    remaining_time.tv_nsec,
                                );
                            } else {
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    },
                }
            }
            Sysno::landlock_create_ruleset => {
                let attr = registers[0] as *const ();
                let size = registers[1];
                let flags = lower_32_bits(registers[2]);
                // LANDLOCK_CREATE_RULESET_VERSION = 1
                let retrieving_abi_version = (flags & 1) == 1 && attr.is_null() && size == 0;
                match self.state {
                    Entering => {
                        if retrieving_abi_version {
                            write_general_text(
                                "retrieve the highest supported Landlock ABI version",
                            );
                        } else {
                            write_general_text("create a file descriptor for a landlock ruleset");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                if retrieving_abi_version {
                                    write_text("ABI version retrieved: ".green());
                                    write_text(
                                        syscall_return.to_string().custom_color(*PAGES_COLOR),
                                    );
                                } else {
                                    let file_descriptor =
                                        parse_as_file_descriptor(syscall_return, self.tracee_pid);
                                    write_text("created the ruleset file descriptor: ".green());
                                    write_path_file(file_descriptor);
                                }
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::landlock_add_rule => {
                let ruleset_fd = parse_as_int(registers[0]);
                let rule_type_num = registers[1];
                // should be 0
                let flags = lower_32_bits(registers[0]);
                match self.state {
                    Entering => {
                        // LANDLOCK_RULE_PATH_BENEATH = 1
                        if (rule_type_num & 1) == 1 {
                            write_general_text("add a new rule for ");
                            write_text(
                                "file system path-beneath access rights".custom_color(*OUR_YELLOW),
                            );
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("rule added".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::landlock_restrict_self => {
                let ruleset_fd = parse_as_file_descriptor(registers[0], self.tracee_pid);
                // should be 0
                let flags = lower_32_bits(registers[0]);
                match self.state {
                    Entering => {
                        write_general_text("enforce the landlock ruleset inside: ");
                        write_general_text(&ruleset_fd);
                        write_general_text(" on the calling process");
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("ruleset active".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::fallocate => {
                let file_descriptor = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let mode = parse_as_int(registers[1]);
                let offset = parse_as_int(registers[2]);
                let offset_string = parse_as_signed_bytes(registers[2]);
                let bytes = parse_as_signed_bytes(registers[3]);
                match self.state {
                    Entering => {
                        if mode == 0
                            || (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE
                            || (mode & FALLOC_FL_UNSHARE_RANGE) == FALLOC_FL_UNSHARE_RANGE
                        {
                            write_text("allocate ".magenta());
                            write_text(bytes.custom_color(*PAGES_COLOR));
                            if offset == 0 {
                                write_general_text(" at the beginning of the file: ");
                            } else {
                                write_general_text(" starting at ");
                                write_text(offset_string.custom_color(*PAGES_COLOR));
                                write_general_text(" from the beginning of the file: ");
                            }
                            write_path_file(file_descriptor);
                            if (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE
                                && !(mode & FALLOC_FL_PUNCH_HOLE) == FALLOC_FL_PUNCH_HOLE
                            {
                                // this improves performance when appeding (makes appending later faster)
                                write_general_text(" (");
                                write_general_text("do not increase the file size if the range is larger, simply zeroize the out of bound bytes)");
                                write_general_text(")");
                            } else if (mode & FALLOC_FL_UNSHARE_RANGE) == FALLOC_FL_UNSHARE_RANGE {
                                // this improves performance when appeding (makes appending later faster)
                                write_general_text(" (");

                                write_text(
                                    "modify any shared file data to private copy-on-write"
                                        .custom_color(*OUR_YELLOW),
                                );
                                write_general_text(")");
                            } else {
                                write_general_text(" (");
                                write_text(
                                    "increase file size and zeroize if the range is larger"
                                        .custom_color(*OUR_YELLOW),
                                );
                                write_general_text(")");
                            }
                        } else if (mode & FALLOC_FL_PUNCH_HOLE) == FALLOC_FL_PUNCH_HOLE
                            && (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE
                        {
                            write_text("deallocate ".magenta());
                            write_text(bytes.custom_color(*PAGES_COLOR));
                            if offset == 0 {
                                write_general_text(" at the beginning of the file: ");
                            } else {
                                write_general_text(" starting at ");
                                write_text(offset_string.custom_color(*PAGES_COLOR));
                                write_general_text(" from the beginning of the file: ");
                            }
                            write_path_file(file_descriptor);
                        } else if (mode & FALLOC_FL_COLLAPSE_RANGE) == FALLOC_FL_COLLAPSE_RANGE {
                            write_text("remove ".magenta());
                            write_text(bytes.custom_color(*PAGES_COLOR));
                            if offset == 0 {
                                write_general_text(" from the beginning of the file: ");
                            } else {
                                write_general_text(" starting at ");
                                write_text(offset_string.custom_color(*PAGES_COLOR));
                                write_general_text(" from the beginning of the file: ");
                            }
                            write_path_file(file_descriptor);
                            write_text(" without leaving a hole".custom_color(*OUR_YELLOW));
                        } else if (mode & FALLOC_FL_ZERO_RANGE) == FALLOC_FL_ZERO_RANGE {
                            write_text("zeroize ".magenta());
                            write_text(bytes.custom_color(*PAGES_COLOR));
                            if offset == 0 {
                                write_general_text(" from the beginning of the file: ");
                            } else {
                                write_general_text(" starting at ");
                                write_text(offset_string.custom_color(*PAGES_COLOR));
                                write_general_text(" from the beginning of the file: ");
                            }
                            write_path_file(file_descriptor);
                            if (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE {
                                write_general_text(" (");
                                write_text(
                                    "do not increase the file size if the range is larger"
                                        .custom_color(*OUR_YELLOW),
                                );
                                write_general_text(")");
                            }
                        } else if (mode & FALLOC_FL_INSERT_RANGE) == FALLOC_FL_INSERT_RANGE {
                            write_text("insert ".magenta());
                            write_text(bytes.custom_color(*PAGES_COLOR));
                            write_text(" of holes".magenta());

                            if offset == 0 {
                                write_general_text(" at the beginning of the file: ");
                            } else {
                                write_general_text(" starting at ");
                                write_text(offset_string.custom_color(*PAGES_COLOR));
                                write_general_text(" from the beginning of the file: ");
                            }
                            write_path_file(file_descriptor);
                            write_general_text(" and displace any existing data");
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // TODO! granular
                                write_general_text(" |=> ");
                                write_text("operation successful".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getpriority => {
                let which = lower_32_bits(registers[0]);
                let process = parse_as_int(registers[1]);

                match self.state {
                    Entering => {
                        write_general_text("get the scheduling priority ");
                        match which {
                            PRIO_PROCESS => {
                                write_general_text("of ");
                                if process == 0 {
                                    write_text("the calling process".custom_color(*OUR_YELLOW));
                                } else {
                                    write_text("process: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                }
                            }
                            PRIO_PGRP => {
                                write_general_text("of ");
                                if process == 0 {
                                    write_text(
                                        "the process group of calling process"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    write_text("process group: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                }
                            }
                            PRIO_USER => {
                                write_general_text("for ");
                                if process == 0 {
                                    write_text(
                                        "the real user id of the calling process"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    write_text("the real user id: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                // 40..1
                                let kernel_space_nice = syscall_return as i64;
                                write_general_text(" |=> ");
                                write_text("scheduling priority retrieved: ".green());
                                write_text(
                                    // -20..19
                                    (20 - kernel_space_nice)
                                        .to_string()
                                        .custom_color(*PAGES_COLOR),
                                );
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::setpriority => {
                let which = lower_32_bits(registers[1]);
                let process = parse_as_int(registers[1]);
                let prio = parse_as_int(registers[1]);
                match self.state {
                    Entering => {
                        write_general_text("set the scheduling priority ");
                        match which {
                            PRIO_PROCESS => {
                                write_general_text("of ");
                                if process == 0 {
                                    write_text("the calling process".custom_color(*OUR_YELLOW));
                                } else {
                                    write_text("process: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                }
                                write_general_text(" to ");
                                write_text(prio.to_string().custom_color(*PAGES_COLOR));
                            }
                            PRIO_PGRP => {
                                write_general_text("of ");
                                if process == 0 {
                                    write_text(
                                        "the process group of calling process"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    write_text("process group: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                }
                                write_general_text(" to ");
                                write_text(prio.to_string().custom_color(*PAGES_COLOR));
                            }
                            PRIO_USER => {
                                write_general_text("for ");
                                if process == 0 {
                                    write_text(
                                        "the real user id of the calling process"
                                            .custom_color(*OUR_YELLOW),
                                    );
                                } else {
                                    write_text("the real user id: ".custom_color(*OUR_YELLOW));
                                    write_text(process.to_string().custom_color(*PAGES_COLOR));
                                    write_general_text(" to ");
                                    write_text(prio.to_string().custom_color(*PAGES_COLOR));
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("successfully set the scheduling priority".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getdents => {
                let directory = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let count = lower_32_bits(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("retrieve the entries ");
                        write_general_text(" (");
                        write_general_text("maximum: ");
                        write_text(count.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(")");
                        write_general_text(" inside the directory: ");
                        write_path_file(directory);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("entries retrieved".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
                        }
                    }
                }
            }
            Sysno::getdents64 => {
                let directory = parse_as_file_descriptor(registers[0], self.tracee_pid);
                let count = lower_32_bits(registers[2]);
                match self.state {
                    Entering => {
                        write_general_text("retrieve the entries ");
                        write_general_text(" (");
                        write_general_text("maximum: ");
                        write_text(count.to_string().custom_color(*PAGES_COLOR));
                        write_general_text(")");
                        write_general_text(" inside the directory: ");
                        write_path_file(directory);
                    }
                    Exiting => {
                        match self.result {
                            SyscallResult::Success(syscall_return) => {
                                write_general_text(" |=> ");
                                write_text("entries retrieved".green());
                            }
                            SyscallResult::Fail(errno) => {
                                // TODO! granular
                                SyscallObject::one_line_error(errno)
                            }
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
    pub fn mode_matcher(&mut self, mode: u32) {
        // USER
        let mut perms = vec![];

        if (mode & S_IRUSR) == S_IRUSR {
            perms.push("read".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IWUSR) == S_IWUSR {
            perms.push("write".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IXUSR) == S_IXUSR {
            perms.push("execute".custom_color(*OUR_YELLOW));
        }
        if !perms.is_empty() {
            write_general_text(" allowing the user to ");
            write_vanilla_commas(perms);
            write_general_text(", ");
        }

        // GROUP
        let mut group_perms = vec![];
        if (mode & S_IRGRP) == S_IRGRP {
            group_perms.push("read".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IWGRP) == S_IWGRP {
            group_perms.push("write".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IXGRP) == S_IXGRP {
            group_perms.push("execute".custom_color(*OUR_YELLOW));
        }
        if !group_perms.is_empty() {
            write_general_text(" allowing the group to ");
            write_vanilla_commas(group_perms);
            write_general_text(", ");
        }
        // OTHER
        let mut other_perms = vec![];
        if (mode & S_IROTH) == S_IROTH {
            other_perms.push("read".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IWOTH) == S_IWOTH {
            other_perms.push("write".custom_color(*OUR_YELLOW));
        }
        if (mode & S_IXOTH) == S_IXOTH {
            other_perms.push("execute".custom_color(*OUR_YELLOW));
        }
        if !other_perms.is_empty() {
            write_general_text(" allowing others to ");
            write_vanilla_commas(other_perms);
            write_general_text(", ");
        }

        // SETS
        let mut sets = vec![];
        if (mode & S_ISUID) == S_ISUID {
            sets.push("set-uid".custom_color(*OUR_YELLOW));
        } else if (mode & S_ISGID) == S_ISGID {
            sets.push("set-gid".custom_color(*OUR_YELLOW));
        } else if (mode & S_ISVTX) == S_ISVTX {
            sets.push("sticky-bit".custom_color(*OUR_YELLOW));
        }
        if !sets.is_empty() {
            write_general_text(" and set ");
            write_vanilla_commas(sets);
        }
    }

    pub fn resource_matcher(&mut self, resource: u32) {
        // TODO! fix segmentation fault here
        match resource {
            RLIMIT_AS => {
                write_text("maximum virtual memory size".custom_color(*OUR_YELLOW));
            }
            RLIMIT_CORE => {
                write_text("maximum core size that may be dumped".custom_color(*OUR_YELLOW));
            }
            RLIMIT_CPU => {
                write_text("maximum time in seconds to use in the CPU".custom_color(*OUR_YELLOW));
            }
            RLIMIT_DATA => {
                write_text("maximum data segment size".custom_color(*OUR_YELLOW));
            }
            RLIMIT_FSIZE => {
                write_text("maximum allowed size of files to creates".custom_color(*OUR_YELLOW));
            }
            RLIMIT_NOFILE => {
                write_text("maximum allowed open file descriptors".custom_color(*OUR_YELLOW));
            }
            RLIMIT_STACK => {
                write_text("maximum stack size".custom_color(*OUR_YELLOW));
            }
            RLIMIT_LOCKS => {
                write_text(
                    "maximum number of flock() locks and fcntl() leases".custom_color(*OUR_YELLOW),
                );
            }
            RLIMIT_MEMLOCK => {
                // affects mlock
                write_text("maximum amount of memory that can be locked".custom_color(*OUR_YELLOW));
            }
            RLIMIT_MSGQUEUE => {
                write_text(
                    "maximum number of bytes to use on message queues".custom_color(*OUR_YELLOW),
                );
            }
            RLIMIT_NICE => {
                write_text("maximum nice value".custom_color(*OUR_YELLOW));
            }
            RLIMIT_NPROC => {
                write_text("maximum number of threads".custom_color(*OUR_YELLOW));
            }
            RLIMIT_RSS => {
                // affects madvise
                write_text("maximum RSS memory".custom_color(*OUR_YELLOW));
            }
            RLIMIT_RTPRIO => {
                write_text("maximum real-time priority".custom_color(*OUR_YELLOW));
            }
            RLIMIT_RTTIME => {
                write_text(
                    "maximum time in micro-seconds to use in the CPU without syscalls"
                        .custom_color(*OUR_YELLOW),
                );
            }
            RLIMIT_SIGPENDING => {
                write_text("maximum number of queued pending signals".custom_color(*OUR_YELLOW));
            }
            _ => {}
        }
    }
}
// same path rules (faccessat2, mkdir, mkdirat, readlinkat, linkat, openat)
// TODO!
// future:
// introduce macro interpretations
//     example:
//         open syscall returns fd
//         that fd is immediately unlinked
//     interprtation: binary is creating an anon inode
//     (should be more sophisticated)
