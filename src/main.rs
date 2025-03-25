#![allow(
    unused_doc_comments,
    unused_variables,
    unused_imports,
    unused_mut,
    dead_code,
    unused_assignments,
    non_camel_case_types,
    unreachable_code,
    unused_macros,
    bare_trait_objects,
    non_snake_case,
    invalid_value
)]

macro_rules! p {
    ($a:expr) => {
        println!("{:?}", $a)
    };
}
macro_rules! pp {
    ($a:expr, $b:expr) => {
        println!("{:?}, {:?}", $a, $b)
    };
}
macro_rules! ppp {
    ($a:expr, $b:expr, $c:expr) => {
        println!("{:?}, {:?}, {:?}", $a, $b, $c)
    };
}

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    env::args,
    error::Error,
    fmt::Debug,
    mem::{self, MaybeUninit, transmute},
    os::{raw::c_void, unix::process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio, exit},
    ptr::null,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use ::errno::{errno, set_errno};
use clap::Parser;
use colored::{ColoredString, Colorize};
use errno::Errno as LibErrno;
use nix::{
    errno::Errno,
    libc::{ESRCH, sigaction, user_regs_struct},
    sys::{
        ptrace::{self},
        signal::{Signal, kill},
        wait::waitpid,
    },
    unistd::{ForkResult::*, Pid, fork},
};
use pete::{Ptracer, Restart, Stop, Tracee};
use procfs::process::{MMapPath, MemoryMap};
use syscalls::Sysno;
use utilities::{
    buffered_write, colorize_diverse, display_unsupported, errno_check, flush_buffer, set_memory_break, IntentraceArgs, ATTACH_PID, BINARY_AND_ARGS, EXITED_BACKGROUND_COLOR, FAILED_ONLY, FOLLOW_FORKS, GENERAL_TEXT_COLOR, HALT_TRACING, PID_BACKGROUND_COLOR, QUIET, REGISTERS, STOPPED_COLOR, SUMMARY, SYSKELETON_MAP, TABLE, TABLE_FOLLOW_FORKS
};

mod syscall_annotations_map;
mod syscall_categories;
mod syscall_object;
mod syscall_object_annotations;
mod syscall_skeleton_map;
mod types;
use syscall_object::{SyscallObject, SyscallState};
mod one_line_formatter;
mod utilities;

fn main() {
    let args = IntentraceArgs::parse();
    ctrlc::set_handler(|| {
        flush_buffer();
        HALT_TRACING.store(true, Ordering::SeqCst);

        if *SUMMARY {
            print_table();
        }
        std::process::exit(0);
    })
    .unwrap();
    runner(&BINARY_AND_ARGS);
}

fn runner(command_line: &[String]) {
    let attach_pid = *ATTACH_PID;
    if *FOLLOW_FORKS {
        match attach_pid {
            Some(_) => follow_forks(None),
            None => follow_forks(Some(command_line)),
        }
    } else {
        if attach_pid.is_some() {
            parent(None);
        } else {
            match unsafe { fork() }.expect("Error: Fork Failed") {
                Parent { child } => {
                    parent(Some(child));
                }
                Child => {
                    child_trace_me(command_line);
                }
            }
        }
    }
    if !*FAILED_ONLY {
        flush_buffer();
    }
    if *SUMMARY {
        print_table();
    }
}

fn child_trace_me(comm: &[String]) {
    let mut command = Command::new(&comm[0]);
    command.args(&comm[1..]);

    if *QUIET{
        command.stdout(Stdio::null());
    }

    // TRACE ME
    let _ = ptrace::traceme().unwrap();
    // EXECUTE
    let res = command.exec();

    // This won't be reached unless exec fails
    eprintln!("Error: could not execute program");
    std::process::exit(res.raw_os_error().unwrap())
}

fn follow_forks(command_to_run: Option<&[String]>) {
    match command_to_run {
        // COMMANDLINE PROGRAM
        Some(comm) => {
            let mut command = Command::new(&comm[0]);
            command.args(&comm[1..]);

            if *QUIET {
                command.stdout(Stdio::null());
            }

            let mut ptracer = Ptracer::new();
            *ptracer.poll_delay_mut() = Duration::from_nanos(1);
            let child = ptracer.spawn(command).unwrap();
            ptrace_ptracer(ptracer, Pid::from_raw(child.id() as i32));
        }
        // ATTACHING TO PID
        None => {
            if let Some(attach_pid) = *ATTACH_PID {
                let mut ptracer = Ptracer::new();
                *ptracer.poll_delay_mut() = Duration::from_nanos(1);
                let child = ptracer.attach(pete::Pid::from_raw(attach_pid as i32)).unwrap();
                ptrace_ptracer(ptracer, Pid::from_raw(attach_pid as i32));
            } else {
                eprintln!("Usage: invalid arguments\n");
            }
        }
    }
}

fn parent(child_or_attach: Option<Pid>) {
    let child = if child_or_attach.is_some() {
        child_or_attach.unwrap()
    } else {
        let child = Pid::from_raw(ATTACH_PID.unwrap() as i32);
        let _ = ptrace::attach(child).unwrap();
        child
    };
    // skip first execve
    let _res = waitpid(child, None).unwrap();
    let mut syscall_entering = true;
    let (mut start, mut end) = (None, None);
    let mut syscall = SyscallObject::default();
    'main_loop: loop {
        match ptrace::syscall(child, None) {
            Ok(_void) => {
                let _res = waitpid(child, None).expect("Failed waiting for child.");
                match syscall_entering {
                    true => {
                        // SYSCALL ABOUT TO RUN
                        match nix::sys::ptrace::getregs(child) {
                            Ok(registers) => {
                                let sysno = Sysno::from(registers.orig_rax as i32);
                                if let Some(syscall_built) = SyscallObject::build(child, sysno) {
                                    syscall = syscall_built;
                                    *REGISTERS.lock().unwrap() = [
                                        registers.rdi,
                                        registers.rsi,
                                        registers.rdx,
                                        registers.r10,
                                        registers.r8,
                                        registers.r9,
                                    ];
                                    syscall_will_run(&mut syscall);
                                    if syscall.is_exiting() {
                                        break 'main_loop;
                                    }
                                }
                            }
                            Err(errno) => {
                                if errno == Errno::ESRCH {
                                    print_exiting(child);
                                    break 'main_loop;
                                }
                            }
                        }
                        syscall_entering = false;
                        start = Some(std::time::Instant::now());
                        continue 'main_loop;
                    }
                    false => {
                        // SYSCALL RETURNED
                        end = Some(std::time::Instant::now());

                        match nix::sys::ptrace::getregs(child) {
                            Ok(registers) => {
                                let mut table = TABLE.lock().unwrap();
                                table
                                    .entry(syscall.sysno)
                                    .and_modify(|value| {
                                        value.0 += 1;
                                        value.1 = value.1.saturating_add(
                                            end.unwrap().duration_since(start.unwrap()),
                                        );
                                    })
                                    .or_insert((1, end.unwrap().duration_since(start.unwrap())));
                                start = None;
                                end = None;
                                *REGISTERS.lock().unwrap() = [
                                    registers.rdi,
                                    registers.rsi,
                                    registers.rdx,
                                    registers.r10,
                                    registers.r8,
                                    registers.r9,
                                ];
                                syscall_returned(&mut syscall, registers.rax)
                            }
                            Err(errno) => {
                                if errno == Errno::ESRCH {
                                    print_exiting(child);
                                    break 'main_loop;
                                }
                            }
                        }
                        syscall_entering = true;
                    }
                }
            }
            Err(errno) => {
                println!(
                    "\n\n ptrace-syscall Error: {errno}, last syscall: {} \n\n",
                    syscall.sysno
                );
                break 'main_loop;
            }
        }
    }
}

fn ptrace_ptracer(mut ptracer: Ptracer, child: Pid) {
    let mut last_sysno: Sysno = unsafe { mem::zeroed() };
    let mut last_pid = unsafe { mem::zeroed() };
    let mut pid_syscall_map: HashMap<Pid, SyscallObject> = HashMap::new();

    while let Some(mut tracee) = ptracer.wait().unwrap() {
        if HALT_TRACING.load(Ordering::SeqCst) {
            break;
        }
        let syscall_pid = Pid::from_raw(tracee.pid.as_raw());
        match tracee.stop {
            Stop::SyscallEnter =>
            // 'for_exiting:
            {
                match nix::sys::ptrace::getregs(syscall_pid) {
                    Ok(registers) => {
                        check_syscall_switch(last_pid, syscall_pid, &mut pid_syscall_map);
                        let sysno = Sysno::from(registers.orig_rax as i32);
                        let mut syscall_built = SyscallObject::build(syscall_pid, sysno);
                        if let Some(mut syscall) = syscall_built {
                            if *SUMMARY {
                                let mut output = TABLE_FOLLOW_FORKS.lock().unwrap();
                                output
                                    .entry(syscall.sysno)
                                    .and_modify(|value| {
                                        *value += 1;
                                    })
                                    .or_insert(1);
                            }
                            *REGISTERS.lock().unwrap() = [
                                registers.rdi,
                                registers.rsi,
                                registers.rdx,
                                registers.r10,
                                registers.r8,
                                registers.r9,
                            ];
                            syscall_will_run(&mut syscall);
                            // if syscall.is_exiting() {
                            //     break 'for_exiting;
                            // }
                            last_sysno = syscall.sysno;
                            syscall.state = SyscallState::Exiting;
                            pid_syscall_map.insert(syscall_pid, syscall);
                        }
                    }
                    Err(errno) => handle_getting_registers_error(errno, "enter", last_sysno),
                }
                last_pid = syscall_pid;
            }
            Stop::SyscallExit => {
                check_syscall_switch(last_pid, syscall_pid, &mut pid_syscall_map);
                match nix::sys::ptrace::getregs(syscall_pid) {
                    Ok(registers) => {
                        *REGISTERS.lock().unwrap() = [
                            registers.rdi,
                            registers.rsi,
                            registers.rdx,
                            registers.r10,
                            registers.r8,
                            registers.r9,
                        ];
                        if let Some(mut syscall) = pid_syscall_map.get_mut(&syscall_pid) {
                            syscall_returned(&mut syscall, registers.rax);
                            pid_syscall_map.remove(&syscall_pid).unwrap();
                        }
                    }
                    Err(errno) => handle_getting_registers_error(errno, "exit", last_sysno),
                }
                last_pid = syscall_pid;
            }
            _ => {
                let Tracee { pid, stop, .. } = tracee;
            }
        }
        ptracer.restart(tracee, Restart::Syscall).unwrap();
    }
}

fn syscall_will_run(syscall: &mut SyscallObject) {
    // GET PRECALL DATA (some data will be lost if not saved in this time frame)
    syscall.get_precall_data();

    // handle program break point
    if syscall.is_mem_alloc_dealloc() {
        set_memory_break(syscall.process_pid);
    }
    if *FOLLOW_FORKS || syscall.is_exiting() {
        syscall.format();
        if syscall.is_exiting() {
            print_exiting(syscall.process_pid);
        }
    }
}

fn print_exiting(process_pid: Pid) {
    let exited = " EXITED ".on_custom_color(*EXITED_BACKGROUND_COLOR);
    let pid = format!(" {} ", process_pid).on_custom_color(*PID_BACKGROUND_COLOR);
    buffered_write("\n\n ".white());
    buffered_write(pid);
    buffered_write(exited);
    buffered_write("\n\n".white());
}

fn syscall_returned(syscall: &mut SyscallObject, return_value: u64) {
    // STORE SYSCALL RETURN VALUE
    syscall.result.0 = Some(return_value);

    // manual calculation of errno for now
    // TODO! make this cleaner
    syscall.errno = errno_check(return_value);

    // GET POSTCALL DATA (some data will be lost if not saved in this time frame)
    syscall.get_postcall_data();

    if !*FOLLOW_FORKS {
        if *FAILED_ONLY && !syscall.displayable_return_ol().is_err() {
            return;
        }

        syscall.state = SyscallState::Entering;
        syscall.format();
        syscall.state = SyscallState::Exiting;
        syscall.format();
        // this line was moved from the main loops to after this check ^
        // it was previously not aware of FAILED_ONLY being its edge-case
        // this resulted in long streaks of newlines in the output
        // this is also more correct
        buffered_write("\n".white());
    } else {
        syscall.format();
        buffered_write("\n".white());
    }
    flush_buffer();
}

fn check_syscall_switch(
    last_pid: Pid,
    syscall_pid: Pid,
    pid_syscall_map: &mut HashMap<Pid, SyscallObject>,
) {
    if syscall_pid != last_pid {
        if let Some(last_syscall) = pid_syscall_map.get_mut(&last_pid) {
            if !last_syscall.is_exiting() {
                last_syscall.paused = true;
                last_syscall.write_text(" ├ ".custom_color(*GENERAL_TEXT_COLOR));
                last_syscall.write_text(" STOPPED ".on_custom_color(*STOPPED_COLOR));
                buffered_write("\n".white());
            }
        }
    }
}

fn handle_getting_registers_error(errno: Errno, syscall_enter_or_exit: &str, sysno: Sysno) {
    if sysno == Sysno::exit || sysno == Sysno::exit_group {
        println!("\n\nSuccessfully exited\n");
    } else {
        match errno {
            Errno::ESRCH => {
                println!(
                    "\n\n getting registers: syscall-{syscall_enter_or_exit} error: process \
                     disappeared\nsyscall: {sysno}, error: {errno}"
                );
                exit(0);
            }
            _ => println!("Encountered error while retrieving registers"),
        }
    }
}

fn print_table() {
    if *FOLLOW_FORKS {
        let output = TABLE_FOLLOW_FORKS.lock().unwrap();
        let mut vec = Vec::from_iter(output.iter());
        vec.sort_by(|(_sysno, count), (_sysno2, count2)| count2.cmp(count));

        use tabled::{builder::Builder, settings::Style};
        let mut builder = Builder::new();

        builder.push_record(["calls", "syscall"]);
        builder.push_record([""]);
        for (sys, count) in vec {
            builder.push_record([&count.to_string(), sys.name()]);
        }
        let table = builder.build().with(Style::ascii_rounded()).to_string();

        println!("\n{}", table);
    } else {
        let mut output = TABLE.lock().unwrap();
        let mut vec = Vec::from_iter(output.iter());
        vec.sort_by(|(_sysno, (count, duration)), (_sysno2, (count2, duration2))| {
            duration2.cmp(duration)
        });

        use tabled::{builder::Builder, settings::Style};
        let mut builder = Builder::new();

        builder.push_record(["% time", "seconds", "usecs/call", "calls", "syscall"]);
        builder.push_record([""]);
        let total_time = vec.iter().map(|(_, (_, time))| time.as_micros()).sum::<u128>();
        for (sys, (count, time)) in vec {
            let time_MICROS = time.as_micros() as f64;
            let time = time_MICROS / 1_000_000.0;
            let usecs_call = (time_MICROS / *count as f64) as i64;
            let time_percent = time_MICROS / total_time as f64;
            builder.push_record([
                &format!("{:.2}", time_percent * 100.0),
                &format!("{:.6}", time),
                &format!("{}", usecs_call),
                &count.to_string(),
                sys.name(),
            ]);
        }
        let table = builder.build().with(Style::ascii_rounded()).to_string();

        println!("\n{}", table);
    }
}
