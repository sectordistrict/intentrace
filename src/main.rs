#![allow(
    unused_doc_comments,
    dead_code,
    non_camel_case_types,
    unused_macros,
    non_snake_case,
    invalid_value,
    unused_assignments
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
    collections::HashMap,
    mem::{self},
    os::unix::process::CommandExt,
    process::{exit, Command, Stdio},
    sync::atomic::Ordering,
    time::Duration,
};

use clap::Parser;
use cli::{
    IntentraceArgs, ATTACH_PID, BINARY_AND_ARGS, FAILED_ONLY, FOLLOW_FORKS, QUIET, SUMMARY,
    SUMMARY_ONLY,
};
use colored::Colorize;
use colors::{GENERAL_TEXT_COLOR, STOPPED_COLOR};
use nix::{
    errno::Errno,
    sys::{
        ptrace::{self},
        wait::waitpid,
    },
    unistd::{fork, ForkResult::*, Pid},
};
use pete::{Ptracer, Restart, Stop};
use syscalls::Sysno;
use utilities::{
    interpret_syscall_result, set_memory_break_pre_call, syscall_is_blocking, HALT_TRACING, REGISTERS,
    TABLE, TABLE_FOLLOW_FORKS,
};
use writer::{
    empty_buffer, flush_buffer, initialize_writer, write_exiting, write_syscall_not_covered,
    write_text,
};

mod syscall_categories;
mod syscall_object;
// mod syscall_annotations_map;
// mod syscall_object_annotations;
mod syscall_skeleton_map;
mod types;
use syscall_object::{SyscallObject, SyscallResult, SyscallState};
mod auxiliary;
mod cli;
mod colors;
mod one_line_formatter;
mod peeker_poker;
mod return_resolvers;
mod utilities;
mod writer;

fn main() -> anyhow::Result<()> {
    IntentraceArgs::parse();
    initialize_writer();
    ctrlc::set_handler(|| {
        flush_buffer();
        HALT_TRACING.store(true, Ordering::SeqCst);
        if *SUMMARY_ONLY || *SUMMARY {
            print_table();
        }
        std::process::exit(0);
    })?;
    if *FOLLOW_FORKS {
        follow_forks(*BINARY_AND_ARGS)
    } else {
        match *ATTACH_PID {
            Some(pid) => {
                let child = Pid::from_raw(pid as i32);
                ptrace::attach(child)?;
                parent(child);
            }
            None => match *BINARY_AND_ARGS {
                Some(binary_and_args) => match unsafe { fork() }? {
                    Parent { child } => {
                        parent(child);
                    }
                    Child => child_trace_me(binary_and_args),
                },
                None => {
                    eprintln!("Usage: must provide a command to run or attach to a PID\n");
                    exit(100);
                }
            },
        }
    }
    if !*FAILED_ONLY {
        // flush_buffer();
    }
    if *SUMMARY_ONLY || *SUMMARY {
        print_table();
    }
    Ok(())
}

fn child_trace_me(comm: &[String]) {
    let mut command = Command::new(&comm[0]);
    command.args(&comm[1..]);

    if *QUIET {
        command.stdout(Stdio::null());
    }

    ptrace::traceme().unwrap();
    let res = command.exec();

    // unreachable unless exec fails
    eprintln!("Could not execute program");
    std::process::exit(res.raw_os_error().unwrap())
}

fn follow_forks(command_to_run: Option<&[String]>) {
    match command_to_run {
        Some(comm) => {
            let mut command = Command::new(&comm[0]);
            command.args(&comm[1..]);

            if *QUIET {
                command.stdout(Stdio::null());
            }

            let mut ptracer = Ptracer::new();
            *ptracer.poll_delay_mut() = Duration::from_nanos(1);
            ptracer.spawn(command).unwrap();
            ptrace_ptracer(ptracer);
        }
        None => {
            eprintln!("Usage: must provide a command to run\n");
            exit(100);
        }
    }
}

fn parent(tracee_pid: Pid) {
    // skip first execve
    let _res = waitpid(tracee_pid, None).unwrap();
    let mut syscall_entering = true;
    let (mut start, mut end) = (None, None);
    let mut syscall = SyscallObject::default();
    let (mut supported, mut skip) = (true, false);
    'main_loop: loop {
        match ptrace::syscall(tracee_pid, None) {
            Ok(_void) => {
                let _res = waitpid(tracee_pid, None).expect("Failed waiting for child.");
                match syscall_entering {
                    true => {
                        empty_buffer();
                        // SYSCALL ABOUT TO RUN
                        let ptrace_regs = nix::sys::ptrace::getregs(tracee_pid);
                        if let Err(Errno::ESRCH) = ptrace_regs {
                            write_exiting(tracee_pid);
                            break 'main_loop;
                        }
                        let registers = ptrace_regs.unwrap();
                        let sysno = Sysno::from(registers.orig_rax as i32);
                        skip = SyscallObject::should_skip_building(sysno);
                        if !skip {
                            if let Some(syscall_built) = SyscallObject::build(tracee_pid, sysno) {
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
                                if *SUMMARY {
                                    start = Some(std::time::Instant::now());
                                }
                            } else {
                                write_syscall_not_covered(sysno, tracee_pid);
                                supported = false;
                            }
                        }
                        syscall_entering = false;
                        if *SUMMARY_ONLY {
                            start = Some(std::time::Instant::now());
                        }
                        continue 'main_loop;
                    }
                    false => {
                        // SYSCALL RETURNED
                        end = Some(std::time::Instant::now());
                        let ptrace_regs = nix::sys::ptrace::getregs(tracee_pid);
                        if let Err(Errno::ESRCH) = ptrace_regs {
                            write_exiting(tracee_pid);
                            break 'main_loop;
                        }
                        let registers = ptrace_regs.unwrap();
                        let sysno = Sysno::from(registers.orig_rax as i32);
                        if supported && !skip {
                            *REGISTERS.lock().unwrap() = [
                                registers.rdi,
                                registers.rsi,
                                registers.rdx,
                                registers.r10,
                                registers.r8,
                                registers.r9,
                            ];
                            syscall_returned(&mut syscall, registers.rax);
                            if *SUMMARY {
                                let mut table = TABLE.lock().unwrap();
                                table
                                    .entry(sysno)
                                    .and_modify(|(count, duration, errors)| {
                                        *count += 1;
                                        *duration = duration.saturating_add(
                                            end.unwrap().duration_since(start.unwrap()),
                                        );
                                        *errors += syscall.has_errored() as usize;
                                    })
                                    .or_insert((
                                        1,
                                        end.unwrap().duration_since(start.unwrap()),
                                        syscall.has_errored() as usize,
                                    ));
                                start = None;
                                end = None;
                            }
                        }
                        if *SUMMARY_ONLY {
                            let mut table = TABLE.lock().unwrap();
                            let syscall_result = interpret_syscall_result(registers.rax);
                            let errored = matches!(syscall_result, SyscallResult::Fail(_));
                            table
                                .entry(sysno)
                                .and_modify(|(count, duration, errors)| {
                                    *count += 1;
                                    *duration = duration.saturating_add(
                                        end.unwrap().duration_since(start.unwrap()),
                                    );
                                    *errors += errored as usize;
                                })
                                .or_insert((
                                    1,
                                    end.unwrap().duration_since(start.unwrap()),
                                    errored as usize,
                                ));
                            start = None;
                            end = None;
                        }
                        supported = true;
                        skip = false;
                        syscall_entering = true;
                    }
                }
            }
            Err(errno) => {
                if errno == Errno::ESRCH {
                    eprintln!("\n\nTracee died\nlast syscall: {}", syscall.sysno);
                } else {
                    eprintln!("\n\nError: {errno}\nlast syscall: {}", syscall.sysno);
                }
                break 'main_loop;
            }
        }
    }
}

fn ptrace_ptracer(mut ptracer: Ptracer) {
    let mut last_sysno: syscalls::Sysno = unsafe { mem::zeroed() };
    let mut last_pid = unsafe { mem::zeroed() };
    let mut pid_syscall_map: HashMap<Pid, SyscallObject> = HashMap::new();

    while let Ok(Some(tracee)) = ptracer.wait() {
        if HALT_TRACING.load(Ordering::SeqCst) {
            break;
        }
        let tracee_pid = Pid::from_raw(tracee.pid.as_raw());
        match tracee.stop {
            Stop::SyscallEnter => {
                let ptrace_regs = nix::sys::ptrace::getregs(tracee_pid);
                if let Err(errno) = ptrace_regs {
                    handle_getting_registers_error(errno, "enter", last_sysno)
                }
                let registers = ptrace_regs.unwrap();

                check_syscall_switch(last_pid, tracee_pid, &mut pid_syscall_map);
                let sysno = Sysno::from(registers.orig_rax as i32);
                last_sysno = sysno;
                if !SyscallObject::should_skip_building(sysno) {
                    let syscall_built = SyscallObject::build(tracee_pid, sysno);
                    if let Some(mut syscall) = syscall_built {
                        *REGISTERS.lock().unwrap() = [
                            registers.rdi,
                            registers.rsi,
                            registers.rdx,
                            registers.r10,
                            registers.r8,
                            registers.r9,
                        ];
                        syscall_will_run(&mut syscall);
                        syscall.state = SyscallState::Exiting;
                        pid_syscall_map.insert(tracee_pid, syscall);
                        if *SUMMARY {
                            let mut table = TABLE_FOLLOW_FORKS.lock().unwrap();
                            table
                                .entry(sysno)
                                .and_modify(|value| {
                                    *value += 1;
                                })
                                .or_insert(1);
                        }
                    } else {
                        write_syscall_not_covered(sysno, tracee_pid);
                    }
                }
                if *SUMMARY_ONLY {
                    let mut table = TABLE_FOLLOW_FORKS.lock().unwrap();
                    table
                        .entry(sysno)
                        .and_modify(|value| {
                            *value += 1;
                        })
                        .or_insert(1);
                }
                last_pid = tracee_pid;
            }
            Stop::SyscallExit => {
                check_syscall_switch(last_pid, tracee_pid, &mut pid_syscall_map);
                let ptrace_regs = nix::sys::ptrace::getregs(tracee_pid);
                if let Err(errno) = ptrace_regs {
                    handle_getting_registers_error(errno, "enter", last_sysno)
                }
                let registers = ptrace_regs.unwrap();
                *REGISTERS.lock().unwrap() = [
                    registers.rdi,
                    registers.rsi,
                    registers.rdx,
                    registers.r10,
                    registers.r8,
                    registers.r9,
                ];
                if let Some(syscall) = pid_syscall_map.get_mut(&tracee_pid) {
                    syscall_returned(syscall, registers.rax);
                    pid_syscall_map.remove(&tracee_pid).unwrap();
                }
                last_pid = tracee_pid;
            }
            _ => {}
        }
        match ptracer.restart(tracee, Restart::Syscall) {
            Ok(_) => {}
            Err(e) => {
                if let pete::Error::TraceeDied { pid, source } = e {
                    if source as i32 == Errno::ESRCH as i32 {
                        write_exiting(Pid::from_raw(pid.as_raw()));
                        return;
                    }
                }
                eprintln!("{}", e);
            }
        };
    }
}

fn syscall_will_run(syscall: &mut SyscallObject) {
    // handle program break point
    if syscall.is_mem_alloc_dealloc() {
        set_memory_break_pre_call(syscall.tracee_pid);
    }
    match *FOLLOW_FORKS {
        true => {
            syscall.fill_buffer();
            flush_buffer();
            empty_buffer();
        }
        false => {
            syscall.state = SyscallState::Entering;
            syscall.fill_buffer();
        }
    }
}

fn syscall_returned(syscall: &mut SyscallObject, return_value: u64) {
    syscall.result = interpret_syscall_result(return_value);

    match *FOLLOW_FORKS {
        true => {
            syscall.fill_buffer();
            write_text("\n".white());
        }
        false => {
            if *FAILED_ONLY && !syscall.has_errored() {
                empty_buffer();
                return;
            }
            syscall.state = SyscallState::Exiting;
            syscall.fill_buffer();
            // this line was moved from the main loops to after this check ^
            // it was previously not aware of FAILED_ONLY being its edge-case
            // this resulted in long streaks of newlines in the output
            // this is also more correct
            write_text("\n".white());
        }
    }
    if syscall.currently_blocking {
        write_text(syscall_is_blocking());
    }
    flush_buffer();
    empty_buffer();
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
                write_text(" ├ ".custom_color(*GENERAL_TEXT_COLOR));
                write_text(" STOPPED ".on_custom_color(*STOPPED_COLOR));
                write_text("\n".white());
            }
        }
    }
}

fn handle_getting_registers_error(errno: Errno, syscall_enter_or_exit: &str, sysno: Sysno) {
    if sysno == Sysno::exit || sysno == Sysno::exit_group {
        // no longer needed
        // println!("\n\nSuccessfully exited\n");
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

        eprintln!("\n{}", table);
    } else {
        let output = TABLE.lock().unwrap();
        let mut vec = Vec::from_iter(output.iter());
        vec.sort_by(|(_, (_, duration, _)), (_, (_, duration2, _))| duration2.cmp(duration));

        use tabled::{builder::Builder, settings::Style};
        let mut builder = Builder::new();

        builder.push_record([
            "% time",
            "seconds",
            "usecs/call",
            "calls",
            "errors",
            "syscall",
        ]);
        builder.push_record([""]);
        let total_time = vec
            .iter()
            .map(|(_, (_, time, _))| time.as_micros())
            .sum::<u128>();
        let empty_string = "".to_owned();
        for (sys, (count, time, errors)) in vec {
            let time_MICROS = time.as_micros() as f64;
            let time = time_MICROS / 1_000_000.0;
            let usecs_call = (time_MICROS / *count as f64) as i64;
            let time_percent = time_MICROS / total_time as f64;
            let errors = if *errors == 0 {
                &empty_string
            } else {
                &errors.to_string()
            };
            builder.push_record([
                &format!("{:.2}", time_percent * 100.0),
                &format!("{:.6}", time),
                &format!("{}", usecs_call),
                &count.to_string(),
                errors,
                sys.name(),
            ]);
        }
        let table = builder.build().with(Style::ascii_rounded()).to_string();

        eprintln!("\n{}", table);
    }
}
