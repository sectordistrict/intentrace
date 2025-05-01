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
use cli::{IntentraceArgs, ATTACH_PID, BINARY_AND_ARGS, FAILED_ONLY, FOLLOW_FORKS, QUIET, SUMMARY};
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
     interpret_syscall_result, set_memory_break, syscall_is_blocking,
    HALT_TRACING, REGISTERS, TABLE, TABLE_FOLLOW_FORKS,
};
use writer::{initialize_writer,empty_buffer, flush_buffer, write_exiting, write_syscall_not_covered, write_text};

mod syscall_categories;
mod syscall_object;
// mod syscall_annotations_map;
// mod syscall_object_annotations;
mod syscall_skeleton_map;
mod types;
use syscall_object::{SyscallObject, SyscallState};
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
        if *SUMMARY {
            print_table();
        }
        std::process::exit(0);
    })?;
    if *FOLLOW_FORKS {
        match *ATTACH_PID {
            Some(_) => follow_forks(None),
            None => follow_forks(Some(*BINARY_AND_ARGS)),
        }
    } else {
        match *ATTACH_PID {
            Some(pid) => {
                let child = Pid::from_raw(pid as i32);
                ptrace::attach(child)?;
                parent(child);
            }
            None => match unsafe { fork() }? {
                Parent { child } => {
                    parent(child);
                }
                Child => {
                    child_trace_me(*BINARY_AND_ARGS);
                }
            },
        }
    }
    if !*FAILED_ONLY {
        // flush_buffer();
    }
    if *SUMMARY {
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

    // TRACE ME
    ptrace::traceme().unwrap();
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
            ptracer.spawn(command).unwrap();
            ptrace_ptracer(ptracer);
        }
        // ATTACHING TO PID
        None => {
            if let Some(attach_pid) = *ATTACH_PID {
                let mut ptracer = Ptracer::new();
                *ptracer.poll_delay_mut() = Duration::from_nanos(1);
                ptracer
                    .attach(pete::Pid::from_raw(attach_pid as i32))
                    .unwrap();
                ptrace_ptracer(ptracer);
            } else {
                eprintln!("Usage: invalid arguments\n");
            }
        }
    }
}

fn parent(child: Pid) {
    // skip first execve
    let _res = waitpid(child, None).unwrap();
    let mut syscall_entering = true;
    let (mut start, mut end) = (None, None);
    let mut syscall = SyscallObject::default();
    let mut supported = true;
    'main_loop: loop {
        match ptrace::syscall(child, None) {
            Ok(_void) => {
                let _res = waitpid(child, None).expect("Failed waiting for child.");
                match syscall_entering {
                    true => {
                        empty_buffer();
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
                                } else {
                                    write_syscall_not_covered(sysno, child);
                                    supported = false;
                                }
                            }
                            Err(errno) => {
                                if errno == Errno::ESRCH {
                                    write_exiting(child);
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
                                if supported {
                                    let mut table = TABLE.lock().unwrap();
                                    table
                                        .entry(syscall.sysno)
                                        .and_modify(|value| {
                                            value.0 += 1;
                                            value.1 = value.1.saturating_add(
                                                end.unwrap().duration_since(start.unwrap()),
                                            );
                                        })
                                        .or_insert((
                                            1,
                                            end.unwrap().duration_since(start.unwrap()),
                                        ));
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
                                supported = true;
                            }
                            Err(errno) => {
                                if errno == Errno::ESRCH {
                                    write_exiting(child);
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

fn ptrace_ptracer(mut ptracer: Ptracer) {
    let mut last_sysno: syscalls::Sysno = unsafe { mem::zeroed() };
    let mut last_pid = unsafe { mem::zeroed() };
    let mut pid_syscall_map: HashMap<Pid, SyscallObject> = HashMap::new();

    while let Some(tracee) = ptracer.wait().unwrap() {
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
                        let syscall_built = SyscallObject::build(syscall_pid, sysno);
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
                        } else {
                            write_syscall_not_covered(sysno, syscall_pid);
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
                        if let Some(syscall) = pid_syscall_map.get_mut(&syscall_pid) {
                            syscall_returned(syscall, registers.rax);
                            pid_syscall_map.remove(&syscall_pid).unwrap();
                        }
                    }
                    Err(errno) => handle_getting_registers_error(errno, "exit", last_sysno),
                }
                last_pid = syscall_pid;
            }
            _ => {}
        }
        ptracer.restart(tracee, Restart::Syscall).unwrap();
    }
}

fn syscall_will_run(syscall: &mut SyscallObject) {
    // handle program break point
    if syscall.is_mem_alloc_dealloc() {
        set_memory_break(syscall.tracee_pid);
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

        println!("\n{}", table);
    } else {
        let output = TABLE.lock().unwrap();
        let mut vec = Vec::from_iter(output.iter());
        vec.sort_by(
            |(_sysno, (_count, duration)), (_sysno2, (_count2, duration2))| duration2.cmp(duration),
        );

        use tabled::{builder::Builder, settings::Style};
        let mut builder = Builder::new();

        builder.push_record(["% time", "seconds", "usecs/call", "calls", "syscall"]);
        builder.push_record([""]);
        let total_time = vec
            .iter()
            .map(|(_, (_, time))| time.as_micros())
            .sum::<u128>();
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
