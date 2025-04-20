use crate::{
    colors::{EXITED_BACKGROUND_COLOR, OUR_YELLOW, PAGES_COLOR, PID_BACKGROUND_COLOR},
    utilities::lose_relativity_on_path,
};

use super::GENERAL_TEXT_COLOR;
use colored::{ColoredString, Colorize};
use nix::{libc::AT_FDCWD, unistd::Pid};
use std::{
    io::{BufWriter, Stdout},
    sync::{LazyLock, Mutex},
};
use syscalls::Sysno;
//
//
//
//
pub static BUFFER: LazyLock<Mutex<Vec<ColoredString>>> = LazyLock::new(|| Mutex::new(Vec::new()));
pub static WRITER_LAZY: LazyLock<Mutex<BufWriter<Stdout>>> = LazyLock::new(|| {
    let stdout = std::io::stdout();
    Mutex::new(BufWriter::new(stdout))
});
//
//
//
//
#[inline(always)]
pub(crate) fn write_general_text(arg: &str) {
    let text = arg.custom_color(*GENERAL_TEXT_COLOR);
    buffered_write(text);
}

#[inline(always)]
pub(crate) fn write_text(text: ColoredString) {
    buffered_write(text);
}

#[inline(always)]
pub fn buffered_write(data: ColoredString) {
    let mut buffer = BUFFER.lock().unwrap();
    buffer.push(data);
}

#[inline(always)]
pub(crate) fn errorize_pid_color(text: ColoredString) {
    let mut buffer = BUFFER.lock().unwrap();
    buffer[0] = text;
}

#[inline(always)]
pub fn empty_buffer() {
    use std::io::Write;
    let mut buffer = BUFFER.lock().unwrap();
    buffer.clear();
}

#[inline(always)]
pub fn flush_buffer() {
    use std::io::Write;
    let mut buffer = BUFFER.lock().unwrap();
    for colored_text in buffer.iter_mut() {
        write!(WRITER_LAZY.lock().unwrap(), "{}", colored_text).unwrap();
    }
    WRITER_LAZY.lock().unwrap().flush().unwrap();
}

#[inline(always)]
pub fn write_parenthesis(string: &str) {
    write_general_text(" (");
    write_text(string.custom_color(*OUR_YELLOW));
    write_general_text(")");
}

#[inline(always)]
pub fn write_syscall_not_covered(sysno: Sysno, tracee_pid: Pid) {
    buffered_write(tracee_pid.to_string().white());
    buffered_write(" ".dimmed());
    buffered_write(sysno.name().white());
    buffered_write(" - ".dimmed());
    buffered_write("[intentrace: syscall not covered yet]".white());
    buffered_write("\n".dimmed());
    flush_buffer();
}

pub fn write_path_file(filename: String) {
    let mut pathname = String::new();

    let mut file_start = 0;
    for (index, chara) in filename.chars().rev().enumerate() {
        if chara == '/' && index != 0 {
            file_start = filename.len() - index;
            break;
        }
    }
    write_text(filename[0..file_start].custom_color(*OUR_YELLOW));
    write_text(filename[file_start..].custom_color(*PAGES_COLOR));
}

pub fn write_possible_dirfd_file(dirfd: i32, filename: String, tracee_pid: Pid) {
    if filename.starts_with('.') {
        if dirfd == AT_FDCWD {
            let current_working_directory = procfs::process::Process::new(tracee_pid.into())
                .unwrap()
                .cwd()
                .unwrap();
            write_text(
                current_working_directory
                    .to_str()
                    .unwrap()
                    .custom_color(*OUR_YELLOW),
            );
            write_text(lose_relativity_on_path(filename.as_ref()).custom_color(*PAGES_COLOR));
        } else {
            let file_info = procfs::process::FDInfo::from_raw_fd(tracee_pid.into(), dirfd).unwrap();
            match file_info.target {
                procfs::process::FDTarget::Path(path) => {
                    write_text(path.to_str().unwrap().custom_color(*OUR_YELLOW));
                    write_text(
                        lose_relativity_on_path(filename.as_ref()).custom_color(*PAGES_COLOR),
                    );
                }
                _ => unreachable!(),
            }
        }
    } else {
        write_path_file(filename);
    }
}

pub fn write_directives(vector: Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    // first element
    if vector_iter.peek().is_some() {
        write_general_text(" (");
        write_text(vector_iter.next().unwrap());
        // remaining elements
        for entry in vector_iter {
            write_general_text(", ");
            write_text(entry);
        }
        write_general_text(")");
    }
}

pub fn write_vanilla_commas(vector: Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    // first element
    if vector_iter.peek().is_some() {
        write_text(vector_iter.next().unwrap());
    }
    // remaining elements
    for entry in vector_iter {
        write_general_text(", ");
        write_text(entry);
    }
}

pub fn write_oring(vector: Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    // first element
    if vector_iter.peek().is_some() {
        write_text(vector_iter.next().unwrap());
    }
    // second element
    if vector_iter.peek().is_some() {
        write_general_text(", or ");
        write_text(vector_iter.next().unwrap());
    }
    // remaining elements
    for entry in vector_iter {
        write_general_text(", or ");
        write_text(entry);
    }
}

pub fn write_anding(vector: Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter().peekable();
    // first element
    if vector_iter.peek().is_some() {
        write_text(vector_iter.next().unwrap());
    }
    // second and remaining elements
    if let Some(second_as_last) = vector_iter.next() {
        let third_and_forward = vector_iter;
        for entry in third_and_forward {
            write_general_text(", ");
            write_text(entry);
        }
        // last element
        write_general_text(", and ");
        write_text(second_as_last);
    }
}
pub fn write_timespec(seconds: i64, nanoseconds: i64) {
    if seconds == 0 {
        if nanoseconds == 0 {
            write_text("immediately".custom_color(*OUR_YELLOW));
        } else {
            write_text("after ".custom_color(*OUR_YELLOW));
            write_text(nanoseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" nanoseconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text("after ".custom_color(*OUR_YELLOW));
        write_text(seconds.to_string().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if nanoseconds != 0 {
            write_general_text(", ");
            write_text(nanoseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" nanoseconds".custom_color(*OUR_YELLOW));
        }
    }
}
pub fn write_timespec_non_relative(seconds: i64, nanoseconds: i64) {
    if seconds == 0 {
        if nanoseconds == 0 {
            write_text("0".custom_color(*PAGES_COLOR));
            write_text(" nano-seconds".custom_color(*OUR_YELLOW));
        } else {
            write_text(nanoseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" nano-seconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text(seconds.to_string().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if nanoseconds != 0 {
            write_general_text(" and ");
            write_text(nanoseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" nanoseconds".custom_color(*OUR_YELLOW));
        }
    }
}

pub fn write_timeval(seconds: i64, microseconds: i64) {
    if seconds == 0 {
        if microseconds == 0 {
            write_text("immediately".custom_color(*OUR_YELLOW));
        } else {
            write_text("after ".custom_color(*OUR_YELLOW));
            write_text(microseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" microseconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text("after ".custom_color(*OUR_YELLOW));
        write_text(seconds.to_string().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if microseconds != 0 {
            write_general_text(", ");
            write_text(microseconds.to_string().custom_color(*PAGES_COLOR));
            write_text(" microseconds".custom_color(*OUR_YELLOW));
        }
    }
}

pub fn write_exiting(process_pid: Pid) {
    let exited = " EXITED ".on_custom_color(*EXITED_BACKGROUND_COLOR);
    let pid = format!(" {} ", process_pid).on_custom_color(*PID_BACKGROUND_COLOR);
    write_text("\n\n ".white());
    write_text(pid);
    write_text(exited);
    write_text("\n\n".white());
}
