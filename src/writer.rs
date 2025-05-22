use crate::{
    cli::OUTPUT_FILE,
    colors::{
        EXITED_BACKGROUND_COLOR, GENERAL_TEXT_COLOR, OUR_YELLOW, PAGES_COLOR, PARTITION_1_COLOR,
        PARTITION_2_COLOR, PATHLIKE_ALTERNATOR, PID_BACKGROUND_COLOR,
    },
    utilities::{
        calculate_futex_alias, get_final_dentry_color_consider_repetition,
        get_strings_from_dirfd_anchored_file, partition_by_final_dentry, FUTEXES, PAGE_SIZE,
    },
};
use colored::{ColoredString, Colorize, CustomColor};
use nix::unistd::Pid;
use num_traits::{PrimInt, Signed, Unsigned};
use std::{
    borrow::Cow,
    io::{BufWriter, Write},
    sync::{LazyLock, Mutex, OnceLock},
};
use syscalls::Sysno;

pub static BUFFER: LazyLock<Mutex<Vec<ColoredString>>> = LazyLock::new(|| Mutex::new(Vec::new()));
pub static WRITER: OnceLock<Mutex<BufWriter<Box<dyn Write + Send>>>> = OnceLock::new();

pub fn initialize_writer() {
    // colored crate disables stderr's coloring when stdout is redirected elsewhere, e.g.: /dev/null
    // this is a workaround for now
    // https://github.com/colored-rs/colored/issues/125#issuecomment-1691155922
    use colored;
    colored::control::set_override(true);

    let sink: Box<dyn Write + Send> = if let Some(output) = *OUTPUT_FILE {
        match std::fs::File::options()
            .append(false)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output)
        {
            Ok(file) => Box::new(file),
            Err(_) => {
                eprintln!("Could not open or create file: {}", output.display());
                std::process::exit(100);
            }
        }
    } else {
        Box::new(std::io::stderr())
    };
    let _ = WRITER.set(Mutex::new(BufWriter::new(sink)));
}

#[inline(always)]
pub(crate) fn write_general_text(arg: &str) {
    buffered_write(arg.custom_color(*GENERAL_TEXT_COLOR));
}

#[inline(always)]
pub(crate) fn write_text(text: ColoredString) {
    buffered_write(text);
}

#[inline(always)]
pub fn buffered_write(data: ColoredString) {
    BUFFER.lock().unwrap().push(data);
}

#[inline(always)]
pub(crate) fn errorize_pid_color(text: ColoredString) {
    BUFFER.lock().unwrap()[0] = text;
}

#[inline(always)]
pub fn empty_buffer() {
    let mut buffer = BUFFER.lock().unwrap();
    buffer.clear();
}

#[inline(always)]
pub fn flush_buffer() {
    use std::io::Write;
    let mut buffer = BUFFER.lock().unwrap();
    let mut writer = WRITER.get().unwrap().lock().unwrap();
    for colored_text in buffer.iter_mut() {
        write!(writer, "{}", colored_text).unwrap();
    }
    writer.flush().unwrap();
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

pub fn write_vanilla_path_file(filename: &str) {
    use unicode_segmentation::UnicodeSegmentation;
    let graphemes = filename.graphemes(true);
    let (yellow, repetition_dependent) = partition_by_final_dentry(graphemes);

    write_path_consider_repetition(&yellow, &repetition_dependent);
}

pub fn write_colored(filename: String) {
    buffered_write(filename.normal())
}

pub fn write_path_consider_repetition(yellow: &str, repetition_dependent: &str) {
    write_partition_1_consider_repetition(yellow);
    write_partition_2_consider_repetition(repetition_dependent);
}

// repetition isnt relevant for the first partition of the path
// but the name is kept for consistency
#[inline(always)]
pub fn write_partition_1_consider_repetition(partition1: &str) {
    buffered_write(partition1.custom_color(*PARTITION_1_COLOR));
}

#[inline(always)]
pub fn write_partition_2_consider_repetition(partition2: &str) {
    // don't alternate if we're operating on a directory
    let partition_2_color = if partition2.len() != 0 {
        get_final_dentry_color_consider_repetition(partition2)
    } else {
        PARTITION_2_COLOR[*PATHLIKE_ALTERNATOR.lock().unwrap()]
    };
    buffered_write(partition2.custom_color(partition_2_color));
}

pub fn write_possible_dirfd_anchor(
    dirfd: i32,
    filename: String,
    tracee_pid: Pid,
) -> anyhow::Result<()> {
    let (first_partition, second_partition) =
        get_strings_from_dirfd_anchored_file(dirfd, filename.as_ref(), tracee_pid)?;
    match first_partition {
        Cow::Owned(string) => {
            write_path_consider_repetition(string.as_ref(), second_partition);
        }
        Cow::Borrowed(_empty) => {
            write_vanilla_path_file(second_partition);
        }
    }
    Ok(())
}

pub fn write_directives(mut vector: Vec<ColoredString>) {
    if !vector.is_empty() {
        // first element
        write_general_text(" (");
        write_text(vector.pop().unwrap());
        // remaining elements
        for entry in vector {
            write_general_text(", ");
            write_text(entry);
        }
        write_general_text(")");
    }
}

pub fn write_commas(mut vector: Vec<ColoredString>) {
    if !vector.is_empty() {
        // first element
        write_text(vector.pop().unwrap());
        // remaining elements
        for entry in vector {
            write_general_text(", ");
            write_text(entry);
        }
    }
}

pub fn write_oring(mut vector: Vec<ColoredString>) {
    if !vector.is_empty() {
        // first element
        write_text(vector.pop().unwrap());
        // remaining elements
        for entry in vector {
            write_general_text(", or ");
            write_text(entry);
        }
    }
}

pub fn write_anding(vector: Vec<ColoredString>) {
    let mut vector_iter = vector.into_iter();
    // first element
    if let Some(entry) = vector_iter.next() {
        write_text(entry);
    }
    // second and remaining elements
    if let Some(second_as_last) = vector_iter.next() {
        for entry in vector_iter {
            write_general_text(", ");
            write_text(entry);
        }
        // last element
        write_general_text(", and ");
        write_text(second_as_last);
    }
}
use thousands::Separable;
pub fn write_timespec(seconds: i64, nanoseconds: i64) {
    if seconds == 0 {
        if nanoseconds == 0 {
            write_text("immediately".custom_color(*OUR_YELLOW));
        } else {
            write_text("after ".custom_color(*OUR_YELLOW));
            write_text(
                nanoseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
            write_text(" nanoseconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text("after ".custom_color(*OUR_YELLOW));
        write_text(seconds.separate_with_commas().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if nanoseconds != 0 {
            write_general_text(", ");
            write_text(
                nanoseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
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
            write_text(
                nanoseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
            write_text(" nano-seconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text(seconds.separate_with_commas().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if nanoseconds != 0 {
            write_general_text(" and ");
            write_text(
                nanoseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
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
            write_text(
                microseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
            write_text(" microseconds".custom_color(*OUR_YELLOW));
        }
    } else {
        write_text("after ".custom_color(*OUR_YELLOW));
        write_text(seconds.separate_with_commas().custom_color(*PAGES_COLOR));
        write_text(" seconds".custom_color(*OUR_YELLOW));
        if microseconds != 0 {
            write_general_text(", ");
            write_text(
                microseconds
                    .separate_with_commas()
                    .custom_color(*PAGES_COLOR),
            );
            write_text(" microseconds".custom_color(*OUR_YELLOW));
        }
    }
}

// TODO!
// perf
pub fn write_signed_numeric(signed_numeric: impl PrimInt + Signed) {
    match signed_numeric.to_isize().unwrap() {
        -32767 => write_text("i16::MIN + 1".custom_color(CustomColor::new(0, 169, 233))),
        -32768 => write_text("i16::MIN".custom_color(CustomColor::new(0, 169, 233))),
        -32769 => write_text("i16::MIN - 1".custom_color(CustomColor::new(0, 169, 233))),
        -2147483647 => write_text("i32::MIN + 1".custom_color(CustomColor::new(0, 169, 233))),
        -2147483648 => write_text("i32::MIN".custom_color(CustomColor::new(0, 169, 233))),
        -2147483649 => write_text("i32::MIN - 1".custom_color(CustomColor::new(0, 169, 233))),
        -9223372036854775807 => {
            write_text("i64::MIN + 1".custom_color(CustomColor::new(0, 169, 233)))
        }
        -9223372036854775808 => write_text("i64::MIN".custom_color(CustomColor::new(0, 169, 233))),
        n => write_text(n.to_string().custom_color(CustomColor::new(0, 169, 233))),
    };
}

// TODO!
// perf
pub fn write_unsigned_numeric(unsigned_numeric: impl PrimInt + Unsigned) {
    match unsigned_numeric.to_usize().unwrap() {
        32766 => write_text("i16::MAX - 1".custom_color(CustomColor::new(0, 169, 233))),
        32767 => write_text("i16::MAX".custom_color(CustomColor::new(0, 169, 233))),
        32768 => write_text("i16::MAX + 1".custom_color(CustomColor::new(0, 169, 233))),
        65534 => write_text("u16::MAX - 1".custom_color(CustomColor::new(0, 169, 233))),
        65535 => write_text("u16::MAX".custom_color(CustomColor::new(0, 169, 233))),
        65536 => write_text("u16::MAX + 1".custom_color(CustomColor::new(0, 169, 233))),
        2147483646 => write_text("i32::MAX - 1".custom_color(CustomColor::new(0, 169, 233))),
        2147483647 => write_text("i32::MAX".custom_color(CustomColor::new(0, 169, 233))),
        2147483648 => write_text("i32::MAX + 1".custom_color(CustomColor::new(0, 169, 233))),
        4294967294 => write_text("u32::MAX - 1".custom_color(CustomColor::new(0, 169, 233))),
        4294967295 => write_text("u32::MAX".custom_color(CustomColor::new(0, 169, 233))),
        4294967296 => write_text("u32::MAX + 1".custom_color(CustomColor::new(0, 169, 233))),
        9223372036854775806 => {
            write_text("i64::MAX - 1".custom_color(CustomColor::new(0, 169, 233)))
        }
        9223372036854775807 => write_text("i64::MAX".custom_color(CustomColor::new(0, 169, 233))),
        9223372036854775808 => {
            write_text("i64::MAX + 1".custom_color(CustomColor::new(0, 169, 233)))
        }
        18446744073709551614 => {
            write_text("u64::MAX - 1".custom_color(CustomColor::new(0, 169, 233)))
        }
        18446744073709551615 => write_text("u64::MAX".custom_color(CustomColor::new(0, 169, 233))),
        n => write_text(n.to_string().custom_color(CustomColor::new(0, 169, 233))),
    }
}

// CONVERSION OUTSIDE
pub fn write_address(register_value: usize) {
    let pointer = register_value as *const ();
    if pointer.is_null() {
        write_text("NULL".custom_color(*OUR_YELLOW))
    } else {
        write_text(format!("{pointer:p}").custom_color(*OUR_YELLOW))
    }
}

// CONVERSION OUTSIDE
pub fn write_page_aligned_address(register_value: usize) {
    let pointer = register_value as *const ();
    if pointer.is_null() {
        write_text("NULL".custom_color(*OUR_YELLOW))
    } else {
        // the pipe notation can only be used for 4KiB & 64KiB page sizes
        // 16KiB is a common page size but its equivalent to 250 in decimal
        let pointer_formatted = format!("{pointer:p}");
        match *PAGE_SIZE {
            4096 => {
                write_text(pointer_formatted[..11].custom_color(*OUR_YELLOW));
                if register_value % 4096 == 0 {
                    write_text("|".custom_color(*PAGES_COLOR));
                } else {
                    write_text("|".red());
                }
                write_text(pointer_formatted[11..].custom_color(*OUR_YELLOW));
            }
            65536 => {
                write_text(pointer_formatted[..10].custom_color(*OUR_YELLOW));
                if register_value % 65536 == 0 {
                    write_text("|".custom_color(*PAGES_COLOR));
                } else {
                    write_text("|".red());
                }
                write_text(pointer_formatted[10..].custom_color(*OUR_YELLOW));
            }
            16384 => {
                write_text(pointer_formatted[..9].custom_color(*OUR_YELLOW));
                if register_value % 16384 == 0 {
                    write_text(
                        pointer_formatted[10..11]
                            .custom_color(*PAGES_COLOR)
                            .underline(),
                    );
                } else {
                    write_text(pointer_formatted[10..11].red().underline());
                }
                write_text(pointer_formatted[11..].custom_color(*OUR_YELLOW));
            }
            _ => write_text(pointer_formatted.custom_color(*OUR_YELLOW)),
        }
    }
}

pub fn write_futex(futex_address: usize) {
    let mut futexes = FUTEXES.lock().unwrap();
    let number_of_futexes = futexes.len();
    let futex_alias = futexes.entry(futex_address).or_insert_with(|| {
        calculate_futex_alias(number_of_futexes as _).custom_color(*PAGES_COLOR)
    });
    write_text(futex_alias.clone());
    write_text(format!(" {:p}", futex_address as *const ()).custom_color(*OUR_YELLOW));
}

pub fn write_exiting(process_pid: Pid) {
    let exited = " EXITED ".on_custom_color(*EXITED_BACKGROUND_COLOR);
    let pid = format!(" {} ", process_pid).on_custom_color(*PID_BACKGROUND_COLOR);
    write_text("\n\n ".white());
    write_text(pid);
    write_text(exited);
    write_text("\n\n".white());
}
