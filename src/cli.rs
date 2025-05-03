use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        LazyLock,
    },
};

// TODO! Time blocks feature
// pub static TIME_BLOCKS: Cell<bool> = Cell::new(false);
pub static FOLLOW_FORKS: LazyLock<bool> = LazyLock::new(|| INTENTRACE_ARGS.follow_forks);
pub static STRING_LIMIT: AtomicUsize = AtomicUsize::new(36);
pub static FAILED_ONLY: LazyLock<bool> = LazyLock::new(|| INTENTRACE_ARGS.failed_only);
pub static QUIET: LazyLock<bool> = LazyLock::new(|| INTENTRACE_ARGS.mute_stdout);
pub static ANNOT: AtomicBool = AtomicBool::new(false);
pub static ATTACH_PID: LazyLock<Option<usize>> = LazyLock::new(|| INTENTRACE_ARGS.pid);
pub static SUMMARY: LazyLock<bool> = LazyLock::new(|| INTENTRACE_ARGS.summary);
pub static SYSCALLS_TO_TRACE: LazyLock<SysnoSet> = LazyLock::new(|| {
    if INTENTRACE_ARGS.trace.is_empty() {
        SysnoSet::all()
    } else {
        let mut sysno_set = SysnoSet::empty();
        for syscall in INTENTRACE_ARGS.trace.iter() {
            match Sysno::from_str(syscall) {
                Ok(sysno) => {
                    sysno_set.insert(sysno);
                }
                Err(_) => {
                    eprintln!("Invalid syscall: {}", syscall);
                    std::process::exit(100);
                }
            }
        }
        sysno_set
    }
});
pub static OUTPUT_FILE: LazyLock<Option<&Path>> = LazyLock::new(|| {
    INTENTRACE_ARGS
        .file
        .as_ref()
        .map(|pathbuf| pathbuf.as_path())
});
//
pub static INTENTRACE_ARGS: LazyLock<IntentraceArgs> = LazyLock::new(IntentraceArgs::parse);
pub static BINARY_AND_ARGS: LazyLock<Option<&'static [String]>> =
    LazyLock::new(|| match INTENTRACE_ARGS.binary {
        Some(Binary::Command(ref regs)) if !regs.is_empty() => Some(regs),
        _ => None,
    });

use clap::{Parser, Subcommand};
use syscalls::{Sysno, SysnoSet};

#[derive(Parser)]
#[command(
    about = "intentrace is a strace for everyone.",
    version,
    allow_external_subcommands = true
)]
pub struct IntentraceArgs {
    /// provide a summary table at the end of tracing
    #[arg(short = 'c', long)]
    pub summary: bool,

    /// attach to an already running proceess
    #[arg(short = 'p', long = "attach")]
    pub pid: Option<usize>,

    /// redirect intentrace's output to a provided file
    #[arg(short = 'o', long = "output")]
    pub file: Option<PathBuf>,

    /// trace a specific syscall or a group of syscalls delimited by ','
    #[arg(long, value_delimiter = ',')]
    pub trace: Vec<String>,

    /// trace child processes when traced programs create them
    #[arg(
        short = 'f',
        long = "follow-forks",
        conflicts_with = "pid",
        conflicts_with = "failed_only"
    )]
    pub follow_forks: bool,

    /// only print failed syscalls
    #[arg(short = 'Z', long = "failed-only")]
    pub failed_only: bool,

    /// mute the traced program's std output
    #[arg(short = 'q', long = "mute-stdout")]
    pub mute_stdout: bool,

    #[command(subcommand)]
    pub binary: Option<Binary>,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Binary {
    #[command(external_subcommand)]
    Command(Vec<String>),
}
