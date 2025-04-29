use std::{
    path::{Path, PathBuf},
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
pub static OUTPUT_FILE: LazyLock<Option<&Path>> = LazyLock::new(|| {
    INTENTRACE_ARGS
        .output
        .as_ref()
        .map(|pathbuf| pathbuf.as_path())
});
//
pub static INTENTRACE_ARGS: LazyLock<IntentraceArgs> = LazyLock::new(IntentraceArgs::parse);
pub static BINARY_AND_ARGS: LazyLock<&'static [String]> =
    LazyLock::new(|| match INTENTRACE_ARGS.binary {
        Some(Binary::Command(ref regs)) => regs,
        None => &[],
    });

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "intentrace is a strace for everyone.",
    version,
    allow_external_subcommands = true,
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
    pub output: Option<PathBuf>,

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
