#![allow(unused_variables)]
use crate::peeker_poker::{
    read_bytes_until_null, read_bytes_variable_length, read_one_word, read_words_until_null,
};
use crate::utilities::REGISTERS;
use crate::{
    types::{
        mlock2, Bytes, BytesPagesRelevant, Category, LandlockCreateFlags, LandlockRuleTypeFlags,
        SysReturn, Syscall_Shape,
    },
    utilities::{
        lose_relativity_on_path, static_handle_path_file, SYSCATEGORIES_MAP, SYSKELETON_MAP,
    },
};
use colored::{ColoredString, Colorize};
use core::num::NonZeroUsize;
use core::slice;
use errno::Errno;
use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use std::io::IoSlice;
use std::{
    fmt::Display,
    io::IoSliceMut,
    mem::{self, transmute, zeroed},
    os::{fd::RawFd, raw::c_void},
    path::PathBuf,
    ptr::null,
    sync::atomic::Ordering,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SyscallState {
    Entering,
    Exiting,
}

#[derive(Debug)]
pub enum SyscallResult {
    Fail(nix::errno::Errno),
    Success(u64),
}

use syscalls::Sysno;

#[derive(Debug)]
pub struct SyscallObject {
    pub sysno: Sysno,
    pub tracee_pid: Pid,
    pub state: SyscallState,
    pub paused: bool,
    pub result: SyscallResult,
}

impl Default for SyscallObject {
    fn default() -> Self {
        SyscallObject {
            sysno: unsafe { mem::zeroed() },
            result: unsafe { mem::zeroed() },
            tracee_pid: unsafe { mem::zeroed() },
            state: SyscallState::Entering,
            paused: false,
        }
    }
}

impl SyscallObject {
    pub fn fill_buffer(&mut self) {
        if let Ok(_) = self.one_line_formatter() {
            // let mut string = String::new();
            // for string_portion in &mut self.one_line {
            //     string.push_str(&format!("{}", string_portion));
            // }
            // print!("{}", string)
        } else {
            // disabled for now
            // switch to syscallobject_annotation formatting
            // let mut annot_variant = SyscallObject_Annotations::from(self);
            // annot_variant.format()
        }
    }
}

impl SyscallObject {
    pub(crate) fn get_sysno(orig_rax: i32) -> Sysno {
        Sysno::from(orig_rax)
    }

    pub(crate) fn build(child: Pid, sysno: Sysno) -> Option<Self> {
        let syscall = SYSKELETON_MAP.get(&sysno)?;
        let category = *SYSCATEGORIES_MAP.get(&sysno)?;
        Some(SyscallObject {
            sysno,
            tracee_pid: child,
            ..Default::default()
        })
    }

    pub(crate) fn style_bytes_page_aligned_ceil(register_value: u64) -> String {
        let bytes = BytesPagesRelevant::from_ceil(register_value as usize);
        bytes.to_string()
    }

    fn style_bytes_page_aligned_floor(register_value: u64) -> String {
        let bytes = BytesPagesRelevant::from_floor(register_value as usize);
        bytes.to_string()
    }

    fn style_bytes(register_value: u64) -> String {
        let bytes_amount = register_value as usize;
        let mut bytes = Bytes::norm(bytes_amount);
        if bytes_amount as f64 / 1_000_000_000.0 > 1.0 {
            bytes = Bytes::giga(bytes_amount as f64 / 1_000_000_000.0)
        } else if bytes_amount as f64 / 1_000_000.0 > 1.0 {
            bytes = Bytes::mega(bytes_amount as f64 / 1_000_000.0)
        } else if bytes_amount as f64 / 1_000.0 > 1.0 {
            bytes = Bytes::kilo(bytes_amount as f64 / 1_000.0)
        }
        bytes.to_string()
    }

    pub(crate) fn style_bytes_length_specific(register_value: u64) -> String {
        let bytes_amount = register_value as usize;
        let mut bytes = Bytes::norm(bytes_amount);
        if bytes_amount / 1_000_000_000 > 1 {
            bytes = Bytes::giga(bytes_amount as f64 / 1_000_000_000.0)
        } else if bytes_amount / 1_000_000 > 1 {
            bytes = Bytes::mega(bytes_amount as f64 / 1_000_000.0)
        } else if bytes_amount / 1_000 > 1 {
            bytes = Bytes::kilo(bytes_amount as f64 / 1_000.0)
        }
        bytes.to_string()
    }

    pub(crate) fn read_string_specific_length(
        addr: usize,
        child: Pid,
        size: usize,
    ) -> Option<String> {
        let bytes_buffer = read_bytes_variable_length(addr, child, size)?;
        Some(String::from_utf8_lossy(&bytes_buffer).into_owned())
    }

    pub(crate) fn is_mem_alloc_dealloc(&self) -> bool {
        // TODO!
        // scrutinize
        self.sysno == Sysno::brk || self.sysno == Sysno::mmap
    }

    pub(crate) fn is_exiting(&self) -> bool {
        self.sysno == Sysno::exit || self.sysno == Sysno::exit_group
    }

    pub(crate) fn has_errored(&self) -> bool {
        match self.result {
            SyscallResult::Fail(_) => true,
            SyscallResult::Success(_) => false,
        }
    }

    // TODO! check how strace does this, maybe its better
    pub(crate) fn colorize_syscall_name(sysno: &Sysno, category: &Category) -> ColoredString {
        match category {
            // green
            Category::Process => sysno.name().bold().green(),
            Category::Thread => sysno.name().bold().green(),
            Category::CPU => sysno.name().bold().green(),

            Category::Network => sysno.name().bold().green(),

            // ram
            Category::Memory => sysno.name().bold().bright_red(),

            // bluish
            Category::FileOp => sysno.name().bold().blue(),
            Category::DiskIO => sysno.name().bold().bright_blue(),
            Category::Security => sysno.name().bold().bright_cyan(),

            // black
            Category::System => sysno.name().bold().cyan(),

            // exotic
            Category::Signals => sysno.name().bold().magenta(),
            Category::Device => sysno.name().bold().bright_yellow(),
            Category::AsyncIO => sysno.name().bold().purple(),
        }
    }
}
