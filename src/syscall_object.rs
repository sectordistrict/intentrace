#![allow(unused_variables)]
use crate::auxiliary::kernel_errno::{self};
use crate::{
    types::Bytes,
    utilities::{SYSCATEGORIES_MAP, SYSKELETON_MAP},
};
use nix::unistd::Pid;
use std::{
    fmt::Display,
    mem::{self},
};

#[derive(Clone, Debug, PartialEq)]
pub enum SyscallState {
    Entering,
    Exiting,
}

#[derive(Debug)]
pub enum ErrnoVariant {
    Userland(nix::errno::Errno),
    Kernel(kernel_errno::KernelErrno),
}
impl Display for ErrnoVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrnoVariant::Userland(userland_errno) => {
                write!(f, "{:?}: {}", userland_errno, userland_errno.desc())
            }
            ErrnoVariant::Kernel(kernel_errno) => {
                write!(f, "{:?}: {}", kernel_errno, kernel_errno.desc())
            }
        }
    }
}

impl ErrnoVariant {
    pub fn desc(&self) -> &'static str {
        match self {
            ErrnoVariant::Userland(errno) => errno.desc(),
            ErrnoVariant::Kernel(kernel_errno) => kernel_errno.desc(),
        }
    }
}

#[derive(Debug)]
pub enum SyscallResult {
    Fail(ErrnoVariant),
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
    pub currently_blocking: bool,
}

impl Default for SyscallObject {
    fn default() -> Self {
        SyscallObject {
            sysno: unsafe { mem::zeroed() },
            result: unsafe { mem::zeroed() },
            tracee_pid: unsafe { mem::zeroed() },
            state: SyscallState::Entering,
            paused: false,
            currently_blocking: false,
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

    pub(crate) fn get_errno(&self) -> &ErrnoVariant {
        if let SyscallResult::Fail(ref errno_variant) = self.result {
            return errno_variant;
        }
        unreachable!()
    }

    pub(crate) fn build(tracee_pid: Pid, sysno: Sysno) -> Option<Self> {
        let syscall = SYSKELETON_MAP.get(&sysno)?;
        let category = *SYSCATEGORIES_MAP.get(&sysno)?;
        Some(SyscallObject {
            sysno,
            tracee_pid,
            ..Default::default()
        })
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

    pub(crate) fn is_mem_alloc_dealloc(&self) -> bool {
        // TODO!
        // scrutinize
        self.sysno == Sysno::brk || self.sysno == Sysno::mmap
    }

    pub(crate) fn is_exiting(&self) -> bool {
        self.sysno == Sysno::exit || self.sysno == Sysno::exit_group
    }

    pub(crate) fn has_errored(&self) -> bool {
        matches!(self.result, SyscallResult::Fail(_))
    }
}
