
use crate::{colors::PAGES_COLOR, utilities::PAGE_SIZE};
use colored::Colorize;
use std::{fmt::Display, mem::MaybeUninit};

pub type Annotation = [&'static str; 2];

pub type SysAnnotations = (&'static str, &'static [Annotation], Annotation);

#[derive(Clone)]
pub struct Syscall_Shape {
    // pub types: &'static [SysArg],
    pub syscall_return: SysReturn,
}

type FD = &'static str;
type PID = &'static str;
type FD_PAIR = [&'static str; 2];
type ARR = &'static [&'static str];
type Errored = MaybeUninit<bool>;
type ADDRESS = &'static str;
type SIGNAL = &'static str;
type TEXT = &'static str;

#[derive(Clone, Copy, Debug)]
pub enum SysReturn {
    Numeric_Or_Errno,
    Always_Successful_Numeric,
    Length_Of_Bytes_Specific_Or_Errno,
    Address_Or_Errno(ADDRESS),
    Address_Or_MAP_FAILED_Errno(ADDRESS),
    Address_Or_Errno_getcwd(ADDRESS),
    Signal_Or_Errno(SIGNAL),
    Priority_Or_Errno(Errored),
    File_Descriptor_Or_Errno(FD),
    Does_Not_Return_Anything,
    Ptrace_Diverse_Or_Errno,
    Always_Successful_User_Group,
    Always_Succeeds,
    Always_Errors,
    Never_Returns,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum Category {
    Process,
    System,
    Thread,
    Memory,
    DiskIO,
    FileOp,
    Network,
    CPU,
    Security,
    Device,
    AsyncIO,
    Signals,
}

impl Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::CPU => {
                write!(f, "CPU",)
            }
            Category::Memory => {
                write!(f, "Memory",)
            }
            Category::DiskIO => {
                write!(f, "Disk",)
            }
            Category::FileOp => {
                write!(f, "Disk",)
            }
            Category::Device => {
                write!(f, "Device",)
            }
            Category::Process => {
                write!(f, "Process",)
            }
            Category::AsyncIO => {
                write!(f, "AsyncIO",)
            }
            Category::Signals => {
                write!(f, "Signals",)
            }
            Category::Network => {
                write!(f, "Network",)
            }
            Category::Thread => {
                write!(f, "Thread",)
            }
            Category::System => {
                write!(f, "System",)
            }
            Category::Security => {
                write!(f, "Security",)
            }
        }
    }
}

// TODO!
// consider humansize crate

pub enum Bytes {
    norm(usize),
    kilo(f64),
    mega(f64),
    giga(f64),
}

impl Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bytes::norm(bytes) => {
                write!(f, "{:.1} Bytes", bytes)
            }
            Bytes::kilo(bytes) => {
                write!(f, "{:.1} KiB", bytes)
            }
            Bytes::mega(bytes) => {
                write!(f, "{:.1} MiB", bytes)
            }
            Bytes::giga(bytes) => {
                write!(f, "{:.1} GiB", bytes)
            }
        }
    }
}

impl From<usize> for Bytes {
    fn from(value: usize) -> Self {
        let value_float = value as f64;
        if (value_float / 1_073_741_824.0) >= 1.0 {
            Bytes::giga(value_float / 1_073_741_824.0)
        } else if (value_float / 1_048_576.0) >= 1.0 {
            Bytes::mega(value_float / 1_048_576.0)
        } else if (value_float / 1_024.0) >= 1.0 {
            Bytes::kilo(value_float / 1_024.0)
        } else {
            Bytes::norm(value)
        }
    }
}

pub enum BytesPagesRelevant {
    PagesCeil(Bytes),
    PagesFloor(Bytes),
}

impl BytesPagesRelevant {
    pub fn from_ceil(value: usize) -> Self {
        BytesPagesRelevant::PagesCeil(Bytes::from(value))
    }
    pub fn from_floor(value: usize) -> Self {
        BytesPagesRelevant::PagesFloor(Bytes::from(value))
    }
}

impl Display for BytesPagesRelevant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Bytes::*;
        use BytesPagesRelevant::*;
        match self {
            PagesCeil(bytes) => match *bytes {
                norm(bytes) => {
                    let pages = format!("{} Pages", f64::ceil(bytes as f64 / *PAGE_SIZE as f64))
                        .custom_color(*PAGES_COLOR);
                    write!(f, "{:.1} Bytes ({})", bytes, pages)
                }
                kilo(bytes) => {
                    let pages =
                        format!("{} Pages", f64::ceil((bytes * 1024.0) / *PAGE_SIZE as f64))
                            .custom_color(*PAGES_COLOR);
                    write!(f, "{:.1} KiB ({})", bytes, pages)
                }
                mega(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::ceil((bytes * 1_048_576.0) / *PAGE_SIZE as f64)
                    )
                    .custom_color(*PAGES_COLOR);
                    write!(f, "{:.1} MiB ({})", bytes, pages)
                }
                giga(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::ceil((bytes * 1_073_741_824.0) / *PAGE_SIZE as f64)
                    )
                    .custom_color(*PAGES_COLOR);
                    write!(f, "{:.1} GiB ({})", bytes, pages)
                }
            },
            PagesFloor(bytes) => match *bytes {
                norm(bytes) => {
                    let pages = format!("{} Pages", f64::floor(bytes as f64 / *PAGE_SIZE as f64))
                        .custom_color(*PAGES_COLOR);

                    write!(f, "{:.1} Bytes ({})", bytes, pages)
                }
                kilo(bytes) => {
                    let pages =
                        format!("{} Pages", f64::floor((bytes * 1024.0) / *PAGE_SIZE as f64))
                            .custom_color(*PAGES_COLOR);

                    write!(f, "{:.1} KiB ({})", bytes, pages)
                }
                mega(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::floor((bytes * 1_048_576.0) / *PAGE_SIZE as f64)
                    )
                    .custom_color(*PAGES_COLOR);

                    write!(f, "{:.1} MiB ({})", bytes, pages)
                }
                giga(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::floor((bytes * 1_073_741_824.0) / *PAGE_SIZE as f64)
                    )
                    .custom_color(*PAGES_COLOR);

                    write!(f, "{:.1} GiB ({})", bytes, pages)
                }
            },
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum mlock2 {
    MLOCK_ONFAULT = 1,
}

#[repr(C)]
#[derive(Debug)]
pub enum LandlockCreateFlags {
    LANDLOCK_CREATE_RULESET_VERSION = 1,
}

#[repr(C)]
#[derive(Debug)]
pub enum LandlockRuleTypeFlags {
    LANDLOCK_RULE_PATH_BENEATH = 1,
}
