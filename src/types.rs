use crate::utilities::PAGE_SIZE;
use colored::Colorize;
use std::{convert::Infallible, fmt::Display, marker::PhantomData, mem::MaybeUninit};

pub type Annotation = [&'static str; 2];

pub type SysAnnotations = (Category, &'static str, &'static [Annotation], Annotation);

#[derive(Clone)]
pub struct Syscall_Shape {
    pub category: Category,
    pub types: &'static [SysArg],
    pub syscall_return: SysReturn,
}

#[derive(Clone, Copy, Debug)]
pub enum Flag {
    Map,
    Prot,
    Open,
    FileMode,
    FileRenameFlags,
    FileAtFlags,
    FileStatxFlags,
    ReMap,
    MSync,
    Madvise,
    MLock,
    MLockAll,
    Access,
    Signal,
    P_RW_V2_Flags,
    LSeekWhence,
    SignalHow,
    SignalFDFlags,
    EPollCreate1Flags,
    EPollCTLOperationFlags,
    SocketFamily,
    SocketType,
    SocketProtocol,
    SocketFlag,
    SocketOption,
    SocketLevel,
    SocketMessageFlag,
    SocketMessageReceiveFlag,
    FileChmodAtFlags,
    GetRandomFlags,
    RusageWhoFlags,
    FutexOpFlags,
    SocketShutdownFlag,
    EventfdFlag,
    FcntlFlags,
    ArchPrctlFlags,
    Dup3Flags,
    RSeqFlag,
    ResourceFlags,
    FallocFlags,
    LandlockRuleTypeFlag,
    WaitIdTypeFlags,
    CloneFlags,
    WaitEventFlags,
    LandlockAddRuleFlag,
    PriorityWhich,
    LandlockRestrictFlag,
    ReservedForFutureUse,
    LandlockCreateFlag,
}

type FD = &'static str;
type PID = &'static str;
type FD_PAIR = [&'static str; 2];
type ARR = &'static [&'static str];
type FLAG = Flag;
type Errored = MaybeUninit<bool>;
type FLAG_PAIR = [Flag; 2];
type ADDRESS = &'static str;
type SIGNAL = &'static str;
type TEXT = &'static str;

#[derive(Clone, Debug)]
pub enum SysArg {
    Numeric,
    Unsigned_Numeric,
    PID,
    User_Group,
    Address,
    Single_Word,
    Length_Of_Bytes,
    Length_Of_Bytes_Page_Aligned_Ceil,
    Length_Of_Bytes_Page_Aligned_Floor,
    Pointer_To_Unsigned_Numeric,
    Length_Of_Bytes_Specific,
    Pointer_To_Length_Of_Bytes_Specific,
    Pointer_To_Struct,
    Array_Of_Struct,
    Byte_Stream,
    Array_Of_Strings(ARR),
    General_Flag(FLAG),
    Multiple_Flags(FLAG_PAIR),
    Pointer_To_Numeric(Option<usize>),
    Pointer_To_Numeric_Or_Numeric(Option<usize>),
    Pointer_To_Path(TEXT),
    Pointer_To_Text(TEXT),
    File_Descriptor(FD),
    Pointer_To_File_Descriptor_Array(FD_PAIR),
    File_Descriptor_openat(FD),
}

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
    Always_Successful_User_Group,
    Always_Succeeds,
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
                write!(f, "{:.1} Kib", bytes)
            }
            Bytes::mega(bytes) => {
                write!(f, "{:.1} Mib", bytes)
            }
            Bytes::giga(bytes) => {
                write!(f, "{:.1} Gib", bytes)
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
                        .bright_blue();
                    write!(f, "{:.1} Bytes ({})", bytes, pages)
                }
                kilo(bytes) => {
                    let pages =
                        format!("{} Pages", f64::ceil((bytes * 1024.0) / *PAGE_SIZE as f64))
                            .bright_blue();
                    write!(f, "{:.1} KiB ({})", bytes, pages)
                }
                mega(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::ceil((bytes * 1_048_576.0) / *PAGE_SIZE as f64)
                    )
                    .bright_blue();
                    write!(f, "{:.1} MiB ({})", bytes, pages)
                }
                giga(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::ceil((bytes * 1_073_741_824.0) / *PAGE_SIZE as f64)
                    )
                    .bright_blue();
                    write!(f, "{:.1} GiB ({})", bytes, pages)
                }
            },
            PagesFloor(bytes) => match *bytes {
                norm(bytes) => {
                    let pages = format!("{} Pages", f64::floor(bytes as f64 / *PAGE_SIZE as f64))
                        .bright_blue();

                    write!(f, "{:.1} Bytes ({})", bytes, pages)
                }
                kilo(bytes) => {
                    let pages =
                        format!("{} Pages", f64::floor((bytes * 1024.0) / *PAGE_SIZE as f64))
                            .bright_blue();

                    write!(f, "{:.1} KiB ({})", bytes, pages)
                }
                mega(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::floor((bytes * 1_048_576.0) / *PAGE_SIZE as f64)
                    )
                    .bright_blue();

                    write!(f, "{:.1} MiB ({})", bytes, pages)
                }
                giga(bytes) => {
                    let pages = format!(
                        "{} Pages",
                        f64::floor((bytes * 1_073_741_824.0) / *PAGE_SIZE as f64)
                    )
                    .bright_blue();

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
