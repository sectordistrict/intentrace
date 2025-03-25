use std::{collections::HashMap, mem::MaybeUninit};

use syscalls::Sysno;

use crate::types::{Category, Flag, SysArg, SysReturn, Syscall_Shape};

// TODO! differentiate between bitflags (orables) and enums
// TODO! add granularity for value-return (kernel-modified) syscall arguments
// see if some arguments are better combined, like the very common buffer and buffer lengths (this
// makes processing cleaner but might result in complexity in non-conforming cases) clarify whether
// a buffer is provided by the user or to be filled by the kernel in the name of the argument (GIVE
// vs FILL) switch to MaybeUninit

// TODO! switch to phf later
pub fn initialize_skeletons_map() -> HashMap<Sysno, Syscall_Shape> {
    use Flag::*;
    use SysArg::*;
    use SysReturn::*;
    let array: Vec<(Sysno, Syscall_Shape)> = vec![
        // read from a file descriptor
        (
            Sysno::read,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        // write to a file descriptor
        (
            Sysno::write,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        // read from a file descriptor at a given offset
        (
            // Pread() basically works just like read()
            // but comes with its own offset
            // and doesnt modify the file pointer.

            // If you read() twice, you get different results
            // If you pread() twice, you get the same result

            // the system call was renamed in from pread() to pread64(). The syscall numbers remain
            // the same. The glibc pread() and pwrite() wrapper functions transparently
            // deal with the change. parallel read
            // also: stateless read
            Sysno::pread64,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        // write to a file descriptor at a given offset
        (
            // the system call was renamed in from pwrite() to pwrite64(). The syscall numbers
            // remain the same. The glibc pread() and pwrite() wrapper functions
            // transparently deal with the change. parallel write
            // also: stateless write
            Sysno::pwrite64,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            // The readv() function behave the same as read( ), except that multiple buffers are
            // read to. this is used when memory to read from is scattered around (not
            // contiguous) this avoids multiple read syscalls that would otherwise be
            // needed
            //
            // readv: read vectored
            // you use it when you know that you have multiple fixed size blocks of data
            // to read into non-contiguous memory locations
            Sysno::readv,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Array_Of_Struct, Unsigned_Numeric],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            // same as readv
            Sysno::writev,
            Syscall_Shape {
                types: &[
                    File_Descriptor(""),
                    Array_Of_Struct,
                    Unsigned_Numeric,
                ],
                syscall_return: // zero means what in here? man pages dont say anything
                Length_Of_Bytes_Specific_Or_Errno
                },
        ),
        (
            // parallel read vectored
            Sysno::preadv,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Array_Of_Struct,
                    Unsigned_Numeric,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            // parallel write vectored
            Sysno::pwritev,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Array_Of_Struct,
                    Unsigned_Numeric,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        // (
        //     Sysno::preadv2,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Array_Of_Struct,
        //             Unsigned_Numeric,
        //             Length_Of_Bytes_Specific,
        //             General_Flag(P_RW_V2_Flags),
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::pwritev2,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Array_Of_Struct,
        //             Unsigned_Numeric,
        //             Length_Of_Bytes_Specific,
        //             General_Flag(P_RW_V2_Flags),
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        (
            Sysno::pipe,
            Syscall_Shape {
                types:          &[Pointer_To_File_Descriptor_Array(["", ""])],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::pipe2,
            Syscall_Shape {
                types:          &[Pointer_To_File_Descriptor_Array(["", ""]), General_Flag(Open)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // duplicate a file descriptor
        // creates a copy of the file descriptor oldfd, using the lowest-numbered unused file
        // descriptor for the new descriptor.
        (
            Sysno::dup,
            Syscall_Shape {
                types:          &[File_Descriptor("")],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        // same as dup, but uses newfd for the fd
        // it overrwrites the newfd if its used
        // If newfd was previously open, it is closed before being reused
        (
            Sysno::dup2,
            Syscall_Shape {
                types:          &[File_Descriptor(""), File_Descriptor("")],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        // same as dup2 but the caller can force the close-on-exec flag to be set for the new file
        // descriptor by specifying O_CLOEXEC in flags.
        (
            Sysno::dup3,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    File_Descriptor(""),
                    General_Flag(Dup3Flags),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            Sysno::access,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), General_Flag(Access)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::faccessat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(Access),
                    General_Flag(FileAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::faccessat2,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(Access),
                    General_Flag(FileAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // open and possibly create a file
        // open handles a relative path by considering it relative to the current process working
        // directory files must be opened first before being read from or written to
        (
            Sysno::open,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Text(""),
                    // flags: one of the following modes: O_RDONLY, O_WRONLY, or O_RDWR.
                    // and an optional or of others
                    General_Flag(Open),
                    General_Flag(FileMode),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        // openat handles a relative path by considering it relative to the directory of dirfd
        // if AT_FDCWD is used in dirfd, then it is identical to open
        // if the path is absolute then dirfd is ignored
        (
            Sysno::openat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor_openat(""),
                    Pointer_To_Text(""),
                    General_Flag(Open),
                    General_Flag(FileMode),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        // an extension of openat(2) and provides a superset of its functionality.
        // operaes with the same logic as openat()
        // (
        //     Sysno::openat2,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Text(""),
        //             Pointer_To_Struct,
        //             Length_Of_Bytes,
        //         ],
        //         syscall_return: File_Descriptor_Or_Errno(""),
        //     },
        // ),
        // calling creat() is equivalent to calling open() with flags equal to
        // O_CREAT|O_WRONLY|O_TRUNC (
        //     Sysno::creat,
        //     Syscall_Shape {
        //         types: &[Pointer_To_Text(""), General_Flag(FileMode)],
        //         syscall_return: File_Descriptor_Or_Errno(""),
        //     },
        // ),
        (
            Sysno::getcwd,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Length_Of_Bytes_Specific],
                syscall_return: Address_Or_Errno_getcwd(""),
            },
        ),
        // (
        //     Sysno::chdir,
        //     Syscall_Shape {
        //         types: &[Pointer_To_Text("")],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::fchdir,
        //     Syscall_Shape {
        //         types: &[File_Descriptor("")],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        (
            Sysno::rename,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Pointer_To_Text("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::renameat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::renameat2,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(FileRenameFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::mkdir,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), General_Flag(FileMode)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::mkdirat,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Pointer_To_Text(""), General_Flag(FileMode)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::link,
        //     Syscall_Shape {
        //         // after hard linking it is impossible to tell which file was the original
        //         // because they both point to the same inode now
        //         //
        //         // The link() system call can be used to detect and trace malicious or
        // suspicious file modification.         // For example, if a malicious user is
        // trying to modify or delete files in a system,         // creating/deleting a
        // hard link to the file is one way to do this.         // Tracking the link()
        // system call will notify if any files are modified in this way.         types: &[
        //             Pointer_To_Text(""),
        //             // if existing, will not be overwritten
        //             Pointer_To_Text(""),
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::linkat,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Text(""),
        //             File_Descriptor(""),
        //             // if existing, will not be overwritten
        //             Pointer_To_Text(""),
        //             General_Flag(FileAtFlags),
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        (
            Sysno::unlink,
            Syscall_Shape {
                // Each inode on your FileOp has a reference count - it knows how many places refer
                // to it. A directory entry is a reference. Multiple references to the same inode
                // can exist. unlink removes a reference. When the reference count is zero, then
                // the inode is no longer in use and may be deleted. This is how many things work,
                // such as hard linking and snap shots. In particular - an open
                // file handle is a reference. So you can open a file, unlink it, and continue to
                // use it - it'll only be actually removed after the file handle is closed
                // (provided the reference count drops to zero, and it's not open/hard linked
                // anywhere else).
                types:          &[Pointer_To_Text("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::unlinkat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(FileAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::rmdir,
        //     Syscall_Shape {
        //         types: &[Pointer_To_Text("")],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        (
            // A symbolic link (also known as a soft link) may becomoe dangling
            // (point to a nonexistent file);
            Sysno::symlink,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Text(""),
                    // If linkpath exists, it will not be overwritten.
                    Pointer_To_Text(""),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::symlinkat,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Text(""),
                    File_Descriptor(""),
                    // If linkpath exists, it will not be overwritten.
                    Pointer_To_Text(""),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // contents of the symbolic link pathname in the buffer buf,
            Sysno::readlink,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Text(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            Sysno::readlinkat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Pointer_To_Text(""),
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            Sysno::chmod,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), General_Flag(FileMode)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::fchmod,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    // the RWX combination variants are infact a combination of the 3 R W X flags
                    // its not its own variant
                    General_Flag(FileMode),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::fchmodat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(FileMode),
                    General_Flag(FileChmodAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::fchmodat2,
        // ),
        (
            Sysno::chown,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Unsigned_Numeric, Unsigned_Numeric],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::fchown,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Unsigned_Numeric, Unsigned_Numeric],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // same as chown but does not recursively follow a symbolic link
        // it will simply change ownership of the link itself
        (
            Sysno::lchown,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Unsigned_Numeric, Unsigned_Numeric],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::fchownat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Numeric,
                    Numeric,
                    General_Flag(FileAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // file-system level sync
            Sysno::sync,
            Syscall_Shape { types: &[], syscall_return: Does_Not_Return_Anything },
        ),
        (
            // file-system level sync
            Sysno::syncfs,
            Syscall_Shape {
                types:          &[File_Descriptor("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // file level sync
            Sysno::fsync,
            Syscall_Shape {
                types:          &[File_Descriptor("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // The aim of fdatasync() is to reduce disk activity for applications
        // that do not require all metadata to be synchronized with the disk.
        (
            // file level sync
            Sysno::fdatasync,
            Syscall_Shape {
                types:          &[File_Descriptor("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        //      (
        //          Sysno::mount,
        //      ),
        //      (
        //          Sysno::umount2,
        //      ),
        //      (
        //          Sysno::swapon,
        //      ),
        //      (
        //          Sysno::swapoff,
        //      ),
        //      (
        //          Sysno::pivot_root,
        //      ),
        //      (
        //          Sysno::chroot,
        //      ),
        (
            // file must be writable.
            Sysno::truncate,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Length_Of_Bytes_Specific],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // file must be open for writing
            Sysno::ftruncate,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Length_Of_Bytes_Specific],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        //    (
        //     ),
        //     (
        //     ),
        //     (
        //     ),
        //     (
        //     ),
        //     (
        //     ),

        // closes a file descriptor, so that it no longer refers to any file and may be reused
        (
            Sysno::close,
            Syscall_Shape {
                types:          &[File_Descriptor("")],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // return information about a file using a path
        (
            Sysno::stat,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // return information about a file using a file descriptor
        (
            Sysno::fstat,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // return information about a file but does not recursively follow a symbolic link
        // it will simply return information about the link itself
        (
            Sysno::lstat,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::newfstatat,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    Pointer_To_Struct,
                    General_Flag(FileAtFlags),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::statx,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Text(""),
                    General_Flag(FileAtFlags),
                    General_Flag(FileStatxFlags),
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::statfs,
            Syscall_Shape {
                types:          &[Pointer_To_Text(""), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::fstatfs,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     // deprecated syscall
        //     Sysno::ustat,
        //     Syscall_Shape {
        //         types: &[Unsigned_Numeric, Pointer_To_Struct],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::cachestat,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // pages ceil
        //             Pointer_To_Struct,
        //             Pointer_To_Struct,
        //             // Some unknown flag argument
        //             General_Flag(ReservedForFutureUse),
        //         ],
        //         // unknown for now error value
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::statmount,
        // ),

        // reposition read/write file offset
        (
            Sysno::lseek,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Length_Of_Bytes_Specific,
                    General_Flag(LSeekWhence),
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            Sysno::mmap,
            Syscall_Shape {
                types:          &[
                    // Nullable
                    Address,
                    Length_Of_Bytes_Page_Aligned_Ceil,
                    // must not conflict with the open mode of the file
                    General_Flag(Prot),
                    General_Flag(Map),
                    File_Descriptor(""),
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Address_Or_MAP_FAILED_Errno(""),
            },
        ),
        // set protection on a region of memory
        (
            Sysno::mprotect,
            Syscall_Shape {
                types:          &[Address, Length_Of_Bytes_Page_Aligned_Ceil, General_Flag(Prot)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // deletes the mappings for the specified address range
        (
            Sysno::munmap,
            Syscall_Shape {
                types:          &[Address, Length_Of_Bytes_Page_Aligned_Ceil],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::brk,
            Syscall_Shape {
                types:          &[Address],
                // However, the actual Linux system call returns the new program break on success.
                syscall_return: Address_Or_Errno(""),
            }, /* On failure, the system call returns the current break.
                * to know if an error occured you have to store the previous program break point
                * somewhere to compare */
        ),
        (
            Sysno::mlock,
            Syscall_Shape {
                types:          &[
                    Address,
                    // Pages Ceil
                    Length_Of_Bytes_Page_Aligned_Ceil,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // mlock2 is linux specific
        (
            Sysno::mlock2,
            Syscall_Shape {
                types:          &[
                    Address,
                    // Pages Ceil
                    Length_Of_Bytes_Page_Aligned_Ceil,
                    // if flag is 0 mlock2 is identical to mlock
                    // MLOCK_ONFAULT
                    //      Lock the pages that are currently resident
                    //      and mark the entire range including non-resident pages
                    //      so that when they are later populated by a page fault
                    //      they get locked
                    General_Flag(MLock),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // Memory locking and unlocking are performed in units of whole pages.
            Sysno::munlock,
            Syscall_Shape {
                types:          &[
                    Address,
                    // Pages Ceil
                    Length_Of_Bytes_Page_Aligned_Ceil,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // Memory locking and unlocking are performed in units of whole pages.
            // this is equivalent to MAP_POPULATE (unless the flag is specified for custom
            // behaviour for non-resident and future pages)
            Sysno::mlockall,
            Syscall_Shape {
                types:          &[General_Flag(MLockAll)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // Memory locking and unlocking are performed in units of whole pages.
            Sysno::munlockall,
            Syscall_Shape { types: &[], syscall_return: Numeric_Or_Errno },
        ),
        // expands (or shrinks) an existing memory mapping, potentially moving it at the same time
        (
            Sysno::mremap,
            Syscall_Shape {
                types:          &[
                    // must be page aligned
                    Address,
                    Length_Of_Bytes_Page_Aligned_Ceil,
                    Length_Of_Bytes_Page_Aligned_Ceil,
                    General_Flag(ReMap),
                    Address,
                ],
                syscall_return: Address_Or_MAP_FAILED_Errno(""),
            },
        ),
        // flushes changes made to the file copy mapped in memory back to the filesystem.
        (
            Sysno::msync,
            Syscall_Shape {
                types:          &[Address, Length_Of_Bytes_Page_Aligned_Ceil, General_Flag(MSync)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // returns a vector that represent whether pages of the calling process's virtual memory
        // are resident in core (RAM), and so will not cause a disk access (page fault) if
        // referenced
        (
            // memory in core
            Sysno::mincore,
            Syscall_Shape {
                types:          &[Address, Length_Of_Bytes_Page_Aligned_Ceil, Byte_Stream],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // give advice about use of memory
        (
            Sysno::madvise,
            Syscall_Shape {
                types:          &[
                    // only operates on whole pages
                    // so must be page aligned
                    Address,
                    Length_Of_Bytes_Page_Aligned_Ceil,
                    General_Flag(Madvise),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::select,
            Syscall_Shape {
                types:          &[
                    Numeric,
                    // you can set any of these sets to NULL if you don’t care about waiting for it
                    Pointer_To_Struct,
                    Pointer_To_Struct,
                    Pointer_To_Struct,
                    // Some Unices update the timeout here to show how much time is left, not all
                    // of them If you set the fields in your struct timeval to
                    // 0, select() will timeout immediately, effectively
                    // polling all the file descriptors in your sets.
                    // If you set the parameter timeout to NULL,
                    // it will wait forever until the first file descriptor is ready.
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::pselect6,
            Syscall_Shape {
                types:          &[
                    Numeric,
                    // you can set any of these sets to NULL if you don’t care about waiting for it
                    Pointer_To_Struct,
                    Pointer_To_Struct,
                    Pointer_To_Struct,
                    // pselect never updates timeout to indicate how much time is left (normal
                    // select does that in some unices) If you set the fields
                    // in your struct timeval to 0, select() will timeout
                    // immediately, effectively polling all the file descriptors in your sets.
                    // If you set the parameter timeout to NULL,
                    // it will wait forever until the first file descriptor is ready.
                    Pointer_To_Struct,
                    // The final argument of the pselect6() system call is not a sigset_t *
                    // pointer, but is instead a structure of the form:
                    // struct {
                    //     const kernel_sigset_t *ss;   /* Pointer to signal set */
                    //     size_t ss_len;               /* Size (in bytes) of object pointed to by
                    // 'ss' */ };
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::poll,
            Syscall_Shape {
                types:          &[Array_Of_Struct, Unsigned_Numeric, Numeric],
                // It doesn’t tell you which elements (you still have to scan for that), it only
                // tell you how many,
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::ppoll,
            Syscall_Shape {
                types:          &[
                    Array_Of_Struct,
                    Unsigned_Numeric,
                    Pointer_To_Struct,
                    // if null then no mask manipulation is performed
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                // It doesn’t tell you which elements (you still have to scan for that),
                syscall_return: Numeric_Or_Errno,
            }, // it only tell you how many,
        ),
        (
            // This file descriptor is used for all the subsequent calls to the epoll interface.
            // the file descriptor returned by epoll_create() should be closed by using close(2)
            Sysno::epoll_create,
            Syscall_Shape {
                types:          &[
                    // in the past this size parameter told the kernel how many fds the caller
                    // expects to add the kerenl now however does not need that
                    // information and instead dynamically allocates space
                    // it is kept for backward compatibility
                    // and must be greater than zero
                    Unsigned_Numeric,
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            // This file descriptor is used for all the subsequent calls to the epoll interface.
            // the file descriptor returned by epoll_create1() should be closed by using close(2)
            // epoll_create but with a bahviour customizing flag
            Sysno::epoll_create1,
            Syscall_Shape {
                types:          &[
                    // if this argument is zero, this syscall is identical to epoll_create
                    General_Flag(EPollCreate1Flags),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            // A call to epoll_wait() will block until either:
            //     • a file descriptor delivers an event;
            //     • the call is interrupted by a signal handler (different from epoll_pwait)
            //     • the timeout expires.
            Sysno::epoll_wait,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Struct,
                    Unsigned_Numeric,
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    Numeric,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // similar to epoll_wait but also waits for specific signals
            Sysno::epoll_pwait,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Struct,
                    Unsigned_Numeric,
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    Numeric,
                    // if null this syscall is equivalent to epoll_pwait
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // similar to epoll_pwait but has nanosend resolution
            Sysno::epoll_pwait2,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Pointer_To_Struct,
                    Unsigned_Numeric,
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    Pointer_To_Struct,
                    // if null this syscall is equivalent to epoll_pwait
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::epoll_ctl,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    General_Flag(EPollCTLOperationFlags),
                    File_Descriptor(""),
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::socket,
        //     Syscall_Shape {
        //         types: &[
        //             General_Flag(SocketFamily),
        //             General_Flag(SocketType),
        //             General_Flag(SocketProtocol),
        //         ],
        //         syscall_return: File_Descriptor_Or_Errno(""),
        //     },
        // ),
        // (
        //     Sysno::bind,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Struct,
        //             Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::getsockname,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // The returned information is truncated if the buffer provided is too small
        // (addrlen small)             Pointer_To_Struct,
        //             // upon return this pointer gets updated with the length of bytes written in
        // the buffer             // but in this case of truncation
        //             // it will return a value greater
        //             // than was supplied to the call.
        //             Pointer_To_Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::getpeername,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // The returned information is truncated
        //             // if the buffer provided is too small (addrlen small);
        //             Pointer_To_Struct,
        //             // upon return this pointer gets updated with the length of bytes written in
        // the buffer             // but in this case of truncation
        //             // it will return a value greater
        //             // than was supplied to the call.
        //             Pointer_To_Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::socketpair,
        //     Syscall_Shape {
        //         types: &[
        //             General_Flag(SocketFamily),
        //             General_Flag(SocketType),
        //             General_Flag(SocketProtocol),
        //             // (ValueReturn(Pointer_To_File_Descriptor_Array(["", ""],syscall_return:
        // Pointer_To_File_Descriptor_Array(["", ""]))
        // Pointer_To_File_Descriptor_Array(["", ""]),         ],
        //         // on error sv is left unchanged
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::setsockopt,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             General_Flag(SocketLevel),
        //             General_Flag(SocketOption),
        //             // the argument should be
        //             // nonzero to enable a boolean option,
        //             // or zero if the option is to be disabled.
        //             Pointer_To_Struct,
        //             Pointer_To_Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::getsockopt,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             General_Flag(SocketLevel),
        //             General_Flag(SocketOption),
        //             Pointer_To_Struct,
        //             //    optlen is a value-result argument
        //             //     initially containing the size of optval buffer
        //             //     and on return modified to the actual size of the value returned
        //             //     can be NULL If no option value is to be supplied or returned,
        //             Pointer_To_Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::listen,
        //     Syscall_Shape {
        //         types: &[File_Descriptor(""), Numeric],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::accept,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // nullable, and when nullable it is not filled
        //             Pointer_To_Struct,
        //             // addrlen is a value-result argument
        //             // initially containing the size of optval buffer
        //             // and on return modified to the actual size of the value returned
        //             // can be NULL If no option value is to be supplied or returned,
        //             Pointer_To_Struct,
        //         ],
        //         // -1 on error, errno modified
        //         syscall_return: File_Descriptor_Or_Errno(""),
        //     },
        // ),
        // (
        //     // identical to accept
        //     // except that it has flag arguments which save from doing extra calls to fcntl(2)
        //     // the flags are to: 1- set socket as non-blocking, 2- set socket as close-on-exec
        //     Sysno::accept4,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // nullable, and when nullable it is not filled
        //             Pointer_To_Struct,
        //             // addrlen is a value-result argument
        //             // initially containing the size of optval buffer
        //             // and on return modified to the actual size of the value returned
        //             // can be NULL If no option value is to be supplied or returned,
        //             Pointer_To_Struct,
        //             // if this flag is 0 then accept4 is identical to accept
        //             General_Flag(SocketFlag),
        //         ],
        //         // -1 on error, errno modified
        //         syscall_return: File_Descriptor_Or_Errno(""),
        //     },
        // ),
        // (
        //     Sysno::connect,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Struct,
        //             Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Numeric_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::sendto,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Text(""),
        //             Length_Of_Bytes_Specific,
        //             General_Flag(SocketMessageFlag),
        //             // WILL BE USED if connection-less (like UDP)
        //             // WILL BE IGNORED if connection-mode (like TCP, or SEQ) and must be null or
        // 0             Pointer_To_Struct,
        //             // IGNORED if connection-mode (like TCP, or SEQ) (UDP IS CONNECTIONLESS) and
        // must be null or 0             Length_Of_Bytes_Specific,
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::sendmsg,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             Pointer_To_Struct,
        //             General_Flag(SocketMessageFlag),
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::recvfrom,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // If a message is too long to fit in the supplied buffer,
        //             // excess bytes may be discarded depending
        //             // on the type of socket the message is received from.
        //             Pointer_To_Text(""),
        //             Length_Of_Bytes_Specific,
        //             General_Flag(SocketMessageReceiveFlag),
        //             // if src_addr and addrlen are NULL
        //             // it means we do not care or want src_addr details
        //             // otherwise addrlen is value-result argument
        //             Pointer_To_Struct,
        //             // value-result argument, will become the length of the buffer, and
        // truncation rules apply             Pointer_To_Struct,
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        // (
        //     Sysno::recvmsg,
        //     Syscall_Shape {
        //         types: &[
        //             File_Descriptor(""),
        //             // If a message is too long to fit in the supplied buffer,
        //             // excess bytes may be discarded depending
        //             // on the type of socket the message is received from.
        //             Pointer_To_Struct,
        //             General_Flag(SocketMessageFlag),
        //         ],
        //         syscall_return: Length_Of_Bytes_Specific_Or_Errno,
        //     },
        // ),
        (
            Sysno::shutdown,
            Syscall_Shape {
                types:          &[File_Descriptor(""), General_Flag(SocketShutdownFlag)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::sendfile,
        // ),
        (
            Sysno::fcntl,
            Syscall_Shape {
                types:          &[File_Descriptor(""), General_Flag(FcntlFlags), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::ioctl,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    Unsigned_Numeric,
                    // The arg parameter to the ioctl is opaque at the generic vfs level (an opaque
                    // data type is a data type whose concrete data structure is not defined in an
                    // interface) How to interpret it is up to the driver or
                    // filesystem that actually handles it So it may be a
                    // pointer to userspace memory, or it could be an index, a flag, whatever
                    // It might even be unused and conventionally passed in a 0
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::prctl,
        // ),
        (
            Sysno::arch_prctl,
            Syscall_Shape {
                types:          &[
                    General_Flag(ArchPrctlFlags),
                    // TODO! this argument is a number for set operations and a pointer to a number
                    // for get operations Pointer_To_Numeric_Or_Numeric is a
                    // special case for arch_prctl, because it depends on the op union
                    Pointer_To_Numeric_Or_Numeric(None),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // causes the calling thread to relinquish the CPU.
        // The thread is moved to the end of the queue for its static priority and a new thread
        // gets to run.
        (Sysno::sched_yield, Syscall_Shape { types: &[], syscall_return: Numeric_Or_Errno }),
        (
            // change the action taken by a process on receipt of a specific signal
            Sysno::rt_sigaction,
            Syscall_Shape {
                types:          &[
                    // can be any valid signal except SIGKILL and SIGSTOP.
                    General_Flag(Signal),
                    // new action
                    Pointer_To_Struct,
                    // old action
                    // nullable meaning we dont want it
                    Pointer_To_Struct,
                    // Size of sigset in new action
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::rt_sigprocmask,
            Syscall_Shape {
                types:          &[
                    General_Flag(SignalHow),
                    // If NULL, then the signal mask is unchanged.
                    Pointer_To_Struct,
                    // If non-NULL, the previous value of the mask is stored here.
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // basically
            // 1- change the signal mask
            // 2- immediately BLOCK the process waiting for a signal on that new mask to trigger
            // (its like what ptrace TRACE_ME does)
            Sysno::rt_sigsuspend,
            Syscall_Shape {
                types:          &[
                    // SIGKILL or SIGSTOP can not be blocked
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                // always returns -1, with errno set to indicate the error (normally, EINTR)
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // used during signal handling
            // A signal stack is a special area of memory
            // to be used as the execution stack during signal handling
            // It should be fairly large, to avoid any danger that it will overflow
            Sysno::sigaltstack,
            Syscall_Shape {
                types:          &[
                    // can be null if dont want this part of the operation
                    Pointer_To_Struct,
                    // NULLABLE meaning we dont want it
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // created to immediately run after signal handlers, to clean up and correct stack
            // pointer/program counter
            Sysno::rt_sigreturn,
            Syscall_Shape { types: &[], syscall_return: Never_Returns },
        ),
        (
            Sysno::rt_sigpending,
            Syscall_Shape {
                types:          &[Pointer_To_Struct, Length_Of_Bytes_Specific],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::rt_sigtimedwait,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Struct,
                    // NULLABLE
                    Pointer_To_Struct,
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                ],
                syscall_return: Signal_Or_Errno(""),
            },
        ),
        (
            // send a signal and data (siginfo_t struct) to a thread group
            // (an arbitrary thread will receive the signal)
            // requires registering a handler first via sigaction
            Sysno::rt_sigqueueinfo,
            Syscall_Shape {
                types:          &[PID, General_Flag(Signal), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // send a signal and data (info struct) to a specific thread in a thread group
            // requires registering a handler first via sigaction
            Sysno::rt_tgsigqueueinfo,
            Syscall_Shape {
                types:          &[PID, PID, General_Flag(Signal), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::signalfd,
            Syscall_Shape {
                types:          &[
                    // fd of a file, or -1, let the kernel create a new file descriptor
                    File_Descriptor(""),
                    // It is not possible to receive SIGKILL or SIGSTOP
                    // SIGKILL or SIGSTOP can not be blocked
                    Pointer_To_Struct,
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            Sysno::signalfd4,
            Syscall_Shape {
                types:          &[
                    // fd of a file, or -1, let the kernel create a new file descriptor
                    File_Descriptor(""),
                    // It is not possible to receive SIGKILL or SIGSTOP
                    // SIGKILL or SIGSTOP can not be blocked
                    Pointer_To_Struct,
                    General_Flag(SignalFDFlags),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        // The pidfd_open syscall allows users to obtain a file descriptor referring to the PID of
        // the specified process. This syscall is useful in situations where one process
        // needs access to the PID of another process in order to send signals,
        // retrieve information about the process, or similar operations.
        // It can also be used to monitor the lifetime of the process, since the file descriptor is
        // closed when the process terminates.
        (
            Sysno::pidfd_send_signal,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    General_Flag(Signal),
                    // if null, its equivalent to the struct version which is provided a signal is
                    // sent using kill otherwise the buffer is equivalent to
                    // the info buffer specified by the rt_sigqueueinfo syscall
                    Pointer_To_Struct,
                    // reserved for future use, currently should be 0
                    General_Flag(ReservedForFutureUse),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // always successful
            Sysno::gettid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_Numeric },
        ),
        // This is often used by routines that generate unique temporary filenames.
        (
            // always successful
            Sysno::getpid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_Numeric },
        ),
        (
            // always successful
            Sysno::getppid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_Numeric },
        ),
        // These bytes can be used to seed user-space random number generators or for cryptographic
        // purposes.
        (
            Sysno::getrandom,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                    General_Flag(GetRandomFlags),
                ],
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            Sysno::setrlimit,
            Syscall_Shape {
                types:          &[General_Flag(ResourceFlags), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::getrlimit,
            Syscall_Shape {
                types:          &[General_Flag(ResourceFlags), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // basically both, setrlimit and getrlimit in one syscall
            // NULL when you dont want either
            Sysno::prlimit64,
            Syscall_Shape {
                types:          &[
                    // if zero then operate on the calling process
                    PID,
                    General_Flag(ResourceFlags),
                    // NULLABLE
                    Pointer_To_Struct,
                    // NULLABLE
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            /* user CPU time used */
            /* system CPU time used */
            /* maximum resident set size */
            /* integral shared memory size */
            /* integral unshared data size */
            /* integral unshared stack size */
            /* page reclaims (soft page faults) */
            /* page faults (hard page faults) */
            /* swaps */
            /* block input operations */
            /* block output operations */
            /* IPC messages sent */
            /* IPC messages received */
            /* signals received */
            /* voluntary context switches */
            /* involuntary context switches */
            Sysno::getrusage,
            Syscall_Shape {
                types: &[General_Flag(RusageWhoFlags), Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::sysinfo,
            Syscall_Shape {
                types:          &[Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::times,
            Syscall_Shape {
                types:          &[Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::sched_setaffinity,
            Syscall_Shape {
                types:          &[
                    // if zero then the calling thread is the thread referred to
                    PID,
                    Length_Of_Bytes_Specific,
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::sched_getaffinity,
            Syscall_Shape {
                types:          &[
                    // if zero then the calling thread is the thread referred to
                    PID,
                    Length_Of_Bytes_Specific,
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // Any open file descriptors belonging to the process are closed.
            // Any children of the process are inherited by init(1)
            // (or  by the nearest "subreaper" process as defined prctl(2) PR_SET_CHILD_SUBREAPER
            // operation). The process's parent is sent a SIGCHLD signal.
            Sysno::exit,
            Syscall_Shape { types: &[Numeric], syscall_return: Never_Returns },
        ),
        (Sysno::exit_group, Syscall_Shape { types: &[Numeric], syscall_return: Never_Returns }),
        (
            // send a signal to a process
            Sysno::kill,
            Syscall_Shape {
                types:          &[
                    // tgid specified as -1 makes the syscall equivalent to tkill()
                    PID, Numeric,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // send a signal to a specific thread in a specific thread group
            Sysno::tgkill,
            Syscall_Shape {
                types:          &[
                    // tgid specified as -1 makes the syscall equivalent to tkill()
                    PID,
                    PID,
                    General_Flag(Signal),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // a version of tgkill that doesnt specify the thread group
            // in rare situations this results in the signal being sent to a wrong thread (true
            // thread dies, and false thread recycles the same tid)
            Sysno::tkill,
            Syscall_Shape {
                types:          &[PID, General_Flag(Signal)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // pause the process until its interrupted by a signal that either triggers a signal
            // handler or triggers a process termination
            Sysno::pause,
            Syscall_Shape {
                types:          &[],
                // returns if the signal triggers a handler and the handler returns, in this case:
                // returns -1, and errno is set to EINTR does not return if the
                // signal causes termination
                syscall_return: Always_Errors,
            },
        ),
        (
            // pause the process until its interrupted by a signal that either triggers a signal
            // handler or triggers a process termination
            Sysno::ptrace,
            Syscall_Shape {
                types:          &[
                    // OP
                    General_Flag(PtraceOperation),
                    // PID
                    PID,
                    // ADDR
                    Pointer_To_Struct,
                    // DATA
                    Pointer_To_Struct,
                ],
                // On success
                // the PTRACE_PEEK* operations return the requested data (one word)
                // the PTRACE_SECCOMP_GET_FILTER operation returns the number of instructions in
                // the BPF program the PTRACE_GET_SYSCALL_INFO operation returns
                // the number of bytes available to be written by the kernel
                // and other operations return zero
                //
                //
                // Since the value returned by a successful PTRACE_PEEK* operation may be -1
                // the  caller  must  clear errno  before  the call
                // and then check afterwards
                syscall_return: Ptrace_Diverse_Or_Errno,
            },
        ),
        (
            Sysno::rseq,
            Syscall_Shape {
                types:          &[
                    // Only one rseq can be registered per thread,
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                    // 0 for registration, and RSEQ FLAG UNREGISTER for unregistration
                    General_Flag(RSeqFlag),
                    // Each supported architecture provides a RSEQ_SIG macro in sys/rseq.h
                    // which contains a signature. That signature is expected to be present in the
                    // code before each restartable sequences abort handler.
                    // Failure to provide the expected signature may terminate the process
                    // with a segmentation fault.
                    Unsigned_Numeric,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::uname,
            Syscall_Shape {
                types:          &[Pointer_To_Struct],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // always successful
            Sysno::getuid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_User_Group },
        ),
        (
            // always successful
            Sysno::geteuid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_User_Group },
        ),
        (
            // always successful
            Sysno::getgid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_User_Group },
        ),
        (
            // always successful
            Sysno::getegid,
            Syscall_Shape { types: &[], syscall_return: Always_Successful_User_Group },
        ),
        // (
        //     // If the calling process is privileged (the process has the CAP_SETUID capability),
        //     // then the real UID and saved set-user-ID are also set.
        //     Sysno::setuid,
        //     Syscall_Shape {
        //         types: &[User_Group],
        //         // The user ID specified in uid is not valid in this user namespace.
        //         syscall_return: Numeric_Or_Errno,
        //     }, // The  user  is  not  privileged (does not have the CAP_SETUID capability)
        //        // and uid does not match the real UID or saved set-user-ID of the calling
        // process. ),
        // (
        //     Sysno::setgid,
        //     Syscall_Shape {
        //         types: &[User_Group],
        //         // The calling process is not privileged (does not have the CAP_SETGID),
        //         syscall_return: Numeric_Or_Errno,
        //     }, // and gid does not match the real group ID or saved set-group-ID of the calling
        // process. ),
        (
            // Before the introduction of futexes, system calls were required for locking and
            // unlocking shared resources (for example semop).
            Sysno::futex,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Unsigned_Numeric,
                    General_Flag(FutexOpFlags),
                    Unsigned_Numeric,
                    Pointer_To_Struct,
                    Pointer_To_Unsigned_Numeric,
                    Unsigned_Numeric,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // always successful
            // When set_child_tid is set, the very first thing the new thread does is to write its
            // thread ID at this address.

            // When a thread whose clear_child_tid is not NULL terminates, then,
            // if the thread is sharing memory with other threads, then 0 is written at the address
            // specified in clear_child_tid and the kernel performs the following
            // operation: futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
            // The effect of this operation is to wake a single thread that is performing a futex
            // wait on the memory location. Errors from the futex wake operation are
            // ignored.
            Sysno::set_tid_address,
            Syscall_Shape {
                types:          &[Pointer_To_Numeric(None)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::eventfd,
            Syscall_Shape {
                types:          &[Unsigned_Numeric],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            Sysno::eventfd2,
            Syscall_Shape {
                types:          &[Unsigned_Numeric, General_Flag(EventfdFlag)],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            Sysno::wait4,
            Syscall_Shape {
                types:          &[
                    // < -1  wait for any child process whose process group ID is equal to the
                    // absolute value of pid. -1    wait for any child process.
                    // 0     wait for any child process whose process group ID is equal to that of
                    // the calling process at the time of the call to waitpid().
                    // > 0   wait for the child whose process ID is equal to the value of pid.
                    User_Group,
                    // If wstatus is not NULL, wait4() stores status information in the int to
                    // which it points. This integer can be inspected with the
                    // following macros (which take the integer itself as an
                    // argument, not a pointer to it (as is done in syscall))
                    Pointer_To_Numeric(None),
                    General_Flag(WaitEventFlags),
                    // NULLABLE means do not want
                    // resource usage information about the child
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::waitid,
            Syscall_Shape {
                types:          &[
                    General_Flag(WaitIdTypeFlags),
                    User_Group,
                    Pointer_To_Struct,
                    General_Flag(WaitEventFlags),
                    // NULLABLE means do not want
                    // resource usage information about  the
                    // child, in the same manner as wait4(2).
                    Pointer_To_Struct,
                ],
                // returns 0 on success or if WNOHANG was specified and no child(ren) specified by
                // id has yet changed state
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::eventfd2,
        // ),
        (
            // in linux every thread can have a list of "robust futexes"
            // threads in programs use this list as a contingency plan in the case that they die
            // unexpectedly given that they are in user-space, the kernel can't do
            // anything in case a thread dies while holding the lock, in that case the
            // only way for waiting threads to be stopped is by rebooting! to fix this,
            // in linux, whever a thread exits (any thread) the kernel checks if it has a robust
            // futex list if it does, then the kernel walks the list of futexes
            // and for every futex it cleans up and wakes any other waiter
            Sysno::set_robust_list,
            Syscall_Shape { types: &[Address, Numeric], syscall_return: Numeric_Or_Errno },
        ),
        (
            // in linux every thread can have a list of "robust futexes"
            // threads in programs use this list as a contingency plan in the case that they die
            // unexpectedly given that they are in user-space, the kernel can't do
            // anything in case a thread dies while holding the lock, in that case the
            // only way for waiting threads to be stopped is by rebooting! to fix this,
            // in linux, whever a thread exits (any thread) the kernel checks if it has a robust
            // futex list if it does, then the kernel walks the list of futexes
            // and for every futex it cleans up and wakes any other waiter
            Sysno::get_robust_list,
            Syscall_Shape {
                types:          &[User_Group, Address, Pointer_To_Numeric(None)],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::setpgid,
            Syscall_Shape {
                types:          &[User_Group, User_Group],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (Sysno::getpgid, Syscall_Shape { types: &[User_Group], syscall_return: Numeric_Or_Errno }),
        (Sysno::getpgrp, Syscall_Shape { types: &[], syscall_return: Numeric_Or_Errno }),
        (
            // run in separate memory spaces.
            // At the time of fork() both memory spaces have the  same  content.
            // Memory  writes,  file  mappings, unmappings, performed by one of the processes do
            // not affect the other.

            // The child process is an exact duplicate of the parent process except for the
            // following points:

            // •  The child has its own unique process ID,

            // •  The child's and parent have the same parent process ID

            // •  The child does not inherit memory locks (mlock(2), mlockall(2)).

            // •  Process resource utilizations (getrusage(2)) and CPU time counters (times(2)) are
            // reset to zero in the child.

            // •  The child's set of pending signals is initially empty (sigpending(2)).

            // •  The child does not inherit semaphore adjustments from its parent (semop(2)).

            // •  The  child  does  not  inherit  process-associated record locks from its parent
            // (fcntl(2)).  (On the other hand, it does inherit fcntl(2) open file description
            // locks and    flock(2) locks from its parent.)

            // •  The child does not inherit timers from its parent (setitimer(2), alarm(2),
            // timer_create(2)).

            // •  The child does not inherit outstanding (unresolved) asynchronous I/O operations
            // from its parent (aio_read(3), aio_write(3), nor does it inherit any asynchronous
            // I/O  contexts  from    its parent (see io_setup(2)).

            // The  process  attributes  in the preceding list are all specified in POSIX.1.  The
            // parent and child also differ with respect to the following Linux-specific process
            // attributes:

            // •  The child does not inherit directory change notifications (dnotify) from its
            // parent

            // •  The prctl(2) PR_SET_PDEATHSIG setting is reset so that the child does not receive
            // a signal when its parent terminates.

            // •  The default timer slack value is set to the parent's current timer slack value.

            // •  madvise(2)  MADV_DONTFORK marked Memory mappings flag are not inherited

            // •  madvise(2)  MADV_WIPEONFORK marked Memory mappings are wiped

            // •  The termination signal of the child is always SIGCHLD (see cl&2)).

            // •  The port access permission bits set by ioperm(2) are not inherited by the child;
            // the child must turn on any bits that it requires using ioperm(2).

            // Note the following further points:

            // •  The  child  process is created with a single thread—the one that called fork().
            // The entire virtual address space of the parent is replicated in the child, including
            // the    states of mutexes, condition variables, and other pthreads
            // objects; the use of pthread_atfork(3) may be helpful for dealing with problems that
            // this can cause.

            // •  After a fork() in a multithreaded program, the child can safely call only
            // async-signal-safe functions (see signal-safety(7)) until such time as it calls
            // execve(2).

            // •  The child inherits copies of the parent's set of open file descriptors.  Each
            // file descriptor in the child refers to the same open file description (see open(2))
            // as  the    corresponding  file  descriptor in the parent.  This means
            // that the two file descriptors share open file status flags, file offset, and
            // signal-driven I/O attributes (see    the description of F_SETOWN and
            // F_SETSIG in fcntl(2)).

            // •  The child inherits copies of the parent's set of open message queue descriptors
            // (see mq_overview(7)).  Each file descriptor in the child refers to the same open
            // message    queue description as the corresponding file descriptor in the
            // parent.  This means that the two file descriptors share the same flags (mq_flags).

            // •  The  child inherits copies of the parent's set of open directory streams (see
            // opendir(3)).  POSIX.1 says that the corresponding directory streams in the parent
            // and child    may share the directory stream positioning; on Linux/glibc
            // they do not.
            Sysno::fork,
            Syscall_Shape { types: &[], syscall_return: Numeric_Or_Errno },
        ),
        (
            // 1- simpler version of the fork() system call.
            //      This is because executing the fork() system call,
            //      (before the copy-on-write mechanism was created)
            //      involved copying everything from the parent process, including address space,
            //      which was very inefficient.
            //
            // 2- the calling thread is suspended until the child terminates or makes a call to
            // execve      This is because both processes use the same address space,
            //      which contains the stack, stack pointer, and instruction pointer.
            Sysno::vfork,
            Syscall_Shape { types: &[], syscall_return: Numeric_Or_Errno },
        ),
        (
            Sysno::clone3,
            Syscall_Shape {
                types:          &[Pointer_To_Struct, Unsigned_Numeric],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::clone,
            Syscall_Shape {
                types:          &[
                    General_Flag(CloneFlags),
                    Address,
                    Pointer_To_Numeric(None),
                    Pointer_To_Numeric(None),
                    Unsigned_Numeric,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::setsid,
        // ),
        // (
        //     Sysno::setreuid,
        // ),
        // (
        //     Sysno::setregid,
        // ),
        // (
        //     Sysno::getgroups,
        // ),
        // (
        //     Sysno::setgroups,
        // ),
        // (
        //     Sysno::setresuid,
        // ),
        // (
        //     Sysno::getresuid,
        // ),
        // (
        //     Sysno::setresgid,
        // ),
        // (
        //     Sysno::getresgid,
        // ),
        // (
        //     Sysno::setfsuid,
        // ),
        // (
        //     Sysno::setfsgid,
        // ),
        // (
        //     Sysno::getsid,
        // ),
        // (
        //     Sysno::unshare,
        // ),
        (
            Sysno::nanosleep,
            Syscall_Shape {
                types:          &[
                    // The value of the nanoseconds field must be in the range [0, 999999999].
                    Pointer_To_Struct,
                    // NULLABLE means do not want
                    Pointer_To_Struct,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::execve,
            Syscall_Shape {
                types:          &[
                    Pointer_To_Text(""),
                    // the first of these strings should be the filename of the file being executed
                    // terminated by a null pointer
                    Array_Of_Strings(&[]),
                    // terminated by a null pointer
                    Array_Of_Strings(&[]),
                ],
                // does not return on success
                syscall_return: Numeric_Or_Errno,
            },
        ),
        // (
        //     Sysno::execveat,
        // ),
        // (
        //     Sysno::shmget,
        // ),
        // (
        //     Sysno::shmat,
        // ),
        // (
        //     Sysno::shmctl,
        // ),
        // (
        //     Sysno::getitimer,
        // ),
        // (
        //     Sysno::alarm,
        // ),
        // (
        //     Sysno::setitimer,
        // ),
        // (
        //     Sysno::remap_file_pages,
        // ),
        // (
        //     Sysno::mq_timedsend,
        // ),
        // (
        //     Sysno::sendmmsg,
        // ),
        // (
        //     Sysno::recvmmsg,
        // ),
        // (
        //     Sysno::reboot,
        // ),
        // (
        //     Sysno::sethostname,
        // ),
        // (
        //     Sysno::setdomainname,
        // ),
        // (
        //     Sysno::iopl,
        // )

        // (
        //     Sysno::seccomp,
        // )

        // (
        //     Sysno::bpf,
        // )

        // (
        //     Sysno::semget,
        // )

        // (
        //     Sysno::semop,
        // )

        // (
        //     Sysno::semctl,
        // )

        // (
        //     Sysno::shmdt,
        // )

        // (
        //     Sysno::msgget,
        // )

        // (
        //     Sysno::msgsnd,
        // )

        // (
        //     Sysno::msgrcv,
        // )

        // (
        //     Sysno::msgctl,
        // )

        // (
        //     Sysno::flock,
        // )

        // (
        //     Sysno::gettimeofday,
        // )

        // (
        //     Sysno::ptrace,
        // )

        // (
        //     Sysno::syslog,
        // )
        (
            // landlocking is mostly a situation where a piece of software
            // is protecting the user from the software itself, in the case that it is exploited
            // think kubernetes/docker protecting you in case they were compromised
            // for now its only file system related
            //
            // landlock is an access control system available to non-priviliged processes
            // using these 3 linux syscalls
            // it enables built-in sandboxing
            //
            // landlock is security sandboxing
            // namespaces/containers are not considered security sandboxes
            // they are resources "virtualization" tools
            Sysno::landlock_create_ruleset,
            Syscall_Shape {
                types:          &[
                    // these actions will by default be forbidden if no future rules explicitly
                    // allows them Nullable
                    Pointer_To_Struct,
                    Length_Of_Bytes_Specific,
                    // flags must be 0 if attr is used.
                    // for now only: LANDLOCK_CREATE_RULESET_VERSION flag available
                    //      If attr is NULL and size is 0, then the returned value is the highest
                    // supported Landlock ABI version
                    General_Flag(LandlockCreateFlag),
                ],
                syscall_return: File_Descriptor_Or_Errno(""),
            },
        ),
        (
            Sysno::landlock_add_rule,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    // currently only LANDLOCK_RULE_PATH_BENEATH : bla is file hierarchy.
                    General_Flag(LandlockRuleTypeFlag),
                    Pointer_To_Struct,
                    // must be 0
                    General_Flag(LandlockAddRuleFlag),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::landlock_restrict_self,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    // must be 0
                    General_Flag(LandlockRestrictFlag),
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // A sparse file is a file that is mostly empty,
            // i.e. it contains large blocks of bytes whose value is 0 (zero).
            // On the disk, the content of a file is stored in blocks of fixed size (usually 4 KiB
            // or more).
            //
            // When all the bytes contained in such a block are 0,
            // a file system that supports sparse files will not store the block on disk,
            // instead it keeps the information somewhere in the file meta-data.
            //
            // offset and len must be a multiple of the filesystem logical block size,
            Sysno::fallocate,
            Syscall_Shape {
                types:          &[
                    File_Descriptor(""),
                    General_Flag(FallocFlags),
                    Length_Of_Bytes_Specific,
                    Length_Of_Bytes,
                ],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            // this is what runs behind the nice command
            Sysno::getpriority,
            Syscall_Shape {
                types:          &[General_Flag(PriorityWhich), Numeric],
                syscall_return: Priority_Or_Errno(MaybeUninit::<bool>::zeroed()),
            },
        ),
        (
            // this is what runs behind the nice command
            Sysno::setpriority,
            Syscall_Shape {
                types:          &[General_Flag(PriorityWhich), Numeric, Unsigned_Numeric],
                syscall_return: Numeric_Or_Errno,
            },
        ),
        (
            Sysno::getdents,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Pointer_To_Struct, Unsigned_Numeric],
                // On end of directory, 0 is returned.
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        (
            // handle large filesystems and large file offsets.
            Sysno::getdents64,
            Syscall_Shape {
                types:          &[File_Descriptor(""), Pointer_To_Struct, Unsigned_Numeric],
                // On end of directory, 0 is returned.
                syscall_return: Length_Of_Bytes_Specific_Or_Errno,
            },
        ),
        //         (
        //         Sysno::umask,
        //         )

        //         (
        //         Sysno::mknod,
        //         )

        //         (
        //         Sysno::mknodat,
        //         )

        //         (
        //         Sysno::getdents,
        //         )

        //         (
        //         Sysno::getdents64,
        //         )

        //         (
        //         Sysno::capget,
        //         )

        //         (
        //         Sysno::capset,
        //         )

        //         (
        //         Sysno::utime,
        //         )

        //         (
        //         Sysno::personality,
        //         )

        //         (
        //         Sysno::sysfs,
        //         )

        //         (
        //         Sysno::sched_setparam,
        //         )

        //         (
        //         Sysno::sched_getparam,
        //         )

        //         (
        //         Sysno::sched_setscheduler,
        //         )

        //         (
        //         Sysno::sched_get_priority_max,
        //         )

        //         (
        //         Sysno::sched_get_priority_min,
        //         )

        //         (
        //         Sysno::sched_rr_get_interval,
        //         )

        //         (
        //         Sysno::modify_ldt,
        //         )

        //         (
        //         Sysno::adjtimex,
        //         )

        //         (
        //         Sysno::settimeofday,
        //         )

        //         (
        //         Sysno::ioperm,
        //         )

        //         (
        //         Sysno::init_module,
        //         )

        //         (
        //         Sysno::delete_module,
        //         )

        //         (
        //         Sysno::quotactl,
        //         )

        //         (
        //         Sysno::readahead,
        //         )

        //         (
        //         Sysno::setxattr,
        //         )

        //         (
        //         Sysno::lsetxattr,
        //         )

        //         (
        //         Sysno::fsetxattr,
        //         )

        //         (
        //         Sysno::getxattr,
        //         )

        //         (
        //         Sysno::lgetxattr,
        //         )

        //         (
        //         Sysno::fgetxattr,
        //         )

        //         (
        //         Sysno::listxattr,
        //         )

        //         (
        //         Sysno::llistxattr,
        //         )

        //         (
        //         Sysno::flistxattr,
        //         )

        //         (
        //         Sysno::removexattr,
        //         )

        //         (
        //         Sysno::lremovexattr,
        //         )

        //         (
        //         Sysno::fremovexattr,
        //         )

        //         (
        //         Sysno::time,
        //         )

        //         (
        //         Sysno::sched_setaffinity,
        //         )

        //         (
        //         Sysno::sched_getaffinity,
        //         )

        //         (
        //         Sysno::io_setup,
        //         )

        //         (
        //         Sysno::io_getevents,
        //         )

        //         (
        //         Sysno::io_submit,
        //         )

        //         (
        //         Sysno::copy_file_range,
        //         )

        //         (
        //         Sysno::io_cancel,
        //         )

        //         (
        //         Sysno::splice,
        //         )

        //         (
        //         Sysno::vmsplice,
        //         )

        //         (
        //         Sysno::semtimedop,
        //         )

        //         (
        //         Sysno::fadvise64,
        //         )

        //         (
        //         Sysno::timer_create,
        //         )

        //         (
        //         Sysno::timer_settime,
        //         )

        //         (
        //         Sysno::timer_gettime,
        //         )

        //         (
        //         Sysno::timer_getoverrun,
        //         )

        //         (
        //         Sysno::timer_delete,
        //         )

        //         (
        //         Sysno::clock_settime,
        //         )

        //         (
        //         Sysno::clock_gettime,
        //         )

        //         (
        //         Sysno::clock_getres,
        //         )

        //         (
        //         Sysno::clock_nanosleep,
        //         )

        //         (
        //         Sysno::utimes,
        //         )

        //         (
        //         Sysno::mbind,
        //         )

        //         (
        //         Sysno::set_mempolicy,
        //         )

        //         (
        //         Sysno::get_mempolicy,
        //         )

        //         (
        //         Sysno::mq_open,
        //         )

        //         (
        //         Sysno::mq_timedreceive,
        //         )

        //         (
        //         Sysno::mq_notify,
        //         )

        //         (
        //         Sysno::mq_getsetattr,
        //         )

        //         (
        //         Sysno::kexec_load,
        //         )

        //         (
        //         Sysno::add_key,
        //         )

        //         (
        //         Sysno::request_key,
        //         )

        //         (
        //         Sysno::keyctl,
        //         )

        //         (
        //         Sysno::ioprio_set,
        //         )

        //         (
        //         Sysno::ioprio_get,
        //         )

        //         (
        //         Sysno::inotify_add_watch,
        //         )

        //         (
        //         Sysno::inotify_rm_watch,
        //         )

        //         (
        //         Sysno::migrate_pages,
        //         )

        //         (
        //         Sysno::futimesat,
        //         )

        //         (
        //         Sysno::tee,
        //         )

        //         (
        //         Sysno::sync_file_range,
        //         )

        //         (
        //         Sysno::move_pages,
        //         )

        //         (
        //         Sysno::utimensat,
        //         )

        //         (
        //         Sysno::timerfd_create,
        //         )

        //         (
        //         Sysno::timerfd_settime,
        //         )

        //         (
        //         Sysno::timerfd_gettime,
        //         )

        //         (
        //         Sysno::perf_event_open,
        //         )

        //         (
        //         Sysno::fanotify_init,
        //         )

        //         (
        //         Sysno::fanotify_mark,
        //         )

        //         (
        //         Sysno::name_to_handle_at,
        //         )

        //         (
        //         Sysno::open_by_handle_at,
        //         )

        //         (
        //         Sysno::clock_adjtime,
        //         )

        //         (
        //         Sysno::getcpu,
        //         )

        //         (
        //         Sysno::process_vm_readv,
        //         )

        //         (
        //         Sysno::process_vm_writev,
        //         )

        //         (
        //         Sysno::kcmp,
        //         )

        //         (
        //         Sysno::finit_module,
        //         )

        //         (
        //         Sysno::sched_setattr,
        //         )

        //         (
        //         Sysno::sched_getattr,
        //         )

        //         (
        //         Sysno::memfd_create,
        //         )

        //         (
        //         Sysno::kexec_file_load,
        //         )

        //         (
        //         Sysno::membarrier,
        //         )

        //         (
        //         Sysno::pkey_mprotect,
        //         )

        //         (
        //         Sysno::faccessat2,
        //         )

        //         (
        //         Sysno::pkey_alloc,
        //         )

        //         (
        //         Sysno::io_pgetevents,
        //         )

        //         (
        //         Sysno::io_uring_setup,
        //         )

        //         (
        //         Sysno::io_uring_enter,
        //         )

        //         (
        //         Sysno::io_uring_register,
        //         )

        //         (
        //         Sysno::open_tree,
        //         )

        //         (
        //         Sysno::move_mount,
        //         )

        //         (
        //         Sysno::fsopen,
        //         )

        //         (
        //         Sysno::fsconfig,
        //         )

        //         (
        //         Sysno::fsmount,
        //         )

        //         (
        //         Sysno::fspick,
        //         )

        //         (
        //         Sysno::pidfd_open,
        //         )

        //         (
        //         Sysno::close_range,
        //         )

        //         (
        //         Sysno::pidfd_getfd,
        //         )

        //         (
        //         Sysno::process_madvise,
        //         )

        //         (
        //         Sysno::mount_setattr,
        //         )

        //         (
        //         Sysno::quotactl_fd,
        //         )

        //         (
        //         Sysno::memfd_secret,
        //         )

        //         (
        //         Sysno::process_mrelease,
        //         )

        //         (
        //         Sysno::futex_waitv,
        //         )

        //         (
        //         Sysno::set_mempolicy_home_node,
        //         )

        //         (
        //         Sysno::map_shadow_stack,
        //         )

        //         (
        //         Sysno::futex_wake,
        //         )

        //         (
        //         Sysno::futex_wait,
        //         )

        //         (
        //         Sysno::futex_requeue,
        //         )

        //         (
        //         Sysno::listmount,
        //         )

        //         (
        //         Sysno::lsm_get_self_attr,
        //         )

        //         (
        //         Sysno::lsm_set_self_attr,
        //         )

        //         (
        //         Sysno::lsm_list_modules,
        //         )
        // (
        //     Sysno::sched_getscheduler
        // )

        // (
        //     Sysno::vhangup
        // )

        // (
        //     Sysno::acct
        // )

        // (
        //     Sysno::io_destroy
        // )

        // (
        //     Sysno::restart_syscall
        // )

        // (
        //     Sysno::mq_unlink
        // )

        // (
        //     Sysno::inotify_init
        // )

        // (
        //     Sysno::inotify_init1
        // )

        // (
        //     Sysno::setns
        // )

        // (
        //     Sysno::userfaultfd
        // )

        // (
        //     Sysno::pkey_free
        // )
    ];

    array.into_iter().collect()
}
