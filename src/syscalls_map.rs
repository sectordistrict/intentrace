use std::collections::HashMap;
use syscalls::Sysno;
use std::mem::MaybeUninit;
use crate::types::{ArgContainer, SysArg, Category, Flag, SysDetails, SysReturn};

// TODO! differentiate between bitflags (orables) and enums
// TODO! add granularity for value-return type of syscall arguments
// these are semantics for syscall arguments that get modified after syscall return
// see if some arguments are better combined, like the very common buffer and buffer lengths (this makes processing cleaner but might result in complexity in non-conforming cases)
// clarify whether a buffer is provided by the user or to be filled by the kernel in the name of the argument (GIVE vs FILL)
// switch to MaybeUninit

pub fn initialize_syscall_map() -> HashMap<Sysno, SysDetails> {
    use ArgContainer::*;
    use SysArg::*;
    use Category::*;
    use Flag::*;
    use SysReturn::*;
    let array: Vec<(Sysno, SysDetails)> = vec![
        // read from a file descriptor
        (
            Sysno::read,
            (
                DiskIO,
                "read",
                &[
                    (["fd", "file descriptor to be read from"], Normal(File_Descriptor(""))),
                    (["buf", "buffer to be read into"], Normal(Pointer_To_Text(""))),
                    (["count", "count of bytes to be read"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "positive number of bytes read, 0 means end of file, -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            ),
        ),
        // write to a file descriptor
        (
            Sysno::write,
            (
                DiskIO,
                "write",
                &[
                    (["fd", "file descriptor"], Normal(File_Descriptor(""))),
                    (["buf", "buffer holding the data to be written"], Normal(Pointer_To_Text(""))),
                    (["count", "amount of bytes to write from the buffer"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "positive number of bytes written, 0 means end of file,  -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        // read from a file descriptor at a given offset
        (
            // Pread() basically works just like read()
            // but comes with its own offset
            // and doesnt modify the file pointer.

            // If you read() twice, you get different results
            // If you pread() twice, you get the same result

            // the system call was renamed in from pread() to pread64(). The syscall numbers remain the same.
            // The glibc pread() and pwrite() wrapper functions transparently deal with the change.
            // parallel read
            // also: stateless read
            Sysno::pread64,
            (
                DiskIO,
                "parallel read, use your own offset to avoid file pointer data race",
                &[
                    (["fd", "file descriptor of the file to be read from"], Normal(File_Descriptor(""))),
                    (["buf", "pointer to a buffer where read data will be stored"], Normal(Pointer_To_Text(""))),
                    (["count", "amount of bytes to be read from the file to the buffer"], Normal(Length_Of_Bytes_Specific)),
                    (["offset", "bytes of offset of where reading must start"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "zero means done eof (done reading), on success returns number of bytes read, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        // write to a file descriptor at a given offset
        (
            // the system call was renamed in from pwrite() to pwrite64(). The syscall numbers remain the same.
            // The glibc pread() and pwrite() wrapper functions transparently deal with the change.
            // parallel write
            // also: stateless write
            Sysno::pwrite64,
            (
                DiskIO,
                "parallel write, use your own offset to avoid file pointer data race",
                &[
                    (["fd", "file descriptor of the file to be written into"], Normal(File_Descriptor(""))),
                    (["buf", "pointer to data which will be written to the file"], Normal(Pointer_To_Text(""))),
                    (["count", "amount of bytes to be written into the file from the buffer"], Normal(Length_Of_Bytes_Specific)),
                    (["offset", "bytes of offset of where writing must start"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "zero means nothing was written (done writing), on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            // The readv() function behave the same as read( ), except that multiple buffers are read to.
            // this is used when memory to read from is scattered around (not contiguous)
            // this avoids multiple read syscalls that would otherwise be needed 
            // 
            // readv: read vectored
            // you use it when you know that you have multiple fixed size blocks of data
            // to read into non-contiguous memory locations
            Sysno::readv,
            (
                DiskIO,
                "scatter read, read vectored, read from several non contiguous regions",
                &[
                    (["fd", "file descriptor of the file to be read from"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "on success returns number of bytes read, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),

        (
            // same as readv
            Sysno::writev,
            (
                DiskIO,
                "gather write, write vectored, write from several non contiguous regions",
                &[
                    (["fd", "file descriptor of the file to be written into"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                ],
                // zero means what in here? man pages dont say anything
                (["return value", "on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            // parallel read vectored
            Sysno::preadv,
            (
                DiskIO,
                "scatter read, read vectored, read from several non contiguous regions using your own offset to avoid file pointer data race",
                &[
                    (["fd", "file descriptor of the file to be read from"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                    (["offset", "amount of bytes of offset from the beginning of the file"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            // parallel write vectored
            Sysno::pwritev,
            (
                DiskIO,
                "gather write, write vectored from several non contiguous regions using your own offset to avoid file pointer data race",
                &[
                    (["fd", "file descriptor of the file to be written into"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                    (["offset", "amount of bytes of offset from the beginning of the file"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),

        (
            Sysno::preadv2,
            (
                DiskIO,
                "scatter read, read vectored, read from several non contiguous regions using your own offset to avoid file pointer data race in addition to customized flags",
                &[
                    (["fd", "file descriptor of the file to be read from"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                    (["offset", "amount of bytes of offset from the beginning of the file"], Normal(Length_Of_Bytes_Specific)),
                    (["flags", "custom falgs for specific write behaviour"], Normal(General_Flag(P_RW_V2_Flags))),
                ],
                (["return value", "on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),

        (
            Sysno::pwritev2,
            (
                DiskIO,
                "gather write, write vectored from several non contiguous regions using your own offset to avoid file pointer data race in addition to customized flags",
                &[
                    (["fd", "file descriptor of the file to be written into"], Normal(File_Descriptor(""))),
                    (["iovec", "array of iovec structs containing pointer-length pairs of scattered regions to be written"], Normal(Array_Of_Struct)),
                    (["count", "number of iovec structs in the iovec array"], Normal(Unsigned_Numeric)),
                    (["offset", "amount of bytes of offset from the beginning of the file"], Normal(Length_Of_Bytes_Specific)),
                    (["flags", "custom falgs for specific write behaviour"], Normal(General_Flag(P_RW_V2_Flags))),
                ],
                (["return value", "on success returns number of bytes written, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)

            )
        ),
        (
            Sysno::pipe, 
            (
                Process,
                "create a unidirectional pipe for process communication",
                &[
                    (["pipefd", "pointer to array containing the read and write file descriptors"], Normal(Pointer_To_File_Descriptor_Array(["", ""]))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::pipe2, 
            (
                Process,
                "create a unidirectional pipe for process communication, in additiona to flags for file opening behaviour",
                &[
                    (["pipefd", "pointer to array containing the read and write file descriptors"], Normal(Pointer_To_File_Descriptor_Array(["", ""]))),
                    // If flags is 0, then pipe2() is the same as pipe()
                    (["flags", "file opening flags for the pipe file descriptors"], Normal(General_Flag(Open)))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // duplicate a file descriptor
        // creates a copy of the file descriptor oldfd, using the lowest-numbered unused file descriptor for the new descriptor.
        (
            Sysno::dup,
            (
                FileOp,
                "duplicate file descriptor",
                &[
                    (["oldfd", "file descriptor to be copied"], Normal(File_Descriptor(""))),
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // same as dup, but uses newfd for the fd 
        // it overrwrites the newfd if its used
        // If newfd was previously open, it is closed before being reused
        (
            Sysno::dup2,
            (
                FileOp,
                "duplicate file descriptor with another file descriptor",
                &[
                    (["oldfd", "file descriptor to be copied"], Normal(File_Descriptor(""))),
                    (["newfd,", "new file descriptor"], Normal(File_Descriptor("")))
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // same as dup2 but the caller can force the close-on-exec flag to be set for the new file descriptor by specifying O_CLOEXEC in flags. 
        (
            Sysno::dup3,
            (
                FileOp,
                "duplicate file descriptor with another file descriptor with some useful flags",
                &[
                    (["oldfd", "file descriptor to be copied"], Normal(File_Descriptor(""))),
                    (["newfd,", "new file descriptor"], Normal(File_Descriptor(""))),
                    (["flags", "flag for -as of now- O_CLOEXEC only"], Normal(General_Flag(Dup3Flags)))
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::access,
            (
                FileOp,
                "check permissions on a file",
                &[
                    (["pathname", "path of the file to be checked"], Normal(Pointer_To_Text(""))),
                    (["mode", "specific accessibilities to be checked"], Normal(General_Flag(Access)))
                ],
                (["numeric return", "0 on success (all permissions were granted), -1 on error (at least one permission was not granted), errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::faccessat,
            (
                FileOp,
                "check permissions on a file, with an optional anchor directory, and path resolution flags",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file to be checked"], Normal(Pointer_To_Text(""))),
                    (["mode", "specific accessibilities to be checked"], Normal(General_Flag(Access))),
                    (["flags", "path resolution flags"], Normal(General_Flag(FileAtFlags))),
                ],
                (["numeric return", "0 on success (all permissions were granted), -1 on error (at least one permission was not granted), errno modified"], Numeric_Or_Errno)
                )
        ),
        (
            Sysno::faccessat2,
            (
                FileOp,
                "check permissions on a file, with an optional anchor directory, and path resolution flags",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file to be checked"], Normal(Pointer_To_Text(""))),
                    (["mode", "specific accessibilities to be checked"], Normal(General_Flag(Access))),
                    (["flags", "path resolution flags"], Normal(General_Flag(FileAtFlags))),
                ],
                (["numeric return", "0 on success (all permissions were granted), -1 on error (at least one permission was not granted), errno modified"], Numeric_Or_Errno)
                )
        ),

        // open and possibly create a file
        // open handles a relative path by considering it relative to the current process working directory
        // files must be opened first before being read from or written to
        (
            Sysno::open,
            (
                FileOp,
                "open and possibly create a file",
                &[
                    (["filename", "path of the file to be opened"], Normal(Pointer_To_Text(""))),
                    // flags: one of the following modes: O_RDONLY, O_WRONLY, or O_RDWR.
                    // and an optional or of others
                    (["flags", "file opening flags"], Normal(General_Flag(Open))),
                    (["mode", "file permission modes (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "-1 for error, and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // openat handles a relative path by considering it relative to the directory of dirfd
        // if AT_FDCWD is used in dirfd, then it is identical to open
        // if the path is absolute then dirfd is ignored
        (
            Sysno::openat,
            (
                FileOp,
                "open and possibly create a file, use dirfd as anchor",
                &[
                    (["dirfd", "file descriptor of the anchor directory"], Normal(File_Descriptor_openat(""))),
                    (["pathname", "path of the file to be opened"], Normal(Pointer_To_Text(""))),
                    (["flags", "file opening flags"], Normal(General_Flag(Open))),
                    (["mode", "file permission modes (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "-1 for error, and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // an extension of openat(2) and provides a superset of its functionality.
        // operaes with the same logic as openat()
        (
            Sysno::openat2,
            (
                FileOp,
                "open and possibly create a file, use dirfd as anchor, and open_how for further customization",
                &[
                    (["dirfd", "file descriptor of the anchor directory"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file to be opened"], Normal(Pointer_To_Text(""))),
                    (["open_how", "how struct which contains the logic for opening"], Normal(Pointer_To_Struct)),
                    (["size", "size of the how struct in bytes"], Normal(Length_Of_Bytes))
                ],
                (["return value", "-1 for error, and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // calling creat() is equivalent to calling open() with flags equal to O_CREAT|O_WRONLY|O_TRUNC
        (
            Sysno::creat,
            (
                FileOp,
                    "create a file",
                &[
                    (["pathname", "path of the file to be opened"], Normal(Pointer_To_Text(""))),
                    (["mode", "file permission modes (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "-1 for error, and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::getcwd,
            (
                FileOp,
                "get current working directory",
                &[
                    (["buf", "buffer to fill with the absolute path of the current working directory"], Normal(Pointer_To_Text(""))),
                    (["size", "size of the absolute path buffer"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "pointer to path of the current working directory, null on error, and errno modified"], Address_Or_Errno_getcwd(""))
            )
        ),
        (
            Sysno::chdir,
            (
                FileOp,
                "change to a new directory using a specific path",
                &[
                    (["pathname", "the new path we're switching to"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fchdir,
            (
                FileOp,
                "change to a new directory using a file desciptor",
                &[
                    (["fd", "file descriptor of the path we're switching to"], Normal(File_Descriptor(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rename,
            (
                FileOp,
                "rename a file and possibly move it",
                &[
                    (["oldpath", "old path of the file"], Normal(Pointer_To_Text(""))),
                    (["newpath", "new path of the file"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::renameat,
            (
                FileOp,
                "rename a file and possibly move it, with an optional anchor directory",
                &[
                    (["olddirfd", "file descriptor of a path to use as anchor if oldpath is relative"], Normal(File_Descriptor(""))),
                    (["oldpath", "old path of the file"], Normal(Pointer_To_Text(""))),

                    (["newdirfd", "file descriptor of a path to use as anchor if newpath is relative"], Normal(File_Descriptor(""))),
                    (["newpath", "new path of the file"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::renameat2,
            (
                FileOp,
                "rename a file and possibly move it, with an optional anchor directory and flags for custom behaviour",
                &[
                    (["olddirfd", "file descriptor of a path to use as anchor if oldpath is relative"], Normal(File_Descriptor(""))),
                    (["oldpath", "old path of the file"], Normal(Pointer_To_Text(""))),

                    (["newdirfd", "file descriptor of a path to use as anchor if newpath is relative"], Normal(File_Descriptor(""))),
                    (["newpath", "new path of the file"], Normal(Pointer_To_Text(""))),
                    (["flags", "renaming and replacement behaviour falgs"], Normal(General_Flag(FileRenameFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::mkdir,
            (
                FileOp,
                "create a new directory using a path",
                &[
                    (["pathname", "path of the new directory to create"], Normal(Pointer_To_Text(""))),
                    (["mode", "directory permission (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::mkdirat,
            (
                FileOp,
                "create a new directory using a path and an optional anchor directory",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the new directory to create"], Normal(Pointer_To_Text(""))),
                    (["mode", "directory permissions (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rmdir,
            (
                FileOp,
                "delete a specific directory",
                &[
                    (["pathname", "path of the directory to remove"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::link,
            (
                // after hard linking it is impossible to tell which file was the original
                // because they both point to the same inode now
                //
                // The link() system call can be used to detect and trace malicious or suspicious file modification.
                // For example, if a malicious user is trying to modify or delete files in a system,
                // creating/deleting a hard link to the file is one way to do this.
                // Tracking the link() system call will notify if any files are modified in this way.
                FileOp,
                "create a hard link for a file",
                &[
                    (["oldpath", "existing file we will link to"], Normal(Pointer_To_Text(""))),
                    // if existing, will not be overwritten
                    (["newpath", "path for the new file which will be linked"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::linkat,
            (
                FileOp,
                "create a hard link for a file, with an optional anchor directory, and path resolution flags",
                &[
                    (["olddirfd", "file descriptor of a path to use as anchor if oldpath is relative"], Normal(File_Descriptor(""))),
                    (["oldpath", "existing file we will link to"], Normal(Pointer_To_Text(""))),
                    (["newdirfd", "file descriptor of a path to use as anchor if newpath is relative"], Normal(File_Descriptor(""))),
                    // if existing, will not be overwritten
                    (["newpath", "path for the new file which will be linked"], Normal(Pointer_To_Text(""))),
                    (["flags", "path resolution flags"], Normal(General_Flag(FileAtFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::unlink,
            (
                // Each inode on your FileOp has a reference count - it knows how many places refer to it. A directory entry is a reference. Multiple references to the same inode can exist. unlink removes a reference. When the reference count is zero, then the inode is no longer in use and may be deleted. This is how many things work, such as hard linking and snap shots.
                // In particular - an open file handle is a reference. So you can open a file, unlink it, and continue to use it - it'll only be actually removed after the file handle is closed (provided the reference count drops to zero, and it's not open/hard linked anywhere else).
                FileOp,
                "either deletes a file or directory, or in the case that other references still exist, simply reduces the reference count of the inode",
                &[
                    (["pathname", "path of the file or directory to be removed"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::unlinkat,
            (
                FileOp,
                "either deletes a file or directory, or in the case that other references still exist, simply reduces the reference count of the inode, in addtion to an optional anchor directory, and a behaviour customization flag",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file or directory to be removed"], Normal(Pointer_To_Text(""))),
                    (["flags", "flag specifying similar behaviour to rmdir or not"], Normal(General_Flag(FileAtFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // A symbolic link (also known as a soft link) may becomoe dangling
            // (point to a nonexistent file);
            Sysno::symlink,
            (
                FileOp,
                "create a symbolic link with the given name linked to the given target",
                &[
                    (["target", "path of the target file to be linked"], Normal(Pointer_To_Text(""))),
                    // If linkpath exists, it will not be overwritten.
                    (["linkpath", "path of the symlink to be created"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::symlinkat,
            (
                FileOp,
                "create a symbolic link with the given name linked to the given target",
                &[
                    (["target", "path of the target file to be linked"], Normal(Pointer_To_Text(""))),
                    (["dirfd", "file descriptor of a path to use as anchor if linkpath is relative"], Normal(File_Descriptor(""))),
                    // If linkpath exists, it will not be overwritten.
                    (["linkpath", "path of the symlink to be created"], Normal(Pointer_To_Text(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // contents of the symbolic link pathname in the buffer buf,
            Sysno::readlink,
            (
                FileOp,
                "read the contents of a symbolic link (its target path) to a buffer",
                &[
                    (["pathname", "path of the symlink to be read"], Normal(Pointer_To_Text(""))),
                    (["buf", "buffer where the the symlink contents will be stored"], Normal(Pointer_To_Text(""))),
                    (["bufsiz", "size of the buffer"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "the number of bytes read to the buffer (can truncate if filled), -1 is returned On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::readlinkat,
            (
                FileOp,
                "read the contents of a symbolic link (its target path) to a buffer",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the symlink to be read"], Normal(Pointer_To_Text(""))),
                    (["buf", "buffer where the the symlink contents will be stored"], Normal(Pointer_To_Text(""))),
                    (["bufsiz", "size of the buffer"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "the number of bytes read to the buffer (can truncate if filled), -1 is returned On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::chmod,
            (
                FileOp,
                "change the mode (rwx rwx rwx, set-uid, set-guid, sticky bits) of the file given through a file path",
                &[
                    (["pathname", "path of the file to be altered"], Normal(Pointer_To_Text(""))),
                    (["mode", "directory permissions (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fchmod,
            (
                FileOp,
                "change the mode (rwx rwx rwx, set-uid, set-guid, sticky bits) of the file given through a file descriptor",
                &[
                    (["fd", "file descriptor of the file to be altered"], Normal(File_Descriptor(""))),
                    // the RWX combination variants are infact a combination of the 3 R W X flags
                    // its not its own variant
                    (["mode", "directory permissions (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fchmodat,
            (
                FileOp,
                "change the mode (rwx rwx rwx, set-uid, set-guid, sticky bits) of the file given through a file path, in addition to path traversal flags",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file to be altered"], Normal(Pointer_To_Text(""))),
                    (["mode", "directory permissions (rwx rwx rwx, set-uid, set-guid, sticky bits)"], Normal(General_Flag(FileMode))),
                    (["flags", "path traversal flags"], Normal(General_Flag(FileChmodAtFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // (
        //     Sysno::fchmodat2,
        // ),
        (
            Sysno::chown,
            (
                FileOp,
                "change the owner and group of a given file by its path",
                &[
                    (["pathname", "path of the file to be altered"], Normal(Pointer_To_Text(""))),
                    (["owner", "new owner to be set for the file"], Normal(Unsigned_Numeric)),
                    (["group", "new group to be set for the file"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fchown,
            (
                FileOp,
                "change the owner and group of a given file by its file descriptor",
                &[
                    (["fd", "file descriptor of the file to be altered"], Normal(File_Descriptor(""))),
                    (["owner", "new owner to be set for the file"], Normal(Unsigned_Numeric)),
                    (["group", "new group to be set for the file"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // same as chown but does not recursively follow a symbolic link
        // it will simply change ownership of the link itself
        (
            Sysno::lchown,
            (
                FileOp,
                "change the owner and group of a given file by its path without recursing symbolic links",
                &[
                    (["pathname", "path of the file to be altered"], Normal(Pointer_To_Text(""))),
                    (["owner", "new owner to be set for the file"], Normal(Unsigned_Numeric)),
                    (["group", "new group to be set for the file"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fchownat,
            (
                FileOp,
                "change the owner and group of a given file by its path, with an optional anchor directory, in addition to path traversal flags",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file to be altered"], Normal(Pointer_To_Text(""))),
                    (["owner", "new owner to be set for the file"], Normal(Numeric)),
                    (["group", "new group to be set for the file"], Normal(Numeric)),
                    (["flags", "path traversal flags"], Normal(General_Flag(FileAtFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // file-system level sync
            Sysno::sync,
            (
                DiskIO,
                "flush all current pending filesystem data and metadata writes",
                &[],
                (["does not return anything", "does not return anything"], Does_Not_Return_Anything)
            )
        ),
        (
            // file-system level sync
            Sysno::syncfs,
            (
                DiskIO,
                "flush all current pending filesystem data and metadata writes via a file descriptor within that filesystem",
                &[
                    (["fd", "file descriptor of a file inside the filesystem to be flushed"], Normal(File_Descriptor(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // file level sync
            Sysno::fsync,
            (
                DiskIO,
                "flush all current pending data and metadata writes for a specific file",
                &[
                    (["fd", "file descriptor of the file whose pending writes are to be flushed"], Normal(File_Descriptor(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // The aim of fdatasync() is to reduce disk activity for applications
        // that do not require all metadata to be synchronized with the disk.
        (
            // file level sync
            Sysno::fdatasync,
            (
                DiskIO,
                "flush all current pending data writes and ignore non-critical metadata writes for a specific file",
                &[
                    (["fd", "file descriptor of the file whose pending writes are to be flushed"], Normal(File_Descriptor(""))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
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
            (
                DiskIO,
                "extend or truncate a file to a precise size",
                &[
                    (["path", "path of the file to be truncated or expanded"], Normal(Pointer_To_Text(""))),
                    (["length", "new length of the file"], Normal(Length_Of_Bytes_Specific))

                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // file must be open for writing
            Sysno::ftruncate,
            (
                DiskIO,
                "extend or truncate a file to a precise size",
                &[
                    (["fd", "file descriptor of the file to be truncated or expanded"], Normal(File_Descriptor(""))),
                    (["length", "new length of the file"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
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
            Sysno::close, (
                FileOp,
                "close a file descriptor, will no longer refer to any file",
                &[
                    (["fd", "file descriptor of the file to be closed"], Normal(File_Descriptor("")))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // return information about a file using a path
        (
            Sysno::stat,
            (
                FileOp,
                "find information about a file using its path",
                &[
                    (["pathname", "path of the file, CWD is used as anchor if relative"], Normal(Pointer_To_Text(""))),
                    (["statbuf", "pointer to a buffer which will contain the information about the file upon success"], Normal(Pointer_To_Struct))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // return information about a file using a file descriptor
        (
            Sysno::fstat,
            (
                FileOp,
                "find information about a file using a file descriptor",
                &[
                    (["fd", "file descriptor of the file"], Normal(File_Descriptor(""))),
                    (["statbuf", "pointer to a buffer which will contain the information about the file upon success"], Normal(Pointer_To_Struct))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // return information about a file but does not recursively follow a symbolic link
        // it will simply return information about the link itself
        (
            Sysno::lstat,
            (
                FileOp,
                "find information about a file using a path without recursing symbolic links",
                &[
                    (["pathname", "path of the file, CWD is used as anchor if relative"], Normal(Pointer_To_Text(""))),
                    (["statbuf", "pointer to a buffer which will contain the information about the file upon success"], Normal(Pointer_To_Struct))
                    ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::newfstatat,
            (
                FileOp,
                "find information about a file using its path, while specifying an anchor, and path resolution flags",
                &[
                    (["dirfd", "file descriptor used either as anchor for pathname, or as a target file"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file"], Normal(Pointer_To_Text(""))),
                    (["statbuf", "pointer to a struct where the retrieved information will be stored"], Normal(Pointer_To_Struct)),
                    (["flags", "path resolution behaviour"], Normal(General_Flag(FileAtFlags))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::statx,
            (
                FileOp,
                "find information about a file using its path, while specifying an anchor, path resolution flags, and specific fields to retrieve",
                &[
                    (["dirfd", "file descriptor of a path to use as anchor if pathname is relative"], Normal(File_Descriptor(""))),
                    (["pathname", "path of the file"], Normal(Pointer_To_Text(""))),
                    (["flags", "path resolution behaviour"], Normal(General_Flag(FileAtFlags))),
                    (["mask", "mask specifying the fields of interest to be retrieved"], Normal(General_Flag(FileStatxFlags))),
                    (["statxbuf", "pointer to a struct where the retrieved information will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::statfs,
            (
                FileOp,
                "get information about a specific filesystem using a path",
                &[
                    (["path", "path of the mounted file system"], Normal(Pointer_To_Text(""))),
                    (["buf", "pointer to a struct where the retrieved information will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::fstatfs,
            (
                FileOp,
                "get information about a specific filesystem using a file descriptor",
                &[
                    (["fd", "file descriptor of the mounted file system"], Normal(File_Descriptor(""))),
                    (["buf", "pointer to a struct where the retrieved information will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // deprecated syscall
            Sysno::ustat,
            (
                Device,
                "",
                &[
                    (["dev", "number of the device where a filesystem is mounted"], Normal(Unsigned_Numeric)),
                    (["ubuf", "pointer to a struct where the retrieved information will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::cachestat,
            (
                Memory,
                "get information about the page cache of a file",
                &[
                    (["fd", "file descriptor of the target file"], Normal(File_Descriptor(""))),
                    // pages ceil
                    (["cachestat_range", "pointer to a struct identifying the offset and range of bytes to find information about, pages ceil"], Normal(Pointer_To_Struct)),
                    (["cachestat", "pointer to a struct where the page caches information will be stored"], Normal(Pointer_To_Struct)),
                    // Some unknown flag argument
                    (["flags", "some flag semantics"], Normal(General_Flag(ReservedForFutureUse))),
                ],
                // unknown for now error value
                (["return value", "some error semantics"], Numeric_Or_Errno)
            )
        ),

        // (
        //     Sysno::statmount,
        // ),

        // reposition read/write file offset
        (
            Sysno::lseek,
            (
                DiskIO,
                "reposition read/write file offset",
                &[
                    (["fd", "file descriptor"], Normal(File_Descriptor(""))),
                    (["offset", "new offset count"], Normal(Length_Of_Bytes_Specific)),
                    (["whence", "determine usage of the offset (offset as new position vs offset as addititon to current position vs ... etc)"], Normal(General_Flag(LSeekWhence)))
                ],
                (["return value", "on success returns resulting offset location as measured in bytes from the beginning of the file. (off_t) -1 is returned On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::mmap,
            (
                Memory,
                "create a memory mapping potentially backed by a file",
                &[
                    // Nullable
                    (["addr", "hint for the starting address of the memory map"], Normal(Address)),
                    (["len", "amount of bytes to be mapped"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    // must not conflict with the open mode of the file
                    (["prot", "memory protection flags"], Normal(General_Flag(Prot))),
                    (["flags", "memory mapping flags"], Normal(General_Flag(Map))),
                    (["fd", "file descriptor of the file to be mapped"], Normal(File_Descriptor(""))),
                    (["off", "offset of where the mapping must start"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "on success: pointer to the mapped area.  On error, the value MAP_FAILED (that is, (void *) -1) is returned, and errno is modified"],Address_Or_MAP_FAILED_Errno("")),
            )
        ),
        // set protection on a region of memory
        (
            Sysno::mprotect,
            (
                Memory,
                "set protection on a region of memory",
                &[
                    (["start", "starting address of the range to be protected"], Normal(Address)),
                    (["len", "amount of bytes to be protected, memory pages ceil"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["prot", "protection/access flags"], Normal(General_Flag(Prot))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        // deletes the mappings for the specified address range
        (
            Sysno::munmap,
            (
                Memory,
                "unmap previously mmapped region of memory",
                &[
                    (["addr", "address where memory unmapping will begin"], Normal(Address)),
                    (["len", "amount of bytes to be unmapped from memory"], Normal(Length_Of_Bytes_Page_Aligned_Ceil))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::brk,
            (
                Memory,
                "change the location of the program break",
                &[
                    (["address", "new program break address"], Normal(Address)),
                ],
                // However, the actual Linux system call returns the new program break on success.  
                // On failure, the system call returns the current break.
                // to know if an error occured you have to store the previous program break point somewhere to compare
                (["return value", "new program break pointer on success, -1 on error and errno ENOMEM only"],Address_Or_Errno(""))
            )
        ),
        (
            Sysno::mlock,
            (
                Memory,
                "lock a range of memory in RAM, to prevent swapping",
                &[
                    (["addr", "starting address of the memory to be locked"], Normal(Address)),
                    // Pages Ceil
                    (["len", "amount of bytes of memory to lock beginning from the addr, pages ceil"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                ],
                (["return value", "0 success. -1 for error and errno modified and no changes made"], Numeric_Or_Errno)
            )
        ),
        // mlock2 is linux specific
        (
            Sysno::mlock2,
            (
                Memory,
                "lock a range of memory in RAM to prevent swapping, in addition to a flag that specifies how to handle non-resident pages",
                &[
                    (["addr", "starting address of the memory to be locked"], Normal(Address)),
                    // Pages Ceil
                    (["len", "amount of bytes of memory to lock beginning from the addr, pages ceil"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    // if flag is 0 mlock2 is identical to mlock
                    // MLOCK_ONFAULT
                    //      Lock the pages that are currently resident
                    //      and mark the entire range including non-resident pages
                    //      so that when they are later populated by a page fault
                    //      they get locked
                    (["flags", "flag that addresses handling non-resident pages"], Normal(General_Flag(MLock))),
                ],
                (["return value", "0 success. -1 for error and errno modified and no changes made"], Numeric_Or_Errno)
            )
        ),

        (
            // Memory locking and unlocking are performed in units of whole pages.
            Sysno::munlock,
            (
                Memory,
                "unlock a memory range and allow it to be swappable",
                &[
                    (["addr", "starting address of the memory to be unlocked"], Normal(Address)),
                    // Pages Ceil
                    (["len", "amount of bytes of memory to unlock beginning from the addr, pages ceil"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                ],
                (["return value", "0 success. -1 for error and errno modified and no changes made"], Numeric_Or_Errno)
            )
        ),
        (
            // Memory locking and unlocking are performed in units of whole pages.
            // this is equivalent to MAP_POPULATE (unless the flag is specified for custom behaviour for non-resident and future pages)
            Sysno::mlockall,
            (
                Memory,
                "lock the entire memory of a process to prevent swapping, in addition to flags for handling non-resident and future pages",
                &[
                    (["flags", "flags that addresses handling non-resident and future pages"], Normal(General_Flag(MLockAll))),
                ],
                (["return value", "0 success. -1 for error and errno modified and no changes made"], Numeric_Or_Errno)
            )
        ),
        (
        // Memory locking and unlocking are performed in units of whole pages.
            Sysno::munlockall,
            (
                Memory,
                "unlock the entire memory of a process, allowing it to be swappable",
                &[],
                (["return value", "0 success. -1 for error and errno modified and no changes made"], Numeric_Or_Errno)
            )
        ),
        // expands (or shrinks) an existing memory mapping, potentially moving it at the same time
        (
            Sysno::mremap,
            (
                Memory,
                "shrink or expand or move memory region",
                &[
                    // must be page aligned
                    (["old_address", "old address of the memory region to be shrinked, expanded, or moved"], Normal(Address)),
                    (["old_len", "old amount of bytes"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["new_len", "new amount of bytes"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["flags", "remapping flags"], Normal(General_Flag(ReMap))),
                    (["new_address", "new address in the case where the mapping is moved"], Normal(Address)),
                ],
                (["return value", "on success: pointer to the mapped area. On error, the value MAP_FAILED (that is, (void *) -1) is returned, and errno is modified"],Address_Or_MAP_FAILED_Errno("")),
            )
        ),
        // flushes changes made to the file copy mapped in memory back to the filesystem.
        (Sysno::msync,
            (
                Memory,
                "flush changes made in an mmapped memory range back to the filesystem",
                &[
                    (["address", "address in the file mapping where flushing starts"], Normal(Address)),
                    (["length", "amount of bytes from the beginning address to be flushed"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["flags", "flushing flags"], Normal(General_Flag(MSync)))
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        // returns a vector that represent whether pages of the calling process's virtual memory 
        // are resident in core (RAM), and so will not cause a disk access (page fault) if referenced
        (
            // memory in core
            Sysno::mincore,
            (
                Memory,
                "indicate in a vector which parts of a memory range are resident and which will cause a page fault if accessed",
                &[
                    (["addr", "address in the file mapping where calculation starts"], Normal(Address)),
                    (["length", "amount of bytes from beginning address where the calculation of resident pages will consider"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["vec", "pointer to array of bytes each represents a memory page, every byte indicates if the respective page is resident"], Normal(Byte_Stream))
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        // give advice about use of memory
        (
            Sysno::madvise,
            (
                Memory,
                "give advice about use of memory in a specific range",
                &[
                    // only operates on whole pages
                    // so must be page aligned
                    (["addr", "beginning of the memory range where the advice is applied"], Normal(Address)),
                    (["length", "amount of bytes from beginning address indicating the range where the advice should be taken in consideration"], Normal(Length_Of_Bytes_Page_Aligned_Ceil)),
                    (["advice", "memory advice flags"], Normal(General_Flag(Madvise)))
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),

        (
            Sysno::select,
            (
                AsyncIO,
                "block while watching file descriptor sets for readiness to read, write, in addition to exceptional conditions",
                &[
                    (["nfds", "the number of the highest file descriptor in the three sets + 1, used by the kernel to loop each set"], Normal(Numeric)),
                    // you can set any of these sets to NULL if you don’t care about waiting for it
                    (["readfds", "pointer to struct containing an array of file descriptors watched to see if they are ready for reading"], Normal(Pointer_To_Struct)),
                    (["writefds,", "pointer to struct containing an array of file descriptors watched to see if they are ready for writing"], Normal(Pointer_To_Struct)),
                    (["exceptfds,", "pointer to struct containing an array of file descriptors in this set are watched for \"exceptional conditions\""], Normal(Pointer_To_Struct)),
                    // Some Unices update the timeout here to show how much time is left, not all of them
                    // If you set the fields in your struct timeval to 0,
                    // select() will timeout immediately, effectively polling all the file descriptors in your sets.
                    // If you set the parameter timeout to NULL,
                    // it will wait forever until the first file descriptor is ready.
                    (["timeout", "pointer to struct describing the amount of time select will block in microseconds"], Normal(Pointer_To_Struct)),
                    ],
                (["retrun value", "total number of file descriptors in all sets, 0 if timeout expired before any file descriptors became ready, On error -1, and errno modified, file descriptor sets are left unmodified, and timeout becomes undefined"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::pselect6,
            (
                AsyncIO,
                "block while watching file descriptor sets for readiness to read, write, in addition to exceptional conditions, and watch for new signals",
                &[
                    (["nfds", "the number of the highest file descriptor in the three sets + 1, used by the kernel to loop each set"], Normal(Numeric)),
                    // you can set any of these sets to NULL if you don’t care about waiting for it
                    (["readfds", "pointer to struct containing an array of file descriptors watched to see if they are ready for reading"], Normal(Pointer_To_Struct)),
                    (["writefds,", "pointer to struct containing an array of file descriptors watched to see if they are ready for writing"], Normal(Pointer_To_Struct)),
                    (["exceptfds,", "pointer to struct containing an array of file descriptors in this set are watched for \"exceptional conditions\""], Normal(Pointer_To_Struct)),
                    // pselect never updates timeout to indicate how much time is left (normal select does that in some unices)
                    // If you set the fields in your struct timeval to 0,
                    // select() will timeout immediately, effectively polling all the file descriptors in your sets.
                    // If you set the parameter timeout to NULL,
                    // it will wait forever until the first file descriptor is ready.
                    (["timeout", "pointer to struct describing the amount of time select will block in nanoseconds"], Normal(Pointer_To_Struct)),
                    // The final argument of the pselect6() system call is not a sigset_t * pointer, but is instead a structure of the form:
                    // struct {
                    //     const kernel_sigset_t *ss;   /* Pointer to signal set */
                    //     size_t ss_len;               /* Size (in bytes) of object pointed to by 'ss' */
                    // };
                    (["sig", "pointer to struct containing both the signal mask to watch for and its size"], Normal(Pointer_To_Struct)),
                ],
                (["retrun value", "total number of file descriptors in all sets, 0 if timeout expired before any file descriptors became ready, On error -1, and errno modified, file descriptor sets are left unmodified, and timeout becomes undefined"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::poll,
            (
                AsyncIO,
                "block until specific events occur on the provided file descriptors",
                &[
                    (["fds", "array of file descriptor-event pairs for poll to monitor"], Normal(Array_Of_Struct)),
                    (["nfds", "number of elements in pollfd"], Normal(Unsigned_Numeric)),
                    (["timeout_msecs", "amount of time for poll to block in milliseconds"], Normal(Numeric)),
                ],
                // It doesn’t tell you which elements (you still have to scan for that), it only tell you how many,
                (["return value", "number of elements in nfds for which events have occurred, -1 on error, errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::ppoll,
            (
                AsyncIO,
                "block until specific events occur on the provided file descriptors or until some signals are caught",
                &[
                    (["fds", "array of file descriptor-event pairs for poll to monitor"], Normal(Array_Of_Struct)),
                    (["nfds", "number of elements in pollfd"], Normal(Unsigned_Numeric)),
                    (["tmo_p", "pointer to struct containing amount of time to block in nanoseconds"], Normal(Pointer_To_Struct)),
                    // if null then no mask manipulation is performed
                    (["sigmask", "signal mask containing the signals to watch for"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "the size in bytes of the signal mask"], Normal(Length_Of_Bytes_Specific))
                ],
                // It doesn’t tell you which elements (you still have to scan for that), 
                // it only tell you how many,
                (["return value", "number of elements in nfds for which events have occurred, -1 on error, errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            // This file descriptor is used for all the subsequent calls to the epoll interface.
            // the file descriptor returned by epoll_create() should be closed by using close(2)
            Sysno::epoll_create,
            (
                AsyncIO,
                "creates a new epoll instance and return a file descriptor for it",
                &[
                    // in the past this size parameter told the kernel how many fds the caller expects to add
                    // the kerenl now however does not need that information and instead dynamically allocates space
                    // it is kept for backward compatibility
                    // and must be greater than zero
                    (["size", "number of fds expected to be added later, this argument is no longer needed, but must not be 0"], Normal(Unsigned_Numeric))
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            // This file descriptor is used for all the subsequent calls to the epoll interface.
            // the file descriptor returned by epoll_create1() should be closed by using close(2)
            // epoll_create but with a bahviour customizing flag
            Sysno::epoll_create1,
            (
                AsyncIO,
                "creates a new epoll instance and return a file descriptor for it, in addition to customizing behaviour with a flag",
                &[
                    // if this argument is zero, this syscall is identical to epoll_create
                    (["flags", "flags for different epoll behaviours"], Normal(General_Flag(EPollCreate1Flags))),
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            // A call to epoll_wait() will block until either:
            //     • a file descriptor delivers an event;
            //     • the call is interrupted by a signal handler (different from epoll_pwait)
            //     • the timeout expires.
            Sysno::epoll_wait,
            (
                AsyncIO,
                "block and wait for events on an epoll instance, equivalent to fetching from the ready list",
                &[
                    (["epfd", "file descriptor of the epoll instance to be waited on"], Normal(File_Descriptor(""))),
                    (["epoll_event", "buffer where information about ready file descriptors will be stored"], Normal(Pointer_To_Struct)),
                    (["maxevents", "maximum number of events to be returned from the epoll instance"], Normal(Unsigned_Numeric)),
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    (["timeout", "amount of time for epoll to block in milliseconds"], Normal(Numeric)),
                    ],
                (["return value", "number of file descriptors ready for the requested I/O,"], Numeric_Or_Errno)
            )
        ),
        (
            // similar to epoll_wait but in addition to waiting on specific signals
            Sysno::epoll_pwait,
            (
                AsyncIO,
                "block and wait until either an event on the epoll instance or a signal, equivalent to fetching from the ready list or waiting for a signal",
                &[
                    (["epfd", "file descriptor of the epoll instance to be waited on"], Normal(File_Descriptor(""))),
                    (["events", "buffer where information about ready file descriptors will be stored"], Normal(Pointer_To_Struct)),
                    (["maxevents", "maximum number of events to be returned from the epoll instance"], Normal(Unsigned_Numeric)),
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    (["timeout", "amount of time for epoll to block in milliseconds"], Normal(Numeric)),
                    // if null this syscall is equivalent to epoll_pwait
                    (["sigmask", "signal mask containing the signals to watch for"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "the size in bytes of the signal mask"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "number of file descriptors ready for the requested I/O,"], Numeric_Or_Errno)
            )
        ),
        (
            // similar to epoll_pwait but has nanosend resolution
            Sysno::epoll_pwait2,
            (
                AsyncIO,
                "block and wait until either an event on the epoll instance or a signal, equivalent to fetching from the ready list or waiting for a signal",
                &[
                    (["epfd", "file descriptor of the epoll instance to be waited on"], Normal(File_Descriptor(""))),
                    (["events", "buffer where information about ready file descriptors will be stored"], Normal(Pointer_To_Struct)),
                    (["maxevents", "maximum number of events to be returned from the epoll instance"], Normal(Unsigned_Numeric)),
                    // Time is measured against the CLOCK_MONOTONIC clock
                    // timeout interval will be rounded up to the system clock granularity
                    // -1 means block indefinitely
                    // 0 means return immediately
                    (["timeout", "pointer to struct containing amount of time to block in nanoseconds"], Normal(Pointer_To_Struct)),
                    // if null this syscall is equivalent to epoll_pwait
                    (["sigmask", "signal mask containing the signals to watch for"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "the size in bytes of the signal mask"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "number of file descriptors ready for the requested I/O,"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::epoll_ctl,
            (
                AsyncIO,
                "add, modify, or remove entries in the interest list of the epoll instance",
                &[
                    (["epfd", "file descriptor of the epoll instance"], Normal(File_Descriptor(""))),
                    (["op", "operation to be performed on the epoll instance, add/remove/change"], Normal(General_Flag(EPollCTLOperationFlags))),
                    (["fd", "the file descriptor that the operation refers to"], Normal(File_Descriptor(""))),
                    (["event", "struct containing information about the event associated with the operation"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::socket,
            (
                Network,
                "create a socket file descriptor",
                &[
                    (["family", "communication domain (Internet/IPV4, IPV6, Bluetooth, Amateur radio, XDP ..etc)"], Normal(General_Flag(SocketFamily))),
                    (["type", "communication type (Streaming, Datagram, etc..)"], Normal(General_Flag(SocketType))),
                    (["protocol", "specific protocol (TCP, UDP, RAW)"], Normal(General_Flag(SocketProtocol)))
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::bind,
            (
                Network,
                "assign an address to a socket file descriptor",
                &[
                    (["sockfd", "file descriptor of the socket to be assigned"], Normal(File_Descriptor(""))),
                    (["addr", "struct containing the address which the socket will get assigned"], Normal(Pointer_To_Struct)),
                    (["addrlen", "size of the socket address struct in bytes"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::getsockname,
            (
                Network,
                "get the address a specific socket is bound to",
                &[
                    (["sockfd", "file descriptor of the socket we're getting the address of"], Normal(File_Descriptor(""))),
                        // The returned information is truncated if the buffer provided is too small (addrlen small)
                    (["addr", "buffer where retrieved address information will get stored"], Normal(Pointer_To_Struct)),
                        // upon return this pointer gets updated with the length of bytes written in the buffer
                        // but in this case of truncation
                        // it will return a value greater
                        // than was supplied to the call.
                    (["addrlen", "pointer to integer specifying the length in bytes of the address buffer"], Normal(Pointer_To_Length_Of_Bytes_Specific)),
                    ],
                    (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
                )
        ),
        (
            Sysno::getpeername,
            (
                Network,
                "get the address of the peer connected to a specific socket",
                &[
                    (["sockfd", "file descriptor of the socket we're getting peer information of"], Normal(File_Descriptor(""))),
                    // The returned information is truncated
                    // if the buffer provided is too small (addrlen small);
                    (["addr", "buffer where retrieved peer address information will get stored"], Normal(Pointer_To_Struct)),
                    // upon return this pointer gets updated with the length of bytes written in the buffer
                    // but in this case of truncation
                    // it will return a value greater
                    // than was supplied to the call.
                    (["addrlen", "pointer to integer specifying the length in bytes of the address buffer"], Normal(Pointer_To_Length_Of_Bytes_Specific)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::socketpair,
            (
                Network,
                "create a pair of connected sockets",
                &[
                    (["family", "communication domain (Internet/IPV4, IPV6, Bluetooth, Amateur radio, XDP ..etc)"], Normal(General_Flag(SocketFamily))),
                    (["type", "communication type (Streaming, Datagram, etc..)"], Normal(General_Flag(SocketType))),
                    (["protocol", "specific protocol (TCP, UDP, RAW)"], Normal(General_Flag(SocketProtocol))),
                    // (["sv", "array in which the two created socket descriptors will be stored"],ValueReturn(Pointer_To_File_Descriptor_Array(["", ""]),Pointer_To_File_Descriptor_Array(["", ""])))
                    (["sv", "array in which the two created socket descriptors will be stored"], Normal(Pointer_To_File_Descriptor_Array(["", ""])))
                ],
                // on error sv is left unchanged
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::setsockopt,
            (
                Network,
                "set the options of a socket descriptor",
                &[
                    (["sockfd", "socket descriptor whose options will be manipulated"], Normal(File_Descriptor(""))),
                    (["level", "the protocol level in which the option resides"], Normal(General_Flag(SocketLevel))),
                    (["optname", "name of the option"], Normal(General_Flag(SocketOption))),

                    // the argument should be
                    // nonzero to enable a boolean option,
                    // or zero if the option is to be disabled.
                    (["optval", "buffer containing the new option value to be set"], Normal(Pointer_To_Struct)),

                    (["optlen", "pointer to integer specifying the size in bytes of the option value buffer"], Normal(Pointer_To_Length_Of_Bytes_Specific)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::getsockopt,
            (
                Network,
                "retrieve the options of a socket descriptor",
                &[
                    (["sockfd", "socket descriptor whose options will be manipulated"], Normal(File_Descriptor(""))),
                    (["level", "the protocol level in which the option resides"], Normal(General_Flag(SocketLevel))),
                    (["optname", "name of the option"], Normal(General_Flag(SocketOption))),

                    (["optval", "buffer in which the retrieved option value will be stored"], Normal(Pointer_To_Struct)),
                    //    optlen is a value-result argument
                    //     initially containing the size of optval buffer
                    //     and on return modified to the actual size of the value returned
                    //     can be NULL If no option value is to be supplied or returned,
                    (["optlen", "pointer to integer specifying the length in bytes of the option value buffer"], Normal(Pointer_To_Length_Of_Bytes_Specific)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),

        (
            Sysno::listen,
            (
                Network,
                "create a backlog queue, and mark the socket descriptor as passive (ready to accept connections)",
                &[
                    (["sockfd", "file descriptor of the socket to mark"], Normal(File_Descriptor(""))),
                    (["backlog", "maximum number of connections the queue must hold"], Normal(Numeric))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        (
            Sysno::accept,
            (
                Network,
                "extract the first connection from the backlog queue",
                &[
                    (["sockfd", "file descriptor of the socket listening for connections"], Normal(File_Descriptor(""))),
                    // nullable, and when nullable it is not filled
                    (["addr", "buffer where information about the peer connection will be stored"], Normal(Pointer_To_Struct)),
                    // addrlen is a value-result argument
                    // initially containing the size of optval buffer
                    // and on return modified to the actual size of the value returned
                    // can be NULL If no option value is to be supplied or returned,
                    (["addrlen", "pointer to struct speciiying the size of the addr buffer"], Normal(Pointer_To_Struct)),
                ],
                // -1 on error, errno modified
                (["return value", "file descriptor of the new connection that was extracted, -1 for error and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            // identical to accept
            // except that it has flag arguments which save from doing extra calls to fcntl(2)
            // the flags are to: 1- set socket as non-blocking, 2- set socket as close-on-exec
            Sysno::accept4,
            (
                Network,
                "extract the first connection from the connection queue in addition to specifying behaviour flag such as non-block and close-on-exec",
                &[
                    (["sockfd", "file descriptor of the socket listening for connections"], Normal(File_Descriptor(""))),
                    // nullable, and when nullable it is not filled
                    (["addr", "buffer where information about the peer connection will be stored"], Normal(Pointer_To_Struct)),
                    // addrlen is a value-result argument
                    // initially containing the size of optval buffer
                    // and on return modified to the actual size of the value returned
                    // can be NULL If no option value is to be supplied or returned,
                    (["addrlen", "pointer to struct speciiying the size of the addr buffer"], Normal(Pointer_To_Struct)),
                    // if this flag is 0 then accept4 is identical to accept
                    (["flags", "?"], Normal(General_Flag(SocketFlag))),
                ],
                // -1 on error, errno modified
                (["return value", "file descriptor of the new connection that was extracted, -1 for error and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::connect,
            (
                Network,
                "connect a socket file descriptor to an address",
                &[
                    (["sockfd", "file descriptor of the socket to be connected"], Normal(File_Descriptor(""))),
                    (["addr", "struct containing the address to which the socket will connect"], Normal(Pointer_To_Struct)),
                    (["addrlen", "size of the socket address struct in bytes"], Normal(Length_Of_Bytes_Specific))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::sendto,
            (
                Network,
                "send a message to another socket",
                &[
                    (["sockfd", "file descriptor of the sending socket"], Normal(File_Descriptor(""))),
                    (["buf", "pointer to a buffer containing the message to be sent and the length of the message"], Normal(Pointer_To_Struct)),
                    (["flags", "flags to customize syscall behaviour"], Normal(General_Flag(SocketMessageFlag))),
                    // WILL BE USED if connection-less (like UDP)
                    // WILL BE IGNORED if connection-mode (like TCP, or SEQ) and must be null or 0
                    (["dest_addr", "address of the target socket"], Normal(Pointer_To_Struct)),
                    // IGNORED if connection-mode (like TCP, or SEQ) (UDP IS CONNECTIONLESS) and must be null or 0
                    (["addr_len", "size of the destination address struct in bytes"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["return value", "number of bytes written, 0 means end of file, -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::sendmsg,
            (
                Network,
                "send a message to another socket",
                &[
                    (["sockfd", "file descriptor of the sending socket"], Normal(File_Descriptor(""))),
                    (["msg", "pointer to struct containing the target socket address, the size of the struct, and an array containing the message to be sent"], Normal(Pointer_To_Struct)),
                    (["flags", "flags to customize syscall behaviour"], Normal(General_Flag(SocketMessageFlag)))
                ],
                (["return value", "number of bytes written, 0 means end of file, -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::recvfrom,
            (
                Network,
                "receive a message from a socket",
                &[
                    (["sockfd", "file descriptor of the socket to receive data from"], Normal(File_Descriptor(""))),
                    // If a message is too long to fit in the supplied buffer,
                    // excess bytes may be discarded depending
                    // on the type of socket the message is received from.
                    (["buf", "buffer in which the received data will be stored"], Normal(Pointer_To_Text(""))),
                    (["len", "size in bytes of the buffer"], Normal(Length_Of_Bytes_Specific)),
                    (["flags", "?"], Normal(General_Flag(SocketMessageReceiveFlag))),
                    // if src_addr and addrlen are NULL
                    // it means we do not care or want src_addr details
                    // otherwise addrlen is value-result argument
                    (["src_addr", "buffer which will contain the source address of the socket we received the data from"], Normal(Pointer_To_Struct)),
                    // value-result argument, will become the length of the buffer, and truncation rules apply
                    (["addrlen", "size of the source address buffer"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "number of bytes written, 0 means zero-length datagrams which are permitted, -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::recvmsg,
            (
                Network,
                "receive a message from a socket",
                &[
                    (["sockfd", "file descriptor of the socket to receive data from"], Normal(File_Descriptor(""))),
                    // If a message is too long to fit in the supplied buffer,
                    // excess bytes may be discarded depending
                    // on the type of socket the message is received from.
                    (["msg", "pointer to a struct containing the details of data received including scatter-gather buffer and length information"], Normal(Pointer_To_Struct)),
                    (["flags", "?"], Normal(General_Flag(SocketMessageFlag)))
                ],
                (["return value", "number of bytes written, 0 means zero-length datagrams which are permitted, -1 means error, and errno modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::shutdown,
            (
                Process,
                "shut down a socket connection full or partially",
                &[
                    (["sockfd", "file descriptor of the affected socket"], Normal(File_Descriptor(""))),
                    (["how", "flag specificying shutdown domain"], Normal(General_Flag(SocketShutdownFlag)))
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno),
            )
        ),
        // (
        //     Sysno::sendfile,
        // ),
        (
            Sysno::fcntl,
            (
               FileOp,
               "perform a file operation on a file",
                &[
                    (["fd", "the file descriptor to be operated on"], Normal(File_Descriptor(""))),
                    (["op", "specific operation to be performed"], Normal(General_Flag(FcntlFlags))),
                    (["arg", "optional argument varying depending on the operation"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 on success (sometimes this is a output value), -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::ioctl,
            (
                Device,
                "carry out a specific operation/request on a device",
                &[
                    (["fd", "file descriptor of the device"], Normal(File_Descriptor(""))),
                    (["request", "code of the specific request to be carried out"], Normal(Unsigned_Numeric)),
                    // The arg parameter to the ioctl is opaque at the generic vfs level (an opaque data type is a data type whose concrete data structure is not defined in an interface)
                    // How to interpret it is up to the driver or filesystem that actually handles it
                    // So it may be a pointer to userspace memory, or it could be an index, a flag, whatever
                    // It might even be unused and conventionally passed in a 0
                    (["argp", "typeless extra argument, the driver defineds it, and can vary based on what the driver wants"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 on success (sometimes this is a output value), -1 on error, errno modified"], Numeric_Or_Errno)

            )
        ),
        // (
        //     Sysno::prctl,
        // ),
        (
            Sysno::arch_prctl,
            (
                Process,
                "set architecture-specific process/thread state",
                &[
                    (["op", "specific operation to perform"], Normal(General_Flag(ArchPrctlFlags))),
                    // TODO! this argument is a number for set operations and a pointer to a number for get operations 
                    // Pointer_To_Numeric_Or_Numeric is a special case for arch_prctl, because it depends on the op union
                    (["addr", "can be either an unsigned long for set operations, or a pointer to unsigned long for get operations"], Normal(Pointer_To_Numeric_Or_Numeric(None))),
                ],
                (["return value", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        // causes the calling thread to relinquish the CPU.  
        // The thread is moved to the end of the queue for its static priority and a new thread gets to run.
        (
            Sysno::sched_yield,
            (
                Process,
                "relinquish the CPU, and move to the end of the queue",
                &[],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rt_sigaction,
            (
                Signals,
                "change action for a specific signal",
                &[
                    // can be any valid signal except SIGKILL and SIGSTOP.
                    (["signum", "specific signal for which the action should be changed"], Normal(General_Flag(Signal))),
                    (["act", "sigaction struct where new action to take is specified"], Normal(Pointer_To_Struct)),
                    // nullable meaning we dont want it
                    (["oldact", "pointe to struct where the old sigaction struct will be saved"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "size of the signal sets in the action mask and the old action mask"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rt_sigprocmask,
            (
                Signals,
                "modify or get the signal mask (signals blocked from delivery) of the calling thread",
                &[
                    (["how", "specific signal for which the action should be changed"], Normal(General_Flag(SignalHow))),
                    // If NULL, then the signal mask is unchanged.
                    (["set", "sigaction struct where new action to take is specified"], Normal(Pointer_To_Struct)),
                    // If non-NULL, the previous value of the mask is stored here.
                    (["oldset", "sigaction struct where new action to take is specified"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "size of the signal sets in the new set and the old set"], Normal(Length_Of_Bytes_Specific)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // basically
            // 1- change the signal mask
            // 2- immediately BLOCK the process waiting for a signal on that new mask to trigger
            // (its like what ptrace TRACE_ME does)
            Sysno::rt_sigsuspend,
            (
                Signals,
                "temporarily alter the signal mask of the process, and suspend execution until the delivery of a signal that has a handler or one that terminates the thread",
                &[
                    // SIGKILL or SIGSTOP can not be blocked
                    (["mask", "new temporary mask to be set"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "size of the mask struct in bytes"], Normal(Length_Of_Bytes_Specific))
                ],
                // always returns -1, with errno set to indicate the error (normally, EINTR)
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // used during signal handling
            // A signal stack is a special area of memory
            // to be used as the execution stack during signal handlers
            // It should be fairly large, to avoid any danger that it will overflow
            Sysno::sigaltstack,
            (
                Signals,
                "define an alternative signal stack or retrieve the state of the current one",
                &[
                    // can be null if dont want this part of the operation
                    (["ss", "pointer to a struct containing information about the new signal stack to use"], Normal(Pointer_To_Struct)),
                    // NULLABLE meaning we dont want it
                    (["old_ss", "pointer to an empty signal stack struct to store the old signal stack information"], Normal(Pointer_To_Struct)),
                    ],
                    (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // created to immediately run after signal handlers, to clean up and correct stack pointer/program counter
            Sysno::rt_sigreturn,
            (
                Signals,
                "return from signal handler and cleanup stack frame",
                &[],
                (["", ""], Never_Returns)
            )
        ),
        (
            Sysno::rt_sigpending,
            (
                Signals,
                "return the set of signals pending for delivery for the calling thread",
                &[
                    (["set", "pointer to struct set where the signals will be stored"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "size of the set struct in bytes"], Normal(Length_Of_Bytes_Specific))
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rt_sigtimedwait,
            (
                Signals,
                "suspends execution of the process until one of the signals provided is pending, or a given timeout is exceeded",
                &[
                    (["set", "pointer to struct containing the set of signals to check for"], Normal(Pointer_To_Struct)),
                    // NULLABLE
                    (["info", "pointer to struct where information about the signals found will be stored"], Normal(Pointer_To_Struct)),
                    (["timeout", "pointer to struct containing amount of time to block in nanoseconds"], Normal(Pointer_To_Struct)),
                    (["sigsetsize", "size of the set struct in bytes"], Normal(Length_Of_Bytes_Specific))
                ],
                (["signal", "signal number on success, -1 on error, errno modified"],Signal_Or_Errno(""))
            )
        ),
        (
            // require registering a handler first via sigaction
            // sends the data to an arbitrary thread with the thread group
            Sysno::rt_sigqueueinfo,
            (
                Signals,
                "send a signal plus data to a process/thread group",
                &[
                    (["tgid", "id of the thread group where the signal will be sent"], Normal(PID)),
                    (["sig", "the signal to be sent"], Normal(General_Flag(Signal))),
                    (["info", "address of the struct containing the data to be sent"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // require registering a handler first via sigaction
            // sends the data to a specific thread withing the thread group
            Sysno::rt_tgsigqueueinfo,
            (
                Signals,
                "send a signal plus data to a specific thread within a process/thread group",
                &[
                    (["tgid", "id of the thread group where the signal will be sent"], Normal(PID)),
                    (["pid", "id of the specific thread in the thread group"], Normal(PID)),
                    (["sig", "the signal to be sent"], Normal(General_Flag(Signal))),
                    (["info", "address of the struct containing the data to be sent"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::signalfd,
            (
                Signals,
                "create a new file for accepting signals",
                &[
                    // fd of a file, or -1, let the kernel create a new file descriptor
                    (["fd", "file descriptor of the file to be used to receive signals"], Normal(File_Descriptor(""))),
                    // It is not possible to receive SIGKILL or SIGSTOP
                    // SIGKILL or SIGSTOP can not be blocked
                    (["mask", "the set of signals to be accept via the file descriptor"], Normal(Pointer_To_Struct)),
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::signalfd4,
            (
                Signals,
                "create a file descriptor for accepting signals, in addition to file customization flags",
                &[
                    // fd of a file, or -1, let the kernel create a new file descriptor
                    (["fd", "file descriptor of the file to be used to receive signals"], Normal(File_Descriptor(""))),
                    // It is not possible to receive SIGKILL or SIGSTOP
                    // SIGKILL or SIGSTOP can not be blocked
                    (["mask", "the set of signals to be accept via the file descriptor"], Normal(Pointer_To_Struct)),
                    (["flags", "flags to customize the file descriptor"], Normal(General_Flag(SignalFDFlags)))
                ],
                (["return value", "-1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        // The pidfd_open syscall allows users to obtain a file descriptor referring to the PID of the specified process. 
        // This syscall is useful in situations where one process needs access to the PID of another process in order to send signals, 
        // retrieve information about the process, or similar operations. 
        // It can also be used to monitor the lifetime of the process, since the file descriptor is closed when the process terminates.
        (
            Sysno::pidfd_send_signal,
            (
                Signals,
                "send a signal to a process specified by a file descriptor",
                &[
                    (["pidfd", "file descriptor of the process of where the siganl is to be sent"], Normal(File_Descriptor(""))),
                    (["sig", "signal to be sent"], Normal(General_Flag(Signal))),
                    // if null, its equivalent to the struct version which is provided a signal is sent using kill
                    // otherwise the buffer is equivalent to the info buffer specified by the rt_sigqueueinfo syscall
                    (["info", "struct containing information about the signal"], Normal(Pointer_To_Struct)),
                    // reserved for future use, currently should be 0
                    (["flags", "flag for customization, currently does not provide any functionality"], Normal(General_Flag(ReservedForFutureUse))),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // always successful
            Sysno::gettid,
            (
                Thread,
                "get the thread id of the calling thread",
                &[],
                (["return value", "thread id of the calling thread"],Always_Successful_Numeric)
            )
        ),
        // This is often used by routines that generate unique temporary filenames.
        (
            // always successful
            Sysno::getpid,
            (
                Thread,
                "get the process id of the calling process",
                &[],
                (["return value", "process id of the calling process"],Always_Successful_Numeric)
            )
        ),
        (
            // always successful
            Sysno::getppid,
            (
                Thread,
                "get the process id of the parent process",
                &[],
                (["return value", "process id of the parent of the calling process"],Always_Successful_Numeric)
            )
        ),
        // These bytes can be used to seed user-space random number generators or for cryptographic purposes.
        (
            Sysno::getrandom,
            (
                Device,
                "fill a specified buffer with random bytes",
                &[
                    (["buf", "pointer to a buffer where the random bytes will be stored"], Normal(Pointer_To_Struct)),
                    (["buflen", "amount of bytes to fill in the buffer"], Normal(Length_Of_Bytes_Specific)),
                    (["flags", "flags to select the random source, and whether the call should block"], Normal(General_Flag(GetRandomFlags))),
                ],
                (["return value", "number of random bytes retrieved, -1 On error and errno is modified"],Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            Sysno::setrlimit,
            (
                Process,
                "set the soft and hard resource limits of a process",
                &[
                    (["resource", "specific resource type to limit"], Normal(General_Flag(ResourceFlags))),
                    (["rlim", "pointer to a struct containing the soft and hard limits"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::getrlimit,
            (
                Process,
                "get the soft and hard resource limits of a process",
                &[
                    (["resource", "specific resource type to retrieve"], Normal(General_Flag(ResourceFlags))),
                    (["rlim", "pointer to a struct where the soft and hard limits of the resource will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // basically both, setrlimit and getrlimit in one syscall
            // NULL when you dont want either
            Sysno::prlimit64,
            (
                Process,
                "get or set the soft and hard limits of a specific resource for a process",
                &[
                    // if zero then operate on the calling process
                    (["pid", "process id of the process to operate on"], Normal(PID)),
                    (["resource", "specific resource type to operate on"], Normal(General_Flag(ResourceFlags))),
                    // NULLABLE
                    (["new_limit", "pointer to a struct containing the soft and hard limits to use as new limits"], Normal(Pointer_To_Struct)),
                    // NULLABLE
                    (["old_limit", "pointer to a struct where the soft and hard limits of the resource will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
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
            (
                Process,
                "get resource usage metrics for a specific process domain",
                &[
                    (["who", "which domain of the process to measure"], Normal(General_Flag(RusageWhoFlags))),
                    (["usage", "pointer to a struct where the the resource usage metrics will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::sysinfo,
            (
                Process,
                "get memory and swap usage metrics",
                &[
                    (["info", "pointer to a struct where the the system info will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::times,
            (
                Process,
                "get time metrics for the calling process and its children",
                &[
                    (["buf", "pointer to a struct where various timing metrics for the process will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "number of clock ticks for the process since an arbitrary point, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::sched_setaffinity,
            (
                CPU,
                "set specific CPUs for this thread to run on",
                &[
                    // if zero then the calling thread is the thread referred to
                    (["pid", "thread id of the thread to operate on"], Normal(PID)),
                    (["cpusetsize", "size of the CPU mask struct"], Normal(Length_Of_Bytes_Specific)),
                    (["mask", "pointer to struct containing the bitmask of CPUs"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::sched_getaffinity,
            (
                CPU,
                "find which CPUs this thread is allowed to run on",
                &[
                    // if zero then the calling thread is the thread referred to
                    (["pid", "thread id of the thread to operate on"], Normal(PID)),
                    (["cpusetsize", "size of the CPU mask struct"], Normal(Length_Of_Bytes_Specific)),
                    (["mask", "pointer to struct where the current thread's CPU bitmask will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // Any open file descriptors belonging to the process are closed.
            // Any children of the process are inherited by init(1)
            // (or  by the nearest "subreaper" process as defined prctl(2) PR_SET_CHILD_SUBREAPER operation).
            // The process's parent is sent a SIGCHLD signal.
            Sysno::exit,
            (
                Process,
                "exit the calling process",
                &[
                    (["status", "status of the process on exit"], Normal(Numeric)),
                ],
                (["", ""], Never_Returns)
            )
        ),
        (
            Sysno::exit_group,
            (
                Process,
                "exit all threads in this process's thread group",
                &[
                    (["status", "status of the process on exit"], Normal(Numeric)),
                ],
                (["", ""], Never_Returns)
            )
        ),
        (
            // can be used to send a signal only to a process (i.e., thread group) as a whole,
            // and the signal will be delivered to an arbitrary thread within that process.
            // similar to rt_tgsigqueueinfo
            Sysno::tgkill,
            (
                Thread,
                "send a signal to a specific thread in a specific thread",
                &[
                    // If tgid is specified as -1, tgkill() is equivalent to tkill().
                    (["tgid", "id of the thread group where the signal will be sent"], Normal(PID)),
                    (["tid", "id of the specific thread in the thread group"], Normal(PID)),
                    (["sig", "the signal to be sent"], Normal(General_Flag(Signal))),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // similar to rt_sigqueueinfo
            Sysno::tkill,
            (
                Thread,
                "send a signal to a specific thread in a specific thread",
                &[
                    (["tid", "id of the specific thread to which the signal will be sent"], Normal(PID)),
                    (["sig", "the signal to be sent"], Normal(General_Flag(Signal))),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::rseq,
            (
                Thread,
                "register a per-thread data structure shared between kernel and user-space",
                &[
                    // Only one rseq can be registered per thread,
                    (["rseq", "pointer to the thread-local rseq struct to be shared between kernel and user-space"], Normal(Pointer_To_Struct)),
                    (["rseq len", "size of the struct rseq"], Normal(Length_Of_Bytes_Specific)),
                    // 0 for registration, and RSEQ FLAG UNREGISTER for unregistration
                    (["flags", "the signal to be sent"], Normal(General_Flag(RSeqFlag))),
                    // Each supported architecture provides a RSEQ_SIG macro in sys/rseq.h
                    // which contains a signature. That signature is expected to be present in the code
                    // before each restartable sequences abort handler.
                    // Failure to provide the expected signature may terminate the process
                    // with a segmentation fault.
                    (["sig", "32-bit signature to be expected before the abort handler code"], Normal(Unsigned_Numeric)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::uname,
            (
                System,
                "get system information",
                &[
                    (["mask", "pointer to struct where the system information will be stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // always successful
            Sysno::getuid,
            (
                Process,
                "get the real user ID of the calling process",
                &[],
                (["return value", "the real user ID of the calling process"],Always_Successful_User_Group)
            )
        ),
        (
            // always successful
            Sysno::geteuid,
            (
                Process,
                "get the effective user ID of the calling process",
                &[],
                (["return value", "the effective user ID of the calling process"],Always_Successful_User_Group)
            )
        ),
        (
            // always successful
            Sysno::getgid,
            (
                Process,
                "get the real group ID of the calling process",
                &[],
                (["return value", "the real group ID of the calling process"],Always_Successful_User_Group)
            )
        ),
        (
            // always successful
            Sysno::getegid,
            (
                Process,
                "get the effective group ID of the calling process",
                &[],
                (["return value", "the effective group ID of the calling process"],Always_Successful_User_Group)
            )
        ),
        (
            // If the calling process is privileged (the process has the CAP_SETUID capability),
            // then the real UID and saved set-user-ID are also set.
            Sysno::setuid,
            (
                Process,
                "set the effective user ID of the calling process",
                &[
                    (["uid", "id of the thread group where the signal will be sent"], Normal(User_Group)),
                ],
                // The user ID specified in uid is not valid in this user namespace.
                // The  user  is  not  privileged (does not have the CAP_SETUID capability)
                // and uid does not match the real UID or saved set-user-ID of the calling process.
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::setgid,
            (
                Process,
                "set the effective user ID of the calling process",
                &[
                    (["gid", "id of the thread group where the signal will be sent"], Normal(User_Group)),
                ],
                // The calling process is not privileged (does not have the CAP_SETGID),
                // and gid does not match the real group ID or saved set-group-ID of the calling process.
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // Before the introduction of futexes, system calls were required for locking and unlocking shared resources
            // (for example semop).
            Sysno::futex,
            (
                AsyncIO,
                "set the effective user ID of the calling process",
                &[
                    (["uaddr", "pointer to the futex-word"], Normal(Pointer_To_Unsigned_Numeric)),
                    (["futex_op", "specific futex operation to carry"], Normal(General_Flag(FutexOpFlags))),
                    (["val", "value specific to each operation"], Normal(Unsigned_Numeric)),
                    (["timeout", "either a pointer to a timeout struct for blocking operations or a normal numeric value specific to some operations"], Normal(Pointer_To_Struct)),
                    (["uaddr2", "pointer to a second futex-word"], Normal(Pointer_To_Unsigned_Numeric)),
                    (["val3", "value specific to each operation"], Normal(Unsigned_Numeric)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // always successful
            // When set_child_tid is set, the very first thing the new thread does is to write its thread ID at this address.

            // When a thread whose clear_child_tid is not NULL terminates, then, 
            // if the thread is sharing memory with other threads, then 0 is written at the address specified in
            // clear_child_tid and the kernel performs the following operation:
            // futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
            // The effect of this operation is to wake a single thread that is performing a futex wait on the memory location.  
            // Errors from the futex wake operation are ignored.
            Sysno::set_tid_address,
            (
                Thread,
                "set the `clear_child_tid` value for the calling thread to the id provided",
                &[
                    (["tidptr", "pointer to the thread id to use for `clear_child_tid`"], Normal(Pointer_To_Numeric(None))),
                ],
                (["return value", "thread id of the calling thread"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::eventfd, 
            (
                FileOp,
                "create a file to use for event notifications/waiting",
                &[
                    (["initval", "value specific to each operation"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "event file descriptor on success, -1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::eventfd2, 
            (
                FileOp,
                "create a file to use for event notifications/waiting with custom file behaviour",
                &[
                    (["initval", "value specific to each operation"], Normal(Unsigned_Numeric)),
                    (["flags", "event file behaviour flag"], Normal(General_Flag(EventfdFlag))),
                ],
                (["return value", "event file descriptor on success, -1 on error, errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::wait4,
            (
                Process,
                "wait for a process to change state",
                &[
                    // < -1  wait for any child process whose process group ID is equal to the absolute value of pid.
                    // -1    wait for any child process.
                    // 0     wait for any child process whose process group ID is equal to that of the calling process at the time of the call to waitpid().
                    // > 0   wait for the child whose process ID is equal to the value of pid.
                    (["pid", "number representing which process to wait on"], Normal(User_Group)),
                    // If wstatus is not NULL, wait4() stores status information in the int to which it points.  
                    // This integer can be inspected with the following macros  
                    // (which take the integer itself as an argument, not a pointer to it (as is done in syscall))
                    (["wstatus", "pointer to int representing the status of the process"], Normal(Pointer_To_Numeric(None))),
                    (["options", "specific state changes to wait for"], Normal(General_Flag(WaitEventFlags))),
                    // NULLABLE means do not want
                    // resource usage information about the child
                    (["rusage", "pointer usage to a struct where the the resource usage metrics will get stored"], Normal(Pointer_To_Struct)),
                ],
                (["numeric return", "pid of the child whose state has changed, or 0 on no state change for WNOHANG, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::waitid,
            (
                Process,
                "wait until a specific event occurs for a specific child process",
                &[

                    (["idtype", "categoty of process identifier to use for specifying the process"], Normal(General_Flag(WaitIdTypeFlags))),
                    (["id", "the specific id in the category defined by idtype"], Normal(User_Group)),
                    (["infop", "pointer to a struct that will store the information about the child"], Normal(Pointer_To_Struct)),
                    (["options", "specific state changes to wait for"], Normal(General_Flag(WaitEventFlags))),
                    // NULLABLE means do not want
                    // resource usage information about  the
                    // child, in the same manner as wait4(2).
                    (["rusage", "pointer usage to a struct where the the resource usage metrics will get stored"], Normal(Pointer_To_Struct)),
                    ],
                // returns 0 on success or if WNOHANG was specified and no child(ren) specified by id has yet changed state
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            ) 
        ),
        // 
        // (
        //     Sysno::eventfd2,
        // ),
        // 
        (
            // in linux every thread can have a list of "robust futexes" 
            // threads in programs use this list as a contingency plan in the case that they die unexpectedly
            // given that they are in user-space, the kernel can't do anything in case a thread dies while holding the lock, 
            // in that case the only way for waiting threads to be stopped is by rebooting!
            // to fix this, in linux, whever a thread exits (any thread) the kernel checks if it has a robust futex list
            // if it does, then the kernel walks the list of futexes 
            // and for every futex it cleans up and wakes any other waiter  
            Sysno::set_robust_list,
            (
                Process,
                "modify the robust futexes list of the calling thread",
                &[
                    (["head_ptr", "location of the head of the robust futex list"], Normal(Address)),
                    (["len_ptr", "size of the robust futex list"], Normal(Numeric)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // in linux every thread can have a list of "robust futexes" 
            // threads in programs use this list as a contingency plan in the case that they die unexpectedly
            // given that they are in user-space, the kernel can't do anything in case a thread dies while holding the lock, 
            // in that case the only way for waiting threads to be stopped is by rebooting!
            // to fix this, in linux, whever a thread exits (any thread) the kernel checks if it has a robust futex list
            // if it does, then the kernel walks the list of futexes 
            // and for every futex it cleans up and wakes any other waiter  
            Sysno::get_robust_list,
            (
                Process,
                "retrieve the list of robust futexes for a specific thread",
                &[
                    (["pid", "id of the process to be modified"], Normal(User_Group)),
                    (["head_ptr", "address of the head of the robust futex list"], Normal(Address)),
                    (["len_ptr", "size of the robust futex list"], Normal(Pointer_To_Numeric(None))),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::setpgid,
            (
                Process,
                "set the process group ID of a specific process",
                &[
                    (["pid", "id of the process to be modified"], Normal(User_Group)),
                    (["pgid", "the new process group id to set for the process"], Normal(User_Group)),
                ],
                (["numeric return", "0 on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::getpgid,
            (
                Process,
                "get the process group ID of a specific process",
                &[
                    (["pid", "id of the process to operate on"], Normal(User_Group)),
                ],
                (["return value", "process group id on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::getpgrp,
            (
                Process,
                "get the process group ID of the calling process",
                &[],
                (["return value", "process group id on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // run in separate memory spaces.
            // At the time of fork() both memory spaces have the  same  content.
            // Memory  writes,  file  mappings, unmappings, performed by one of the processes do not affect the other.

            // The child process is an exact duplicate of the parent process except for the following points:

            // •  The child has its own unique process ID, 
     
            // •  The child's and parent have the same parent process ID 
     
            // •  The child does not inherit memory locks (mlock(2), mlockall(2)).
     
            // •  Process resource utilizations (getrusage(2)) and CPU time counters (times(2)) are reset to zero in the child.
     
            // •  The child's set of pending signals is initially empty (sigpending(2)).
     
            // •  The child does not inherit semaphore adjustments from its parent (semop(2)).
     
            // •  The  child  does  not  inherit  process-associated record locks from its parent (fcntl(2)).  (On the other hand, it does inherit fcntl(2) open file description locks and
            //    flock(2) locks from its parent.)
     
            // •  The child does not inherit timers from its parent (setitimer(2), alarm(2), timer_create(2)).
     
            // •  The child does not inherit outstanding (unresolved) asynchronous I/O operations from its parent (aio_read(3), aio_write(3)), nor does it inherit any asynchronous  I/O  contexts  from
            //    its parent (see io_setup(2)).
     
            // The  process  attributes  in the preceding list are all specified in POSIX.1.  The parent and child also differ with respect to the following Linux-specific process attributes:
     
            // •  The child does not inherit directory change notifications (dnotify) from its parent 
     
            // •  The prctl(2) PR_SET_PDEATHSIG setting is reset so that the child does not receive a signal when its parent terminates.

            // •  The default timer slack value is set to the parent's current timer slack value.  

            // •  madvise(2)  MADV_DONTFORK marked Memory mappings flag are not inherited 

            // •  madvise(2)  MADV_WIPEONFORK marked Memory mappings are wiped
     
            // •  The termination signal of the child is always SIGCHLD (see clone(2)).
     
            // •  The port access permission bits set by ioperm(2) are not inherited by the child; the child must turn on any bits that it requires using ioperm(2).
     
            // Note the following further points:
     
            // •  The  child  process is created with a single thread—the one that called fork().  The entire virtual address space of the parent is replicated in the child, including the
            //    states of mutexes, condition variables, and other pthreads objects; the use of pthread_atfork(3) may be helpful for dealing with problems that this can cause.
     
            // •  After a fork() in a multithreaded program, the child can safely call only async-signal-safe functions (see signal-safety(7)) until such time as it calls execve(2).
     
            // •  The child inherits copies of the parent's set of open file descriptors.  Each file descriptor in the child refers to the same open file description (see open(2)) as  the
            //    corresponding  file  descriptor in the parent.  This means that the two file descriptors share open file status flags, file offset, and signal-driven I/O attributes (see
            //    the description of F_SETOWN and F_SETSIG in fcntl(2)).
     
            // •  The child inherits copies of the parent's set of open message queue descriptors (see mq_overview(7)).  Each file descriptor in the child refers to the same open  message
            //    queue description as the corresponding file descriptor in the parent.  This means that the two file descriptors share the same flags (mq_flags).
     
            // •  The  child inherits copies of the parent's set of open directory streams (see opendir(3)).  POSIX.1 says that the corresponding directory streams in the parent and child
            //    may share the directory stream positioning; on Linux/glibc they do not.
     
            Sysno::fork,
            (
                Process,
                "creates a new child process by duplicating the calling process",
                &[],
                (["return value", "0 returned to the child process, and the new process id of the child returned to the calling process, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // 1- simpler version of the fork() system call. 
            //      This is because executing the fork() system call, 
            //      (before the copy-on-write mechanism was created) 
            //      involved copying everything from the parent process, including address space, 
            //      which was very inefficient.
            // 
            // 2- the calling thread is suspended until the child terminates or makes a call to execve
            //      This is because both processes use the same address space, 
            //      which contains the stack, stack pointer, and instruction pointer.

            Sysno::vfork,
            (
                Process,
                "creates a new child process, and suspend the calling process until child termination",
                &[],
                (["return value", "0 returned to the child process, and the new process id of the child returned to the calling process, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::clone3,
            (
                Process,
                "Create a new child thread",
                &[
                    (["cl_args", "pointer to a struct containing the parameters for the new thread"], Normal(Pointer_To_Struct)),
                    (["size", "size of the cl_args struct"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "thread id of the new child thread"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::clone,
            (
                Process,
                "Create a new child thread",
                &[
                    (["flags", "cloning customization flags"], Normal(General_Flag(CloneFlags))),
                    (["stack", "pointer to a struct containing the parameters for the new thread"], Normal(Address)),
                    (["parent_tid", "location where child thread id is stored in parent's memory"], Normal(Pointer_To_Numeric(None))),
                    (["child_tid", "location where child thread id is stored in child's memory"], Normal(Pointer_To_Numeric(None))),
                    (["tls", "thread local storage descriptor"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "thread id of the new child thread"], Numeric_Or_Errno)
            )
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
            Sysno::execve,
            (
                Process,
                "execute a program using a pathname and replace the current program",
                &[
                    (["pathname", "path of the file of the program to be executed"], Normal(Pointer_To_Text(""))),
                    // the first of these strings should be the filename of the file being executed
                    // terminated by a null pointer
                    (["argv","array of pointers to strings containing the command-line arguments for the program"],Normal(Array_Of_Strings(&[]))),
                    // terminated by a null pointer
                    (["envp","array of pointers to `key=value` strings containing the environment of the new program"],Normal(Array_Of_Strings(&[]))),
                ],
                // does not return on success
                (["return value", "does not return on success, -1 on error, errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::nanosleep,
            (
                Process,
                "suspend execution of the calling thread until the specified timeout, or ocurrence of siganl handling",
                &[
                    // The value of the nanoseconds field must be in the range [0, 999999999].
                    (["duration", "pointer to struct containing amount of time to block in nanoseconds"], Normal(Pointer_To_Struct)),
                    // NULLABLE means do not want
                    (["rem", "pointer to a struct where the remaining time is to be stored in case of an interruption"],Normal(Pointer_To_Struct)),
                ],
                (["return value", "0 on success, -1 on interruption or error, errno modified"], Numeric_Or_Errno)
            )
        ),
        // (
        //     Sysno::execveat,
        // ),
        // (
        //     Sysno::kill,
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
        //     Sysno::pause,
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
            (
                Security,
                "create a file descriptor for a landlock ruleset",
                &[
                    // these actions will by default be forbidden if no future rules explicitly allows them
                    // Nullable
                    (["attr", "pointer to struct containing a bitmask of actions to be handled by this ruleset"], Normal(Pointer_To_Struct)),
                    (["size", "size of the landlock ruleset struct"], Normal(Length_Of_Bytes_Specific)),
                    // flags must be 0 if attr is used.
                    // for now only: LANDLOCK_CREATE_RULESET_VERSION flag available
                    //      If attr is NULL and size is 0, then the returned value is the highest supported Landlock ABI version
                    (["flags", "flags "], Normal(General_Flag(LandlockCreateFlag))),
                ],
                (["return value", "landlock ruleset file descriptor, or a Landlock ABI version, -1 for error, and errno modified"],File_Descriptor_Or_Errno(""))
            )
        ),
        (
            Sysno::landlock_add_rule,
            (
                Security,
                "add a new Landlock rule to an existing landlock ruleset",
                &[
                    (["ruleset_fd", "file descriptor of the landlock ruleset where the rule will be added"], Normal(File_Descriptor(""))),
                    // currently only LANDLOCK_RULE_PATH_BENEATH : bla is file hierarchy.
                    (["rule_type", "flag identifying the type of rule in rule_attr"], Normal(General_Flag(LandlockRuleTypeFlag))),
                    (["rule_attr", "pointer to struct containing the new rule details"], Normal(Pointer_To_Struct)),
                    // must be 0
                    (["flags", "curently no flags supported"], Normal(General_Flag(LandlockAddRuleFlag))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::landlock_restrict_self,
            (
                Security,
                "enforce the ruleset in the provided file descriptor on the calling thread",
                &[
                    (["ruleset_fd", "file descriptor of the landlock ruleset"], Normal(File_Descriptor(""))),
                    // must be 0
                    (["flags", "curently no flags supported"], Normal(General_Flag(LandlockRestrictFlag))),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // A sparse file is a file that is mostly empty, 
            // i.e. it contains large blocks of bytes whose value is 0 (zero).
            // On the disk, the content of a file is stored in blocks of fixed size (usually 4 KiB or more). 
            // 
            // When all the bytes contained in such a block are 0, 
            // a file system that supports sparse files will not store the block on disk, 
            // instead it keeps the information somewhere in the file meta-data.
            // 
            // offset and len must be a multiple of the filesystem logical block size,
            Sysno::fallocate,
            (
                DiskIO,
                "modify the allocated disk space for a specific file",
                &[
                    (["fd", "file descriptor of the file to be modified"], Normal(File_Descriptor(""))),
                    (["mode", "disk space modification flags"], Normal(General_Flag(FallocFlags))),
                    (["offset", "offset where the operation starts"], Normal(Length_Of_Bytes_Specific)),
                    (["len", "amount of bytes from the offset to operate on"], Normal(Length_Of_Bytes)),
                 ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            // this is what runs behind the nice command
            Sysno::getpriority,
            (
                Process,
                "get a processes' or user's scheduling priority",
                &[
                    (["which", "type of the target (process/process group/user)"], Normal(General_Flag(PriorityWhich))),
                    (["who", "specific id of the target"], Normal(Numeric)),
                ],
                (["return value", "priority of the process/process group/user. -1 for error and errno modified"], Priority_Or_Errno(MaybeUninit::<bool>::zeroed())),
            )
        ),
        (
            // this is what runs behind the nice command
            Sysno::setpriority,
            (
                Process,
                "increase or decrease processes' or user's scheduling priority",
                &[
                    (["which", "type of the target (process/process group/user)"], Normal(General_Flag(PriorityWhich))),
                    (["who", "specific id of the target"], Normal(Numeric)),
                    (["prio", "new scheduling priority value"], Normal(Unsigned_Numeric)),
                ],
                (["return value", "0 success. -1 for error and errno modified"], Numeric_Or_Errno)
            )
        ),
        (
            Sysno::getdents,
            (
                DiskIO,
                "get the directory entries for a specific directory",
                &[
                    (["fd", "file descriptor of the directory"], Normal(File_Descriptor(""))),
                    (["dirp", "pointer to a buffer where the retrieved directory entries will be stored"], Normal(Pointer_To_Struct)),
                    (["count", "size of the dirp buffer"], Normal(Unsigned_Numeric)),
                ],
                // On end of directory, 0 is returned.
                (["return value", "number of bytes read on success. -1 for error and errno modified"], Length_Of_Bytes_Specific_Or_Errno)
            )
        ),
        (
            // handle large filesystems and large file offsets.
            Sysno::getdents64,
            (
                DiskIO,
                "get the directory entries for a specific directory",
                &[
                    (["fd", "file descriptor of the directory"], Normal(File_Descriptor(""))),
                    (["dirp", "pointer to a buffer where the retrieved directory entries will be stored"], Normal(Pointer_To_Struct)),
                    (["count", "size of the dirp buffer"], Normal(Unsigned_Numeric)),
                ],
                // On end of directory, 0 is returned.
                (["return value", "number of bytes read on success. -1 for error and errno modified"], Length_Of_Bytes_Specific_Or_Errno)
            )
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
    // println!("{} supported", array.len());
    array.into_iter().collect()
}
