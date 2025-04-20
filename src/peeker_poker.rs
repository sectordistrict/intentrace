// file is called peeker poker
// because it's the lingo[1] that ptrace
// uses to refer to reading/writing
// from/to a tracee's memory
//
// [1]: https://en.wikipedia.org/wiki/PEEK_and_POKE
//
#[cfg(target_pointer_width = "32")]
pub const WORD_SIZE: usize = 4;

#[cfg(target_pointer_width = "64")]
pub const WORD_SIZE: usize = 8;

use std::{ffi::c_void, io::IoSliceMut, num::NonZeroUsize};

use nix::{
    libc::{cpu_set_t, CPU_ISSET, CPU_SETSIZE},
    sys::{
        ptrace,
        uio::{process_vm_readv, RemoteIoVec},
    },
    unistd::Pid,
};

pub fn read_bytes<const N: usize>(addr: usize, child: Pid) -> Option<[u8; N]> {
    let mut base = addr;
    let remote_iov = RemoteIoVec { base, len: N };
    // TODO!
    // consider large array sizes
    let mut bytes_buffer = [0u8; N];
    match process_vm_readv(
        child,
        &mut [IoSliceMut::new(&mut bytes_buffer)],
        &[remote_iov],
    ) {
        Ok(_) => Some(bytes_buffer),
        Err(err) => {
            p!(err);
            None
        }
    }
}

pub fn read_bytes_variable_length(base: usize, child: Pid, len: usize) -> Option<Vec<u8>> {
    let remote_iov = RemoteIoVec { base, len };
    let mut bytes_buffer = vec![0u8; len];
    // Note, however, that these system calls
    // do not check the memory regions in the remote process
    // until just before doing the read/write.
    // Consequently, a partial read/write (see RETURN VALUE) may result
    // if one of the remote_iov elements points to an invalid memory region in the remote process.
    // No further reads/writes will be attempted beyond that point.
    //
    // Keep this in mind when attempting to read data of unknown length
    // (such as C strings that are null-terminated) from a remote process,
    // by avoiding spanning memory pages (typically 4 KiB)
    // in a single remote iovec element.
    // (Instead, split the remote read into two remote_iov elements
    // and have them merge back into a single write local_iov entry.
    // The first read entry goes up to the page boundary,
    match process_vm_readv(
        child,
        &mut [IoSliceMut::new(&mut bytes_buffer)],
        &[remote_iov],
    ) {
        Ok(_) => Some(bytes_buffer),
        Err(err) => None,
    }
}

pub fn read_bytes_as_struct<const N: usize, T>(addr: usize, child: Pid) -> Option<T> {
    match read_bytes::<N>(addr, child) {
        Some(vec) => {
            let arr: [u8; N] = vec.try_into().unwrap();
            Some(unsafe { std::mem::transmute_copy(&arr) })
        }
        None => None,
    }
    // match SyscallObject::read_bytes::<N>(addr, child) {
    //     Some(bytes) => Some(unsafe { std::mem::transmute_copy(&bytes) }),
    //     None => None,
    // }
}

pub fn read_one_word(address: usize, child: Pid) -> Option<usize> {
    let remote_iov = RemoteIoVec {
        base: address,
        len: 1,
    };
    let mut bytes_buffer = vec![0u8; 4];
    match process_vm_readv(
        child,
        &mut [IoSliceMut::new(&mut bytes_buffer)],
        &[remote_iov],
    ) {
        Ok(_) => Some(unsafe { std::mem::transmute(&bytes_buffer) }),
        Err(err) => None,
    }
}

pub fn read_bytes_until_null(address: usize, child: Pid) -> Option<Vec<u8>> {
    let mut address = address as *mut c_void;
    let mut data = vec![];
    'read_loop: loop {
        match ptrace::read(child, address) {
            Ok(word) => {
                let bytes: [u8; WORD_SIZE] = unsafe { std::mem::transmute(word) };
                for byte in bytes {
                    if byte == b'\0' {
                        break 'read_loop;
                    }
                    data.push(byte);
                }
                address = unsafe { address.byte_add(8) };
            }
            Err(res) => {
                return None;
            }
        };
    }
    Some(data)
}

// usually used to resolve array of pointers to *
pub fn read_words_until_null(address: usize, child: Pid) -> Option<Vec<usize>> {
    let mut addr = address as *mut c_void;
    let mut data = vec![];
    'read_loop: loop {
        match ptrace::read(child, addr) {
            Ok(word) => {
                if word == 0 {
                    break 'read_loop;
                }
                data.push(word as usize);
                addr = unsafe { addr.byte_add(WORD_SIZE) };
            }
            Err(err) => return Some(data),
        };
    }
    Some(data)
}

//
//
//
//
//
//
//

pub fn read_affinity_from_child(address: usize, child: Pid) -> Option<Vec<usize>> {
    const CPU_SET_USIZE: usize = (CPU_SETSIZE / WORD_SIZE as i32) as usize;

    let cpu_set = read_bytes_as_struct::<CPU_SET_USIZE, cpu_set_t>(address, child).unwrap();

    let mut vec = Vec::new();
    for cpu_number in 0..std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1) as usize
    {
        if unsafe { CPU_ISSET(cpu_number, &cpu_set) } {
            vec.push(cpu_number)
        }
    }
    Some(vec)
}



pub fn read_string_specific_length(
    addr: usize,
    child: Pid,
    size: usize,
) -> Option<String> {
    let bytes_buffer = read_bytes_variable_length(addr, child, size)?;
    Some(String::from_utf8_lossy(&bytes_buffer).into_owned())
}


//
//
//
//
//
//

pub fn write_bytes<const N: usize>(addr: usize, child: Pid, data: [u64; N]) -> Result<(), ()> {
    let mut addr = addr as *mut c_void;
    for word in data {
        match ptrace::write(child, addr, word as _) {
            Ok(_void) => {
                addr = unsafe { addr.byte_add(8) };
            }
            Err(res) => return Err(()),
        };
    }
    Ok(())
}
