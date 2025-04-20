pub mod Readers_Writers {
    // basically all syscalls that return `ssize_t`
    pub fn parse_return(return_register: u64) -> String {
        // if self.sysno == Sysno::readlink || self.sysno == Sysno::readlinkat {
        //     if self.errno.is_some() {
        //         return Err(());
        //     }
        // }
        format!("{return_register} Bytes")
    }
}
