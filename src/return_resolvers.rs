pub mod Readers_Writers {
    // basically all syscalls that return `ssize_t`
    pub fn parse_return(return_register: u64) -> String {
        format!("{return_register} Bytes")
    }
}
