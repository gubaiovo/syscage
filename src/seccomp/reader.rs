use anyhow::{bail, Context, Result};
use nix::sys::ptrace::{self, AddressType};
use nix::unistd::Pid;
use std::mem::{offset_of, size_of};

use super::bpf::{FilterProgram, SockFilter, MAX_BPF_INSTRUCTIONS};

fn read_child_bytes(pid: Pid, address: usize, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let word_size = size_of::<libc::c_long>();
    let mut bytes = Vec::with_capacity(len);
    let mut offset = 0usize;

    while offset < len {
        let word = ptrace::read(pid, (address + offset) as AddressType)
            .with_context(|| format!("ptrace read failed at {:#x}", address + offset))?;
        let chunk = word.to_ne_bytes();
        let take = (len - offset).min(word_size);
        bytes.extend_from_slice(&chunk[..take]);
        offset += take;
    }

    Ok(bytes)
}

fn read_filter_program_header(pid: Pid, address: usize) -> Result<FilterProgram> {
    let bytes = read_child_bytes(pid, address, size_of::<libc::sock_fprog>())?;

    let len_offset = offset_of!(libc::sock_fprog, len);
    let ptr_offset = offset_of!(libc::sock_fprog, filter);
    let len_end = len_offset + size_of::<libc::c_ushort>();
    let ptr_end = ptr_offset + size_of::<usize>();

    let len = u16::from_ne_bytes(bytes[len_offset..len_end].try_into().unwrap()) as usize;
    let filter_ptr = usize::from_ne_bytes(bytes[ptr_offset..ptr_end].try_into().unwrap());

    if len == 0 {
        bail!("seccomp program length is zero");
    }
    if len > MAX_BPF_INSTRUCTIONS {
        bail!(
            "seccomp program length {} exceeds kernel limit {}",
            len,
            MAX_BPF_INSTRUCTIONS
        );
    }
    if filter_ptr == 0 {
        bail!("seccomp filter pointer is null");
    }

    Ok(FilterProgram { len, filter_ptr })
}

pub(crate) fn read_filter_program(pid: Pid, address: usize) -> Result<Vec<SockFilter>> {
    let header = read_filter_program_header(pid, address)?;
    let byte_len = header
        .len
        .checked_mul(size_of::<libc::sock_filter>())
        .context("seccomp program size overflowed usize")?;
    let bytes = read_child_bytes(pid, header.filter_ptr, byte_len)?;

    Ok(bytes
        .chunks_exact(size_of::<libc::sock_filter>())
        .map(|chunk| SockFilter::from_bytes(chunk.try_into().unwrap()))
        .collect())
}
