use std::mem::size_of;

pub(crate) const X86_64: u32 = 0xc000_003e;
pub(crate) const I386: u32 = 0x4000_0003;

pub(crate) const BPF_LD: u16 = 0x00;
pub(crate) const BPF_ALU: u16 = 0x04;
pub(crate) const BPF_JMP: u16 = 0x05;
pub(crate) const BPF_RET: u16 = 0x06;

pub(crate) const BPF_W: u16 = 0x00;
pub(crate) const BPF_ABS: u16 = 0x20;
pub(crate) const BPF_AND: u16 = 0x50;

pub(crate) const BPF_JA: u16 = 0x00;
pub(crate) const BPF_JEQ: u16 = 0x10;
pub(crate) const BPF_JGT: u16 = 0x20;
pub(crate) const BPF_JGE: u16 = 0x30;
pub(crate) const BPF_JSET: u16 = 0x40;

pub(crate) const BPF_K: u16 = 0x00;

pub(crate) const BPF_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
pub(crate) const BPF_RET_K: u16 = BPF_RET | BPF_K;
pub(crate) const BPF_JMP_JA: u16 = BPF_JMP | BPF_JA;
pub(crate) const BPF_JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
pub(crate) const BPF_JMP_JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
pub(crate) const BPF_JMP_JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K;
pub(crate) const BPF_JMP_JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
pub(crate) const BPF_ALU_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;

pub(crate) const MAX_BPF_INSTRUCTIONS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoadTarget {
    SyscallNr,
    Arch,
    Generic(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SockFilter {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

impl SockFilter {
    pub(crate) fn from_bytes(bytes: [u8; size_of::<libc::sock_filter>()]) -> Self {
        Self {
            code: u16::from_ne_bytes([bytes[0], bytes[1]]),
            jt: bytes[2],
            jf: bytes[3],
            k: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FilterProgram {
    pub(crate) len: usize,
    pub(crate) filter_ptr: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InstallSource {
    Seccomp { flags: u64 },
    Prctl,
}

impl InstallSource {
    pub(crate) fn describe(self) -> String {
        match self {
            Self::Prctl => "prctl(PR_SET_SECCOMP)".to_string(),
            Self::Seccomp { flags: 0 } => {
                "seccomp(SECCOMP_SET_MODE_FILTER, flags=0)".to_string()
            }
            Self::Seccomp { flags } => {
                format!(
                    "seccomp(SECCOMP_SET_MODE_FILTER, flags={flags:#x} [{}])",
                    describe_seccomp_flags(flags)
                )
            }
        }
    }
}

pub(crate) fn describe_seccomp_flags(flags: u64) -> String {
    let mut names = Vec::new();

    if flags & libc::SECCOMP_FILTER_FLAG_TSYNC != 0 {
        names.push("TSYNC");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_LOG != 0 {
        names.push("LOG");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW != 0 {
        names.push("SPEC_ALLOW");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
        names.push("NEW_LISTENER");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0 {
        names.push("TSYNC_ESRCH");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0 {
        names.push("WAIT_KILLABLE_RECV");
    }

    if names.is_empty() {
        "unknown".to_string()
    } else {
        names.join(", ")
    }
}
