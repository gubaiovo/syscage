mod bpf;
mod format;
mod reader;

use anyhow::{bail, Context, Result};
use libc::user_regs_struct;
use nix::sys::ptrace::{self};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::{CStr, CString};
use syscalls::Sysno;

use self::bpf::{InstallSource, SockFilter};
use self::format::format_program;
use self::reader::read_filter_program;

fn build_argv(program: &CString, args: &[String]) -> Result<Vec<CString>> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.clone());
    for arg in args {
        argv.push(CString::new(arg.as_str()).context("argument contains NUL byte")?);
    }
    Ok(argv)
}

fn print_seccomp_program(source: InstallSource, rules: &[SockFilter]) {
    println!();
    println!("=== Seccomp filter detected ===");
    println!("Source: {}", source.describe());
    print!("{}", format_program(rules));
    println!("Status: loaded");
}

fn trace_syscall_entry(
    pid: Pid,
    regs: &user_regs_struct,
) -> Result<Option<(InstallSource, Vec<SockFilter>)>> {
    let Some(syscall) = Sysno::new(regs.orig_rax as usize) else {
        return Ok(None);
    };

    match syscall {
        Sysno::prctl
            if regs.rdi == libc::PR_SET_SECCOMP as u64
                && regs.rsi == libc::SECCOMP_MODE_FILTER as u64 =>
        {
            let rules = read_filter_program(pid, regs.rdx as usize)?;
            Ok(Some((InstallSource::Prctl, rules)))
        }
        Sysno::seccomp if regs.rdi == libc::SECCOMP_SET_MODE_FILTER as u64 => {
            let rules = read_filter_program(pid, regs.rdx as usize)?;
            Ok(Some((InstallSource::Seccomp { flags: regs.rsi }, rules)))
        }
        _ => Ok(None),
    }
}

fn child_exec(program: &CString, args: &[CString]) -> ! {
    let argv: Vec<&CStr> = args.iter().map(CString::as_c_str).collect();

    if let Err(err) = ptrace::traceme() {
        eprintln!("ptrace(TRACEME) failed: {err}");
        unsafe {
            libc::_exit(1);
        }
    }

    let err = execvp(program, &argv).expect_err("execvp only returns on failure");
    eprintln!("execvp failed: {err}");
    unsafe {
        libc::_exit(127);
    }
}

pub fn check(binary: String, args: Vec<String>) -> Result<()> {
    println!("[*] Executing: {binary}");
    if !args.is_empty() {
        println!("[*] With args: {args:?}");
    }

    let program = CString::new(binary.as_str()).context("binary path contains NUL byte")?;
    let argv = build_argv(&program, &args)?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => child_exec(&program, &argv),
        ForkResult::Parent { child } => trace_child(child),
    }
}

fn trace_child(pid: Pid) -> Result<()> {
    println!("Monitoring child process PID: {pid}");

    match waitpid(pid, None).context("failed to wait for child startup")? {
        WaitStatus::Stopped(_, _)
        | WaitStatus::PtraceEvent(_, _, _)
        | WaitStatus::PtraceSyscall(_) => {}
        WaitStatus::Exited(_, status) => {
            bail!("child exited before tracing started with status {status}");
        }
        WaitStatus::Signaled(_, signal, _) => {
            bail!("child died before tracing started with signal {signal:?}");
        }
        status => {
            bail!("unexpected child startup status: {status:?}");
        }
    }

    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)
        .context("failed to configure ptrace options")?;
    ptrace::syscall(pid, None).context("failed to resume child after startup stop")?;

    let mut entering_syscall = true;
    let mut trace_errors = Vec::new();

    loop {
        match waitpid(pid, None).context("waitpid failed while tracing child")? {
            WaitStatus::Exited(_, status) => {
                println!("Child exit with {status}");
                break;
            }
            WaitStatus::Signaled(_, signal, _) => {
                println!("Child killed by {signal:?}");
                break;
            }
            WaitStatus::PtraceSyscall(_) => {
                if entering_syscall {
                    match ptrace::getregs(pid).context("failed to fetch child registers") {
                        Ok(regs) => match trace_syscall_entry(pid, &regs) {
                            Ok(Some((source, rules))) => print_seccomp_program(source, &rules),
                            Ok(None) => {}
                            Err(err) => trace_errors.push(format!("{err:#}")),
                        },
                        Err(err) => trace_errors.push(format!("{err:#}")),
                    }
                }
                entering_syscall = !entering_syscall;
            }
            WaitStatus::Stopped(_, signal) => {
                if signal != Signal::SIGTRAP {
                    ptrace::syscall(pid, Some(signal))
                        .with_context(|| format!("failed to deliver signal {signal:?} to child"))?;
                    continue;
                }
            }
            WaitStatus::Continued(_) | WaitStatus::StillAlive | WaitStatus::PtraceEvent(_, _, _) => {}
        }

        match ptrace::syscall(pid, None) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => break,
            Err(err) => return Err(err).context("failed to resume child with PTRACE_SYSCALL"),
        }
    }

    if trace_errors.is_empty() {
        Ok(())
    } else {
        bail!("tracing completed with errors:\n{}", trace_errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bpf::{
            InstallSource, SockFilter, BPF_JMP_JEQ_K, BPF_JMP_JSET_K, BPF_LD_W_ABS, BPF_RET_K,
        },
        build_argv,
        format::format_program,
    };
    use std::ffi::CString;

    #[test]
    fn build_argv_includes_program_as_argv0() {
        let program = CString::new("/tmp/prog").unwrap();
        let argv = build_argv(&program, &[String::from("alpha"), String::from("beta")]).unwrap();

        let rendered: Vec<&str> = argv.iter().map(|arg| arg.to_str().unwrap()).collect();
        assert_eq!(rendered, vec!["/tmp/prog", "alpha", "beta"]);
    }

    #[test]
    fn format_program_handles_jset_with_bitmask_semantics() {
        let rules = [
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP_JSET_K,
                jt: 1,
                jf: 0,
                k: 0x4000_0000,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        let output = format_program(&rules);
        assert!(output.contains("0000: 0x20 0x00 0x00 0x00000004  A = arch"));
        assert!(output.contains("if ((A & 0x40000000) != 0) goto 0003"));
    }

    #[test]
    fn format_program_keeps_branch_targets_wide() {
        let mut rules = Vec::new();
        for _ in 0..260 {
            rules.push(SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            });
        }
        rules[258] = SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: 1,
        };

        let output = format_program(&rules);
        assert!(output.contains("0258: 0x15 0x01 0x00 0x00000001  if (A == 0x1) goto 0260"));
    }

    #[test]
    fn install_source_describes_flags() {
        let description = InstallSource::Seccomp {
            flags: libc::SECCOMP_FILTER_FLAG_TSYNC | libc::SECCOMP_FILTER_FLAG_LOG,
        }
        .describe();

        assert!(description.contains("TSYNC"));
        assert!(description.contains("LOG"));
    }

    #[test]
    fn filter_program_header_reads_only_len_and_pointer_bytes() {
        let len = 1u16;
        let filter_ptr = 0x1122_3344_5566_7788usize;
        let mut bytes = vec![0x41u8; std::mem::size_of::<libc::sock_fprog>()];

        let len_offset = std::mem::offset_of!(libc::sock_fprog, len);
        let ptr_offset = std::mem::offset_of!(libc::sock_fprog, filter);

        bytes[len_offset..len_offset + std::mem::size_of::<u16>()]
            .copy_from_slice(&len.to_ne_bytes());
        bytes[ptr_offset..ptr_offset + std::mem::size_of::<usize>()]
            .copy_from_slice(&filter_ptr.to_ne_bytes());

        let parsed_len =
            u16::from_ne_bytes(bytes[len_offset..len_offset + 2].try_into().unwrap()) as usize;
        let parsed_ptr = usize::from_ne_bytes(
            bytes[ptr_offset..ptr_offset + std::mem::size_of::<usize>()]
                .try_into()
                .unwrap(),
        );

        assert_eq!(parsed_len, 1);
        assert_eq!(parsed_ptr, filter_ptr);
    }
}
