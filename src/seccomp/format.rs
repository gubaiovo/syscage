use std::fmt::Write as _;

use syscalls::Sysno;

use super::bpf::{
    LoadTarget, SockFilter, BPF_ALU_AND_K, BPF_JMP_JA, BPF_JMP_JEQ_K, BPF_JMP_JGE_K,
    BPF_JMP_JGT_K, BPF_JMP_JSET_K, BPF_LD_W_ABS, BPF_RET_K, I386, X86_64,
};

fn describe_load_target(offset: u32) -> (String, Option<LoadTarget>) {
    match offset {
        0 => ("A = sys_number".to_string(), Some(LoadTarget::SyscallNr)),
        4 => ("A = arch".to_string(), Some(LoadTarget::Arch)),
        8 => (
            "A = instruction_pointer_low".to_string(),
            Some(LoadTarget::Generic(offset)),
        ),
        12 => (
            "A = instruction_pointer_high".to_string(),
            Some(LoadTarget::Generic(offset)),
        ),
        value if value >= 16 => {
            let relative = value - 16;
            let arg_index = relative / 8;
            let arg_half = relative % 8;
            if arg_index < 6 && (arg_half == 0 || arg_half == 4) {
                let half = if arg_half == 0 { "low" } else { "high" };
                (
                    format!("A = args[{arg_index}]_{half}"),
                    Some(LoadTarget::Generic(offset)),
                )
            } else {
                (
                    format!("A = seccomp_data[{offset}]"),
                    Some(LoadTarget::Generic(offset)),
                )
            }
        }
        _ => (
            format!("A = seccomp_data[{offset}]"),
            Some(LoadTarget::Generic(offset)),
        ),
    }
}

fn describe_return(k: u32) -> String {
    let action = k & libc::SECCOMP_RET_ACTION_FULL;
    let data = k & libc::SECCOMP_RET_DATA;

    match action {
        libc::SECCOMP_RET_ALLOW => "return ALLOW".to_string(),
        libc::SECCOMP_RET_KILL_PROCESS => "return KILL_PROCESS".to_string(),
        libc::SECCOMP_RET_KILL_THREAD => "return KILL".to_string(),
        libc::SECCOMP_RET_TRAP => format!("return TRAP({data})"),
        libc::SECCOMP_RET_ERRNO => format!("return ERRNO({data})"),
        libc::SECCOMP_RET_TRACE => format!("return TRACE({data})"),
        libc::SECCOMP_RET_LOG => format!("return LOG({data})"),
        libc::SECCOMP_RET_USER_NOTIF => format!("return USER_NOTIF({data})"),
        _ => format!("return RAW({k:#010x})"),
    }
}

fn describe_value(k: u32, load_target: Option<LoadTarget>) -> String {
    match load_target {
        Some(LoadTarget::SyscallNr) => Sysno::new(k as usize)
            .map(|syscall| syscall.name().to_string())
            .unwrap_or_else(|| format!("{k:#x}")),
        Some(LoadTarget::Arch) => match k {
            X86_64 => "ARCH_X86_64".to_string(),
            I386 => "ARCH_I386".to_string(),
            _ => format!("{k:#x}"),
        },
        _ => format!("{k:#x}"),
    }
}

fn describe_conditional_jump(
    line: usize,
    rule: SockFilter,
    positive: String,
    negative: String,
) -> String {
    let true_target = line + 1 + usize::from(rule.jt);
    let false_target = line + 1 + usize::from(rule.jf);

    match (rule.jt, rule.jf) {
        (0, 0) => format!("if ({positive}) continue"),
        (_, 0) => format!("if ({positive}) goto {true_target:04}"),
        (0, _) => format!("if ({negative}) goto {false_target:04}"),
        _ => format!("if ({positive}) goto {true_target:04} else goto {false_target:04}"),
    }
}

pub(crate) fn format_program(rules: &[SockFilter]) -> String {
    let mut output = String::new();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, " line  CODE  JT   JF      K           COMMENT").unwrap();
    writeln!(&mut output, "==============================================================").unwrap();

    if rules.is_empty() {
        writeln!(&mut output, " <empty>").unwrap();
        return output;
    }

    let mut load_target = None;

    for (line, rule) in rules.iter().copied().enumerate() {
        let description = match rule.code {
            BPF_LD_W_ABS => {
                let (description, next_target) = describe_load_target(rule.k);
                load_target = next_target;
                description
            }
            BPF_RET_K => describe_return(rule.k),
            BPF_JMP_JA => format!("goto {:04}", line + 1 + rule.k as usize),
            BPF_JMP_JEQ_K => describe_conditional_jump(
                line,
                rule,
                format!("A == {}", describe_value(rule.k, load_target)),
                format!("A != {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JGE_K => describe_conditional_jump(
                line,
                rule,
                format!("A >= {}", describe_value(rule.k, load_target)),
                format!("A < {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JGT_K => describe_conditional_jump(
                line,
                rule,
                format!("A > {}", describe_value(rule.k, load_target)),
                format!("A <= {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JSET_K => describe_conditional_jump(
                line,
                rule,
                format!("(A & {}) != 0", describe_value(rule.k, load_target)),
                format!("(A & {}) == 0", describe_value(rule.k, load_target)),
            ),
            BPF_ALU_AND_K => format!("A = A & {:#x}", rule.k),
            _ => format!(
                "raw rule: code={:#06x} jt={} jf={} k={:#010x}",
                rule.code, rule.jt, rule.jf, rule.k
            ),
        };

        writeln!(
            &mut output,
            " {:04}: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:08x}  {}",
            line, rule.code, rule.jt, rule.jf, rule.k, description
        )
        .unwrap();
    }

    output
}
