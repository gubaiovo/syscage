use anyhow::Result;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use syscalls::Sysno;
use std::ffi::{CString, CStr};
use libc::user_regs_struct;

const SECCOMP_SET_MODE_FILTER : u64 = 1;

const SECCOMP_RET_KILL  : u32 = 0x80000000;
const SECCOMP_RET_ALLOW : u32 = 0x7fff0000;

const PR_SET_NO_NEW_PRIVS : u64 = 38;

const BPF_LD   : u16 = 0x00;
const BPF_JMP  : u16 = 0x05;
const BPF_RET  : u16 = 0x06;
    
const BPF_W    : u16 = 0x00;

const BPF_ABS  : u16 = 0x20;

const BPF_JA   : u16 = 0x00;
const BPF_JEQ  : u16 = 0x10;
const BPF_JGT  : u16 = 0x20;
const BPF_JGE  : u16 = 0x30;
const BPF_JSET : u16 = 0x40;

const BPF_K    : u16 = 0x00;

struct SockFilter {
    code : u16,
    jt : u8,
    jf : u8,
    k : u32
}

impl SockFilter {
    fn new(rule: u64) -> Self {
        SockFilter { 
            code: (rule & 0xffff) as u16, 
            jt: ((rule >> 16) & 0xff) as u8, 
            jf: ((rule >> 24) & 0xff) as u8, 
            k: (rule >> 32) as u32 
        }
    }
    
    fn create(pid: Pid, address: AddressType) -> Self {
        let rule = ptrace::read(pid, address).unwrap() as u64;
        
        Self::new(rule)
    }
    
    fn create_all(pid: Pid, address: AddressType) -> Vec<Self> {
        let len = ptrace::read(pid, address).unwrap();
        let filter_ptr = ptrace::read(pid, (address as u64 + 8) as AddressType).unwrap() as i64;
        
        (0..len)
            .map(|i| Self::create(pid, (filter_ptr + 8*i) as AddressType))
            .collect()
    }
    
    fn print_raw(self: &Self) {
        println!("{:#06X} {:#04X} {:#04X} {:#010X}", self.code, self.jt, self.jf, self.k);
    }
}

#[allow(unused)]
fn show_rule(rules: &Vec<SockFilter>) {
    
    const BPF_LD_W_ABS   : u16 = BPF_LD | BPF_W | BPF_ABS;
    const BPF_RET_K      : u16 = BPF_RET | BPF_K;
    const BPF_JMP_JA     : u16 = BPF_JMP | BPF_JA;
    const BPF_JMP_JEQ_K  : u16 = BPF_JMP | BPF_JEQ | BPF_K;
    const BPF_JMP_JGE_K  : u16 = BPF_JMP | BPF_JGE | BPF_K;
    const BPF_JMP_JGT_K  : u16 = BPF_JMP | BPF_JGT | BPF_K;
    const BPF_JMP_JSET_K : u16 = BPF_JMP | BPF_JSET | BPF_K;
    

    for line in 0..rules.len() {
        print!("{:6}: ", line);
        
        match rules[line].code {
            BPF_LD_W_ABS => {
                match rules[line].k {
                    0 => {
                        print!("val = syscall number(nr)")  
                    },
                    4 => {
                        print!("val = arch")
                    },
                    _ => unreachable!()
                }
            },
            BPF_RET_K => {
                match rules[line].k {
                    SECCOMP_RET_ALLOW => println!("return allow"),
                    SECCOMP_RET_KILL => print!("return kill"),
                    _ => unreachable!()
                }
            },
            BPF_JMP_JA => {
                print!("jmp {}", line + rules[line].k as usize);
            },
            BPF_JMP_JEQ_K | BPF_JMP_JGE_K | BPF_JMP_JGT_K | BPF_JMP_JSET_K => {
                match rules[line].code & 0xf0 {
                    BPF_JEQ => {
                        todo!()
                    },
                    BPF_JGE => {
                        todo!()
                    },
                    BPF_JGT => {
                        todo!()
                    },
                    BPF_JSET => {
                        todo!()
                    },
                    _ => unreachable!()
                };
            }
            
            _ => unreachable!()
        }
    }
}

fn is_set_no_new_prevs(regs: &user_regs_struct) -> bool {
    regs.rdi == PR_SET_NO_NEW_PRIVS as u64
    && regs.rsi == 1
    && regs.rdx == 0
    && regs.r10 == 0
    && regs.r8 == 0
}



pub fn check(binary: String, args: Vec<String>) -> Result<()> {
    println!("[*] Executing: {}", binary);

    if !args.is_empty() {
        println!("[*] With args: {:?}", args);
    }

    let program: CString = CString::new(binary.as_str()).unwrap();
    let arguments: Vec<CString> = args
                                .iter()
                                .map(|arg| CString::new(arg.as_str()).unwrap())
                                .collect();
    
    let arguments_ref: Vec<&CStr> = arguments
                                .iter()
                                .map(|arg| arg.as_c_str())
                                .collect();
    
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Traceme failed");
            
            execvp(&program, &arguments_ref).unwrap();
        },
        Ok(ForkResult::Parent{ child }) => {
            let pid = child; 
            let mut entering = true;
            println!("Monitoring child process PID: {}", child);
            
            waitpid(pid, None).unwrap();
            
            ptrace::setoptions(
                pid,
                ptrace::Options::PTRACE_O_TRACESYSGOOD
            ).unwrap();
            
            ptrace::syscall(pid, None).unwrap();
            
            loop {
                match waitpid(pid, None).unwrap() {
                    WaitStatus::Exited(_, status) => {
                        println!("Child exit with {}", status);
                        break;
                    },
                    WaitStatus::PtraceSyscall(_) => {
                        if entering {
                            let regs = ptrace::getregs(pid).unwrap();
            
                            if let Some(syscall) = Sysno::new(regs.orig_rax as usize) {
                                // println!("Child tries syscall {}", syscall.name());
                                
                                match syscall {
                                    Sysno::prctl => {
                                        if is_set_no_new_prevs(&regs) {
                                            println!("Clear the prev filter!")
                                        }
                                    },
                                    Sysno::seccomp => {
                                        
                                        let op = regs.rdi;
                                        let flags = regs.rsi;
                                        
                                        if op == SECCOMP_SET_MODE_FILTER as u64 && flags == 0 {
                                            let rules : Vec<SockFilter> = SockFilter::create_all(pid, regs.rdx as AddressType);
                                            
                                            for rule in rules {
                                                rule.print_raw();
                                            }
                                            println!("Seccomp load!")
                                        }
                                    },
                                    _ => {}
                                }
                            }
                        }
            
                        entering = !entering;
                        
                    },
                    _ => {}
                }
                ptrace::syscall(pid, None).unwrap();
            }
            
            
        },
        Err(_) => {
            println!("Fork failed")
        }
    }
    
    
    println!("[!] seccomp extraction not implemented yet");

    Ok(())
}
