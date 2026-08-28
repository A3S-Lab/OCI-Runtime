use std::collections::BTreeSet;
use std::str::FromStr;

use super::architecture::SeccompArchitecture;

const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const X86_SOCKETCALL: i64 = 102;
const X86_IPC: i64 = 117;

/// One concrete seccomp syscall target, optionally narrowed to a legacy x86
/// socketcall/ipc selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SyscallTarget {
    pub(super) number: i64,
    pub(super) multiplexer_selector: Option<u64>,
}

pub(super) fn resolve(architecture: SeccompArchitecture, name: &str) -> Vec<SyscallTarget> {
    match architecture {
        SeccompArchitecture::Aarch64 => direct(
            syscalls::aarch64::Sysno::from_str(name)
                .ok()
                .map(|syscall| i64::from(syscall.id())),
        ),
        SeccompArchitecture::X86_64 => direct(
            syscalls::x86_64::Sysno::from_str(name)
                .ok()
                .map(|syscall| i64::from(syscall.id())),
        ),
        SeccompArchitecture::X86 => resolve_x86(name),
        SeccompArchitecture::X32 => direct(resolve_x32(name)),
    }
}

fn direct(number: Option<i64>) -> Vec<SyscallTarget> {
    number
        .map(|number| {
            vec![SyscallTarget {
                number,
                multiplexer_selector: None,
            }]
        })
        .unwrap_or_default()
}

fn resolve_x86(name: &str) -> Vec<SyscallTarget> {
    let mut targets = BTreeSet::new();
    if let Ok(syscall) = syscalls::x86::Sysno::from_str(name) {
        targets.insert(SyscallTarget {
            number: i64::from(syscall.id()),
            multiplexer_selector: None,
        });
    }
    if let Some((number, selector)) = x86_multiplexer(name) {
        targets.insert(SyscallTarget {
            number,
            multiplexer_selector: Some(selector),
        });
    }
    targets.into_iter().collect()
}

fn x86_multiplexer(name: &str) -> Option<(i64, u64)> {
    let target = match name {
        "socket" => (X86_SOCKETCALL, 1),
        "bind" => (X86_SOCKETCALL, 2),
        "connect" => (X86_SOCKETCALL, 3),
        "listen" => (X86_SOCKETCALL, 4),
        "accept" => (X86_SOCKETCALL, 5),
        "getsockname" => (X86_SOCKETCALL, 6),
        "getpeername" => (X86_SOCKETCALL, 7),
        "socketpair" => (X86_SOCKETCALL, 8),
        "send" => (X86_SOCKETCALL, 9),
        "recv" => (X86_SOCKETCALL, 10),
        "sendto" => (X86_SOCKETCALL, 11),
        "recvfrom" => (X86_SOCKETCALL, 12),
        "shutdown" => (X86_SOCKETCALL, 13),
        "setsockopt" => (X86_SOCKETCALL, 14),
        "getsockopt" => (X86_SOCKETCALL, 15),
        "sendmsg" => (X86_SOCKETCALL, 16),
        "recvmsg" => (X86_SOCKETCALL, 17),
        "accept4" => (X86_SOCKETCALL, 18),
        "recvmmsg" => (X86_SOCKETCALL, 19),
        "sendmmsg" => (X86_SOCKETCALL, 20),
        "semop" => (X86_IPC, 1),
        "semget" => (X86_IPC, 2),
        "semctl" => (X86_IPC, 3),
        "semtimedop" => (X86_IPC, 4),
        "msgsnd" => (X86_IPC, 11),
        "msgrcv" => (X86_IPC, 12),
        "msgget" => (X86_IPC, 13),
        "msgctl" => (X86_IPC, 14),
        "shmat" => (X86_IPC, 21),
        "shmdt" => (X86_IPC, 22),
        "shmget" => (X86_IPC, 23),
        "shmctl" => (X86_IPC, 24),
        _ => return None,
    };
    Some(target)
}

fn resolve_x32(name: &str) -> Option<i64> {
    if x32_unavailable(name) {
        return None;
    }
    let number = x32_special_number(name).or_else(|| {
        syscalls::x86_64::Sysno::from_str(name)
            .ok()
            .and_then(|syscall| u32::try_from(syscall.id()).ok())
    })?;
    Some(i64::from(number | X32_SYSCALL_BIT))
}

// X32 uses its own compatibility entry points when pointer-bearing argument
// layouts differ from x86_64. Values follow the Linux x32 syscall table used
// by libseccomp; all other available calls reuse the x86_64 number.
fn x32_special_number(name: &str) -> Option<u32> {
    let number = match name {
        "rt_sigaction" => 512,
        "rt_sigreturn" => 513,
        "ioctl" => 514,
        "readv" => 515,
        "writev" => 516,
        "recvfrom" => 517,
        "sendmsg" => 518,
        "recvmsg" => 519,
        "execve" => 520,
        "ptrace" => 521,
        "rt_sigpending" => 522,
        "rt_sigtimedwait" => 523,
        "rt_sigqueueinfo" => 524,
        "sigaltstack" => 525,
        "timer_create" => 526,
        "mq_notify" => 527,
        "kexec_load" => 528,
        "waitid" => 529,
        "set_robust_list" => 530,
        "get_robust_list" => 531,
        "vmsplice" => 532,
        "move_pages" => 533,
        "preadv" => 534,
        "pwritev" => 535,
        "rt_tgsigqueueinfo" => 536,
        "recvmmsg" => 537,
        "sendmmsg" => 538,
        "process_vm_readv" => 539,
        "process_vm_writev" => 540,
        "setsockopt" => 541,
        "getsockopt" => 542,
        "io_setup" => 543,
        "io_submit" => 544,
        "execveat" => 545,
        "preadv2" => 546,
        "pwritev2" => 547,
        _ => return None,
    };
    Some(number)
}

fn x32_unavailable(name: &str) -> bool {
    matches!(
        name,
        "create_module"
            | "epoll_ctl_old"
            | "epoll_wait_old"
            | "get_kernel_syms"
            | "get_thread_area"
            | "nfsservctl"
            | "query_module"
            | "set_thread_area"
            | "_sysctl"
            | "uselib"
            | "vserver"
    )
}

#[cfg(test)]
mod tests {
    use super::{resolve, SeccompArchitecture, SyscallTarget, X32_SYSCALL_BIT};

    #[test]
    fn x86_socket_and_ipc_names_include_legacy_multiplexers() {
        let socket = resolve(SeccompArchitecture::X86, "socket");
        assert!(socket.contains(&SyscallTarget {
            number: 102,
            multiplexer_selector: Some(1),
        }));
        assert!(socket.contains(&SyscallTarget {
            number: 359,
            multiplexer_selector: None,
        }));

        let accept4 = resolve(SeccompArchitecture::X86, "accept4");
        assert!(accept4.contains(&SyscallTarget {
            number: 102,
            multiplexer_selector: Some(18),
        }));
        assert!(accept4.contains(&SyscallTarget {
            number: 364,
            multiplexer_selector: None,
        }));

        let semop = resolve(SeccompArchitecture::X86, "semop");
        assert!(semop.contains(&SyscallTarget {
            number: 117,
            multiplexer_selector: Some(1),
        }));
    }

    #[test]
    fn x32_uses_compatibility_numbers_and_rejects_absent_calls() {
        assert_eq!(single_x32("read"), i64::from(X32_SYSCALL_BIT));
        assert_eq!(single_x32("execve"), i64::from(X32_SYSCALL_BIT | 520));
        assert_eq!(single_x32("pwritev2"), i64::from(X32_SYSCALL_BIT | 547));
        assert!(resolve(SeccompArchitecture::X32, "get_thread_area").is_empty());
    }

    #[test]
    fn x32_special_table_is_complete_and_unique() {
        let entries = [
            ("rt_sigaction", 512),
            ("rt_sigreturn", 513),
            ("ioctl", 514),
            ("readv", 515),
            ("writev", 516),
            ("recvfrom", 517),
            ("sendmsg", 518),
            ("recvmsg", 519),
            ("execve", 520),
            ("ptrace", 521),
            ("rt_sigpending", 522),
            ("rt_sigtimedwait", 523),
            ("rt_sigqueueinfo", 524),
            ("sigaltstack", 525),
            ("timer_create", 526),
            ("mq_notify", 527),
            ("kexec_load", 528),
            ("waitid", 529),
            ("set_robust_list", 530),
            ("get_robust_list", 531),
            ("vmsplice", 532),
            ("move_pages", 533),
            ("preadv", 534),
            ("pwritev", 535),
            ("rt_tgsigqueueinfo", 536),
            ("recvmmsg", 537),
            ("sendmmsg", 538),
            ("process_vm_readv", 539),
            ("process_vm_writev", 540),
            ("setsockopt", 541),
            ("getsockopt", 542),
            ("io_setup", 543),
            ("io_submit", 544),
            ("execveat", 545),
            ("preadv2", 546),
            ("pwritev2", 547),
        ];
        for (name, number) in entries {
            assert_eq!(
                single_x32(name),
                i64::from(X32_SYSCALL_BIT | number),
                "{name}"
            );
        }
    }

    fn single_x32(name: &str) -> i64 {
        let targets = resolve(SeccompArchitecture::X32, name);
        assert_eq!(targets.len(), 1, "{name}");
        assert_eq!(targets[0].multiplexer_selector, None, "{name}");
        targets[0].number
    }
}
