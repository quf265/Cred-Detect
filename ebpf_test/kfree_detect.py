from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>

TRACEPOINT_PROBE(kmem, kfree) {
    char name[TASK_COMM_LEN];
    bpf_get_current_comm(&name, sizeof(name));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    bpf_trace_printk("kmem_cache_free: Process %s tgid = %u tid = %u\n", name, pid,tid);
    //bpf_trace_printk("kfree: Process %s freed address %p\n", name, args->call_site);
    return 0;
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
    char name[TASK_COMM_LEN];
    bpf_get_current_comm(&name, sizeof(name));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    bpf_trace_printk("kmem_cache_free: Process %s tgid = %u tid = %u\n", name, pid,tid);
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# 출력 이벤트를 처리
while 1:
    try :
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        if 'open_close' in msg.decode('utf-8'):
            if 'kfree' in msg.decode('utf-8'):
                print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')),'kfree!!')
            if 'kmem_cache_free' in msg.decode('utf-8'):
                print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')),'kmem_cache_free!!')
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
