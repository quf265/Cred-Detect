from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

TRACEPOINT_PROBE(kmem, kmalloc) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("kmalloc request from: %s, requested size: %lu, actual size: %lu\n", comm, args->bytes_req, args->bytes_alloc);
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# 출력 이벤트를 처리
while 1:
    try :
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
