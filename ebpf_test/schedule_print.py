from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int print_exec_info(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    int cpu = bpf_get_smp_processor_id();
    bpf_trace_printk("Process executing on CPU: %s, CPU ID: %d\n", comm, cpu);
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# kprobe를 설치
bpf.attach_kprobe(event="schedule", fn_name="print_exec_info")

# 출력 이벤트를 처리
while 1:
    try :
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
