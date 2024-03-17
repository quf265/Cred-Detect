from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
/*
TRACEPOINT_PROBE(sched, sched_switch) {
    int cpu = bpf_get_smp_processor_id();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    bpf_trace_printk("Previous PID: %d, cur pid: %d cur tid: %d, \n",args->prev_pid, pid,tid);
    //bpf_trace_printk("Previous PID: %d, Next PID: %d cur pid: %d cur tid: %d, CPU ID: %d\n",args->prev_pid, args->next_pid, pid,tid,cpu);                

    return 0;
}
*/

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;
    s32 prev_pid, next_pid;

    char name[TASK_COMM_LEN];
    bpf_get_current_comm(&name, sizeof(name));
    bpf_trace_printk("sched_switch: Process %s sched_switch address \n", name);


/*
    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_probe_read_kernel(&prev_pid, sizeof(prev->pid), &prev->pid);
    bpf_probe_read_kernel(&next_pid, sizeof(next->pid), &next->pid);
    bpf_trace_printk("%d -> %d, %d\\n", prev_tgid, next_tgid,next_pid);
*/
done :
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# 출력 이벤트를 처리
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
