from bcc import BPF

# BPF 프로그램
prog = """
#include <linux/fs.h>

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // 파일의 inode 정보를 가져옵니다.
    struct inode *inode = file->f_inode;

    // inode 번호를 출력합니다.
    bpf_trace_printk("Writing to inode: %lu\\n", inode->i_ino);
    return 0;
}
"""

# BPF 객체를 만들고 프로그램을 로드합니다.
b = BPF(text=prog)

# vfs_write에 대한 kprobe를 설정합니다.
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")

# 이벤트를 출력하는 루프입니다.
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        message = msg.decode('utf-8')
        #print(message)
        if '1321593' in message:
            print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        exit()
