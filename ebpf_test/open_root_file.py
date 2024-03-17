from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

int vfs_open_entry(struct pt_regs *ctx, struct file *f, struct inode *inode) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        return 0;
    }
    uid_t uid = __kuid_val(inode->i_uid);
    bpf_trace_printk("Process UID: %u ,File owner UID: %u\n", (cred->euid).val,uid);
    if (uid == 0) {
        bpf_trace_printk("The file owner is root!\n");
    }
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# kprobe를 설치
bpf.attach_kprobe(event="do_dentry_open", fn_name="vfs_open_entry")

# 출력 이벤트를 처리
while 1:
    try :
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task.decode('utf-8', 'replace'), pid, msg.decode('utf-8', 'replace')))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
