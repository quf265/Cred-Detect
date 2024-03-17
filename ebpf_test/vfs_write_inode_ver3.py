from bcc import BPF

program = """
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/uio.h>

BPF_PERF_OUTPUT(events);

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {
    if (file == NULL)
        return 0;

    if (file->f_path.dentry == NULL)
        return 0;

    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    if (d_name.name != NULL) {
        events.perf_submit(ctx, (void*)d_name.name, d_name.len);
    }

    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%s" % (event.data))

b["events"].open_perf_buffer(print_event)

while 1:
    b.perf_buffer_poll()
