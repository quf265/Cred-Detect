from bcc import BPF

program = """
#include <linux/fs.h>
#include <linux/uio.h>

struct data_t {
    unsigned long ino;
};

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(events_probe);
int trace_vfs_write(struct pt_regs *ctx) {
    struct data_t data = {};
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);

    if (file == NULL)
    {
        data.ino = 7777;
        events_probe.perf_submit(ctx,&data,sizeof(data));
        return 0;
    }
    else if(file->f_inode == NULL)
    {
        data.ino = 8888;
        events_probe.perf_submit(ctx,&data,sizeof(data));
        return 0;
    }
    data.ino = file->f_inode->i_ino;

    events_probe.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_vfs_write_return(struct pt_regs *ctx) {
    struct data_t data = {};
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);

    if (file == NULL)
    {
        data.ino = 7777;
        //events.perf_submit(ctx,&data,sizeof(data));
        return 0;
    }
    else if(file->f_inode == NULL)
    {
        data.ino = 8888;
        //events.perf_submit(ctx,&data,sizeof(data));
        return 0;
    }
    data.ino = file->f_inode->i_ino;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
b.attach_kretprobe(event="vfs_write", fn_name="trace_vfs_write_return")
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("Inode number: %d" % event.ino)

def print_event_probe(cpu, data, size):
    event_probe = b["events_probe"].event(data)
    print("Inode number: %d" % event_probe.ino);

b["events"].open_perf_buffer(print_event)
b["events_probe"].open_perf_buffer(print_event_probe)

while 1:
    b.perf_buffer_poll()

