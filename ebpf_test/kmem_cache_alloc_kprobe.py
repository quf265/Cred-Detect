from bcc import BPF

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/slab.h>

BPF_HASH(req_size_map, u64, size_t);
BPF_HASH(ret_size_map, u64, size_t);

void kprobe__kmem_cache_alloc(struct pt_regs *ctx, struct kmem_cache *s, gfp_t flags) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    size_t size = s->object_size;
    req_size_map.update(&pid_tgid, &size);
}

void kretprobe__kmem_cache_alloc(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    size_t *req_size = req_size_map.lookup(&pid_tgid);
    if (req_size) {
        size_t ret_size = (size_t)PT_REGS_RC(ctx);
        ret_size_map.update(&pid_tgid, &ret_size);
    }
}
"""

# BPF 프로그램 컴파일 및 로드
b = BPF(text=bpf_text)

# 출력 처리
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        req_size = b["req_size_map"]
        ret_size = b["ret_size_map"]
        for k, v in req_size.items():
            print("%-18.9f %-16s %-6d requested: %zu, allocated: %zu" % (ts, task, pid, v.value, ret_size[k].value))
        req_size.clear()
        ret_size.clear()
    except KeyboardInterrupt:
        exit()
