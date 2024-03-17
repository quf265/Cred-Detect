from bcc import BPF

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/slab.h>

void kprobe__kmem_cache_alloc(struct pt_regs *ctx, struct kmem_cache *s, gfp_t flags) {
    bpf_trace_printk("kmem_cache_alloc called by %pS\\n", (void *)ctx->ip);
}

void kprobe____kmalloc(struct pt_regs *ctx, size_t size, gfp_t flags) {
    bpf_trace_printk("kmalloc called by %pS\\n", (void *)ctx->ip);
}
"""

# BPF 프로그램 컴파일 및 로드
b = BPF(text=bpf_text)

# 출력 처리
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        exit()
