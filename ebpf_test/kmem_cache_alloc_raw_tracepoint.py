from bcc import BPF

# BPF 프로그램 정의
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/slab.h>

BPF_HASH(req_size_map, u64, size_t);
BPF_HASH(ret_size_map, u64, size_t);

RAW_TRACEPOINT_PROBE(kmem_cache_alloc)
{
    struct kmem_cache * kmem_cache_object = (struct kmem_cache *)ctx->args[2];

    u64 bytes_req = kmem_cache_object->object_size;
    u64 bytes_alloc = kmem_cache_object->size;
    bpf_trace_printk("%u %uhello",bytes_req, bytes_alloc);
    return 0;
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

