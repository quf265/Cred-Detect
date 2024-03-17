from bcc import BPF

# BPF 프로그램
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>

#define SCHED_ON 1
#define SCHED_OFF 0

struct process_syscall_info{
    //스케줄러 관련
    u64 sched_status;         //현재 cpu에서 돌고있는 상태인지
    u64 prev_cpu_number;
    u64 cpu_similar;   //동일한 시피유에서 많이 돌고 있는지 확인
    u32 start_time;
    u32 end_time;

    u64 dangerous_start;  //위험한 조건에 부합하게 cpu에서 행동
    u64 sched_count;      //위험한 상태에서 몇번 cpu에서 돌았는지 확인

    //시스템콜 관련
    u64 syscall_count; //시스템콜 몇번불렀는지
    u64 syscall_vel;   //시스템콜 호출 속도
    u64 syscall_argument_similar; //유사한 인자를 넣어서 시스템콜을 호출하였는지 확인
    u64 prev_syscall_number;    //직전 호출한 시스템콜 기록
    u64 syscall_kind_similar;   //시스템콜 유사도

    //kernel memory 관련
    u64 prev_kmalloc;           //직전 kmalloc slab크기
    u64 kmalloc_similar;        //kmalloc 유사도
    u64 kmalloc_count;             

    u64 prev_kmem_cache;
    u64 kmem_cache_similar;
    u64 kmem_cache_count;

    //root파일 open 및 free여부
    u64 does_open_root_file;
    u64 does_free_root_file;

    u64 root_file_address;

    //출력용
    char task_name[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
    u32 prev_or_next;
};

BPF_HASH(data_process_syscall_info, u64, struct process_syscall_info);
BPF_HASH(data_first_check, u32, u32);


RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;
    s32 prev_pid, next_pid;
    u64 prev_pid_tgid, next_pid_tgid;
    u32 * first_check, zero_first_check = 10;
    int key_first_check = 50;
    first_check = data_first_check.lookup_or_try_init(&key_first_check,&zero_first_check);
    if(first_check)
    {
        if(*first_check == 10)
        {
            *first_check = 20;
        }
        else
        {
            goto done;
        }
    }
    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_probe_read_kernel(&prev_pid, sizeof(prev->pid), &prev->pid);
    bpf_probe_read_kernel(&next_pid, sizeof(next->pid), &next->pid);

    prev_pid_tgid = prev_tgid;
    prev_pid_tgid = prev_pid_tgid << 32;
    prev_pid_tgid |= prev_pid;
    next_pid_tgid = next_tgid;
    next_pid_tgid = next_pid_tgid << 32;
    next_pid_tgid |= next_pid;

    struct process_syscall_info * prev_val_process_syscall_info, * next_val_process_syscall_info,zero_val_process_syscall_info = {};
    next_val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&next_pid_tgid, &zero_val_process_syscall_info);

    if(next_val_process_syscall_info)
    {
        next_val_process_syscall_info->sched_status = SCHED_ON;
        next_val_process_syscall_info->pid = next_tgid;
        next_val_process_syscall_info->tid = next_pid;
        next_val_process_syscall_info->prev_or_next = 1;
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str(next_val_process_syscall_info->task_name,sizeof(name),name);

    }
    prev_val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&prev_pid_tgid, &zero_val_process_syscall_info);
    if(prev_val_process_syscall_info)
    {
        prev_val_process_syscall_info->sched_status = SCHED_OFF;
        prev_val_process_syscall_info->pid = prev_tgid;
        prev_val_process_syscall_info->tid = prev_pid;
        prev_val_process_syscall_info->prev_or_next = 0;
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str(prev_val_process_syscall_info->task_name,sizeof(name),name);
    }
done :
    return 0;
}
"""

# BPF 객체를 초기화
bpf = BPF(text=BPF_PROGRAM)

# 출력 이벤트를 처리
while 1:
    try :
        data = bpf['data_process_syscall_info']
        for k, v in data.items_lookup_and_delete_batch():
            write_data = [v.pid,v.tid,v.prev_or_next,v.task_name]
            print(write_data)
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
