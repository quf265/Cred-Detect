#2024.1.26
#설명
#모든 프로세스에 대해서 uid, suid, euid가 0으로바뀔경우 출력함
#ver4는 euid == 0인 process에 대해서는 검사를 수행하지 않는 것으로 진행 예정
#root권한으로 변경된 것을 잡음
#6버전에서 1버전은 기존 data_cred객체를 안비우는 것으로 진행해봄

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import csv
import time

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)

text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>
//cred 객체 정보
struct cred_data{

    char task_name[TASK_COMM_LEN];
    u32 is_not_root;
    u32 confirm_setuid;        //확인중인 data 표시
    u32 confirm;                //검사 중이라는 뜻
    u32 from_sys_enter;
    u32 cur_sys_enter;          //혹시 sys_enter일때 찍히는지 알고 싶어서

    u32 pid;
    u32 tid;

    kuid_t prev_uid;
    kuid_t prev_suid;
    kuid_t prev_euid;

    kuid_t uid;
    kuid_t suid;
    kuid_t euid;

    u32 chuid;
    u32 chsuid;
    u32 cheuid;

    u32 syscall_number;
    u32 dangerous;      //위험한 data 표시
    u32 call_count;
};

struct cred_data_dangerous
{
    char task_name[TASK_COMM_LEN];
    u32 confirm;        //setuid가 사용된 상태
    u32 cur_sys_enter;

    u32 pid;
    u32 tid;

    kuid_t prev_uid;
    kuid_t prev_suid;
    kuid_t prev_euid;

    kuid_t uid;
    kuid_t suid;
    kuid_t euid;

    u32 chuid;
    u32 chsuid;
    u32 cheuid;
    
    u32 syscall_number;
    u32 dangerous;
    u32 cred_data_call_count;
};

//args error를 감지하기 위해서 넣는 구조체
struct cred_args_error
{
    u32 pid;
    u32 tid;
    
    u32 syscall_number_enter;
    u32 syscall_number_exit;

    u32 confirm; //exit부터 시작한 애가 있을 수 있음 enter부터 시작했냐는 뜻임
};
struct cred_args_error_dangerous
{
    u32 pid;
    u32 tid;

    u32 syscall_number_enter;
    u32 syscall_number_exit;
};

//아래는 cred 객체를 확인하는 것과 관련된 hash_map들
BPF_HASH(data_pid_cred_data, u64 , struct cred_data);
BPF_HASH(data_pid_cred_data_dangerous, u64 , struct cred_data_dangerous);


TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_args_error * val_cred_args_error, zero_cred_args_error = {};
    val_cred_data = data_pid_cred_data.lookup_or_try_init(&pid_tgid, &zero_cred_data);
    if(val_cred_data)
    {   
        val_cred_data->call_count += 1;
        val_cred_data->is_not_root = 1;
        val_cred_data->from_sys_enter = 1;
        val_cred_data->prev_euid = (kuid_t)cred->euid;
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_data_dangerous * val_cred_data_dangerous, zero_cred_data_dangerous={};
    struct cred_args_error * val_cred_args_error, zero_cred_args_error = {};
    struct cred_args_error_dangerous * val_cred_args_error_dangerous, zero_cred_args_error_dangerous = {};

    val_cred_data = data_pid_cred_data.lookup_or_try_init(&pid_tgid, &zero_cred_data);
    if(val_cred_data)
    {   
        if(val_cred_data->is_not_root == 0)
        {
            data_pid_cred_data.delete(&pid_tgid);
            goto done;
        }
        if(val_cred_data->from_sys_enter == 0)
        {
            data_pid_cred_data.delete(&pid_tgid);
            goto done;
        }
        val_cred_data->call_count += 3;
        if((cred->euid).val == 0) //euid가 root로 변경되었음
        {
            val_cred_data->dangerous = 1;
            val_cred_data->cheuid = 1;
            val_cred_data->euid = (kuid_t)cred->euid;
        }

        if(val_cred_data->dangerous != 0)
        {
            val_cred_data_dangerous = data_pid_cred_data_dangerous.lookup_or_try_init(&pid_tgid, &zero_cred_data_dangerous);
            if(val_cred_data_dangerous)
            {
                val_cred_data_dangerous->pid = pid;
                val_cred_data_dangerous->tid = tid;
                val_cred_data_dangerous->dangerous = 1;
                char name[TASK_COMM_LEN];
                bpf_get_current_comm(&name, sizeof(name));
                bpf_probe_read_str((char *)val_cred_data_dangerous->task_name,sizeof(name),name);
                val_cred_data_dangerous->cur_sys_enter += 1;
                val_cred_data_dangerous->syscall_number = args->id;
                val_cred_data_dangerous->prev_euid = val_cred_data->prev_euid;
                val_cred_data_dangerous->cheuid = val_cred_data->cheuid;
                //val_cred_data->dangerous = 0;
                val_cred_data_dangerous->cred_data_call_count = val_cred_data->call_count;
                //data_pid_cred_data.delete(&pid_tgid);
                val_cred_data->from_sys_enter = 0;
                if(val_cred_data->call_count > 210)
                {
                    data_pid_cred_data.delete(&pid_tgid);
                }
            }
        }
        else
        {
            data_pid_cred_data.delete(&pid_tgid);
        }
    }

done :
    return 0;
}

"""

bpf = BPF(text=text)

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

def print_cred_stat():
    data_cred_dangerous = bpf['data_pid_cred_data_dangerous']
    is_alert = 0
    global print_type
    global first_time
    global is_print
    check = 0
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    for k, v in data_cred_dangerous.items_lookup_and_delete_batch():
        process_name= (v.task_name).decode('utf-8')
        write_data = [print_type,v.cur_sys_enter,v.pid, v.tid, v.cred_data_call_count, syscall_name(v.syscall_number).decode('utf-8'),process_name,v.dangerous,v.prev_uid.val,v.uid.val,v.prev_suid.val, v.suid.val, v.prev_euid.val, v.euid.val ,v.chuid, v.chsuid, v.cheuid, cur_time,'dangerous_cred2' ]
        print(write_data)
        is_print = 1
        check = 1
    if check == 1:
        print_type += 1

print_type = 0
is_print = 0
first_time = 0
exiting = 0
print('start')
while True:
    try:
        print_cred_stat()
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if exiting:
        print("Detaching...")
        exit()