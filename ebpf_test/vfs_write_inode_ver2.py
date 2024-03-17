#ver2는 i_mode를 이용해서 파일의 권한을 검사하지만 2_2는 root파일을 사용자영역에서 리스트를 만들고 관리한다.
#ver2는 i_mode값과 유저의 권한을 비교한다.

from bcc import BPF
import time
from bcc.syscall import syscall_name, syscalls

# BPF 프로그램
prog = """
#include <linux/fs.h>

struct cred_data{
    char task_name[TASK_COMM_LEN];
    u32 is_not_root;
    u32 confirm_setuid;        //확인중인 data 표시
    u32 confirm;                //검사 중이라는 뜻
    u32 from_sys_enter;

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

    u64 i_ino;

    u32 syscall_number;
    u32 dangerous;      //위험한 data 표시
};

struct root_file_data{
    char file_name[256];
    u64 prev_i_ino;
    u64 i_ino;
};

BPF_HASH(hash_cred_data,u64,struct cred_data);
BPF_HASH(hash_root_file_data,u64,struct root_file_data);


int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct inode *inode = file->f_inode;
    struct dentry *dentry = file->f_path.dentry;

    struct cred_data * val_cred_data, val_cred_data_zero = {};
    struct root_file_data * val_root_file_data, val_root_file_data_zero = {};

    val_cred_data = hash_cred_data.lookup_or_try_init(&pid_tgid, &val_cred_data_zero);
    val_root_file_data = hash_root_file_data.lookup_or_try_init(&(inode->i_ino)),val_root_file_data_zero);

    if(val_cred_data)
    {
        val_cred_data->pid = pid;
        val_cred_data->tid = tid;
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char *)val_cred_data->task_name,sizeof(name),name);
        val_cred_data->prev_uid = val_cred_data->uid = (kuid_t)cred->uid;
        val_cred_data->prev_suid = val_cred_data->suid = (kuid_t)cred->suid;
        val_cred_data->prev_euid = val_cred_data->euid = (kuid_t)cred->euid;
        val_cred_data->i_ino = inode->i_ino;
    }
    return 0;
}
"""

# BPF 객체를 만들고 프로그램을 로드합니다.
bpf = BPF(text=prog)

# vfs_write에 대한 kprobe를 설정합니다.
#b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
print_type = 0
is_print = 0
first_time = 0

def print_who_write():
    cred_data = bpf["hash_cred_data"]
    is_alert = 0
    global print_type
    global first_time
    global is_print
    check = 0
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    #print(data_kmalloc.items())
    for k, v in cred_data.items_lookup_and_delete_batch():
        process_name= (v.task_name).decode('utf-8')
        #print(v.i_ino)
        if v.i_ino == 1321637:
            write_data =[]
            write_data = [print_type,v.pid, v.tid, v.syscall_number, syscall_name(v.syscall_number).decode('utf-8'),process_name,v.dangerous,v.prev_uid.val,v.uid.val,v.prev_suid.val, v.suid.val, v.prev_euid.val, v.euid.val ,v.chuid, v.chsuid, v.cheuid, cur_time,'real_poc' ]
            print(write_data)
            #writer.writerow(write_data)
            is_print = 1
            check = 1
    if check == 1:
        print_type += 1

# 이벤트를 출력하는 루프입니다.
while True:
    try:
        print_who_write()
    except KeyboardInterrupt:
        exit()
