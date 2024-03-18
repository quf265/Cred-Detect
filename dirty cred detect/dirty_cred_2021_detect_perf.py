#ver2는 i_mode를 이용해서 파일의 권한을 검사하지만 2_2는 root파일을 사용자영역에서 리스트를 만들고 관리한다.

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

struct file_data{
    char file_name[80];
    char task_name[TASK_COMM_LEN];

    u32 pid;
    u32 tid;

    u64 i_ino;
    kuid_t file_uid;  //소유 uid
    kgid_t file_gid;  //소유 gid

    kuid_t uid;
    kuid_t euid;
    u32 setuid; //setuid 비트유무

    struct file * file;

    u64 file_address;
};

struct ret_file_data{
    char file_name[80];
    char task_name[TASK_COMM_LEN];

    u32 pid;
    u32 tid;

    u64 i_ino;
    u64 ret_i_ino;
    
    u32 file_uid;
    u32 file_gid;

    u32 uid;
    u32 euid;
    u32 setuid; //setuid 비트유무

    u64 ret_file_address;
    u64 file_address;
};

struct root_file_data{
    char file_name[80];

    u64 prev_i_ino;
    u64 i_ino;
};

BPF_HASH(hash_file_data,u64, struct file_data);
BPF_HASH(hash_ret_file_data,u64,struct ret_file_data);
BPF_PERF_OUTPUT(events);

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file) {

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct inode *inode = file->f_inode;
    struct dentry *dentry = file->f_path.dentry;
    u64 i_ino = (u64)inode->i_ino;

    struct file_data * val_file_data, val_file_data_zero = {};
    
    val_file_data = hash_file_data.lookup_or_try_init(&pid_tgid,&val_file_data_zero);

    if(val_file_data)
    {
        val_file_data->pid = pid;
        val_file_data->tid = tid;
        val_file_data->i_ino = i_ino;
        val_file_data->file_uid = inode->i_uid;
        val_file_data->file_gid = inode->i_gid;
        val_file_data->uid = (kuid_t)cred->uid;
        val_file_data->euid = (kuid_t)cred->euid;
        val_file_data->setuid = inode->i_mode & S_ISUID;
        val_file_data->file = file;
        val_file_data->file_address = (u64)file;
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char *)val_file_data->task_name,sizeof(name),name);
    }
    return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx) {

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct ret_file_data * val_ret_file_data, val_ret_file_data_zero = {};
    struct file_data * val_file_data, val_file_data_zero = {};

    val_file_data = hash_file_data.lookup_or_try_init(&pid_tgid,&val_file_data_zero);

    if(val_file_data)
    {
        if(val_file_data->i_ino != val_file_data->file->f_inode->i_ino)
        {
            struct ret_file_data val_ret_file_data = {};
            struct file * file = (struct file *)PT_REGS_PARM1(ctx);
            val_ret_file_data.ret_file_address = (u64)file;
            val_ret_file_data.file_address = val_file_data->file_address;
            struct inode *inode = val_file_data->file->f_inode;
            struct dentry *dentry = val_file_data->file->f_path.dentry;
            u64 i_ino = (u64)inode->i_ino;
            val_ret_file_data.i_ino = val_file_data->i_ino;
            val_ret_file_data.ret_i_ino = i_ino;
            val_ret_file_data.file_uid = inode->i_uid.val;
            val_ret_file_data.file_gid = inode->i_gid.val;
            val_ret_file_data.uid = cred->uid.val;
            val_ret_file_data.euid = cred->euid.val;
            val_ret_file_data.setuid = inode->i_mode & S_ISUID;
            bpf_probe_read_str((char *)val_ret_file_data.file_name,sizeof((dentry->d_name).len),(dentry->d_name).name);
            char name[TASK_COMM_LEN];
            bpf_get_current_comm(&name, sizeof(name));
            bpf_probe_read_str((char *)val_ret_file_data.task_name,sizeof(name),name);
            val_ret_file_data.pid = pid;
            val_ret_file_data.tid = tid;
            events.perf_submit(ctx,&val_ret_file_data,sizeof(val_ret_file_data));
        }
        hash_file_data.delete(&pid_tgid);
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

not_print_list = ['TCP','UNI','7','4','Git','.br','rem','.8b','UNIX','[ev','ptm','aut','UDP','[eve']

def print_who_write(cpu, data, size):
    event = bpf["events"].event(data)
    file_name = (event.file_name).decode('utf-8')
    process_name= (event.task_name).decode('utf-8')   
    global print_type
    global first_time
    global is_print
    check = 0
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    print(print_type,event.pid, event.tid, event.ret_file_address, event.file_address, file_name,process_name,event.i_ino,event.ret_i_ino,event.file_uid,event.file_gid, event.uid,event.euid,event.setuid,cur_time)
    print('file inode change!! dirty_cred detect!!')
    print_type += 1

bpf["events"].open_perf_buffer(print_who_write)

# 이벤트를 출력하는 루프입니다.
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
