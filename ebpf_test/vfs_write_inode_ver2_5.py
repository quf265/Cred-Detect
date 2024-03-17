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
    kuid_t file_uid;  //소유 uid
    kgid_t file_gid;  //소유 gid

    kuid_t uid;
    kuid_t euid;
    u32 setuid; //setuid 비트유무

    struct file * file;
    struct file * ret_file;

    u64 ret_file_address;
    u64 file_address;
};

struct root_file_data{
    char file_name[80];

    u64 prev_i_ino;
    u64 i_ino;
};

BPF_HASH(hash_cred_data,u64,struct cred_data);
BPF_HASH(hash_root_file_data,u64,struct root_file_data);
BPF_HASH(hash_file_data,u64, struct file_data);
BPF_HASH(hash_ret_file_data,u64,struct ret_file_data);

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos) {

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

    struct cred_data * val_cred_data, val_cred_data_zero = {};
    struct root_file_data * val_root_file_data, val_root_file_data_zero = {};
    struct file_data * val_file_data, val_file_data_zero = {};

    val_cred_data = hash_cred_data.lookup_or_try_init(&pid_tgid, &val_cred_data_zero);
    val_root_file_data = hash_root_file_data.lookup_or_try_init(&i_ino,&val_root_file_data_zero);
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
        bpf_probe_read_str((char *)val_file_data->file_name,sizeof((dentry->d_name).len),(dentry->d_name).name);
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char *)val_file_data->task_name,sizeof(name),name);
    }
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

    struct cred_data * val_cred_data, val_cred_data_zero = {};
    struct root_file_data * val_root_file_data, val_root_file_data_zero = {};
    struct ret_file_data * val_ret_file_data, val_ret_file_data_zero = {};
    struct file_data * val_file_data, val_file_data_zero = {};

    val_cred_data = hash_cred_data.lookup_or_try_init(&pid_tgid, &val_cred_data_zero);
    val_ret_file_data = hash_ret_file_data.lookup_or_try_init(&pid_tgid,&val_ret_file_data_zero);
    val_file_data = hash_file_data.lookup_or_try_init(&pid_tgid,&val_file_data_zero);

    if(val_ret_file_data)
    {
        struct file * file = (struct file *)PT_REGS_PARM1(ctx);
        val_ret_file_data->ret_file = file;
        val_ret_file_data->ret_file_address = (u64)file;
        if(val_file_data)
        {

            val_ret_file_data->file = val_file_data->file;
            val_ret_file_data->file_address = val_file_data->file_address;
            struct inode *inode = val_file_data->file->f_inode;
            struct dentry *dentry = val_file_data->file->f_path.dentry;
            u64 i_ino = (u64)inode->i_ino;
            val_ret_file_data->i_ino = val_file_data->i_ino;
            val_ret_file_data->ret_i_ino = i_ino;
            val_ret_file_data->file_uid = inode->i_uid;
            val_ret_file_data->file_gid = inode->i_gid;
            val_ret_file_data->uid = (kuid_t)cred->uid;
            val_ret_file_data->euid = (kuid_t)cred->euid;
            val_ret_file_data->setuid = inode->i_mode & S_ISUID;
            bpf_probe_read_str((char *)val_file_data->file_name,sizeof((dentry->d_name).len),(dentry->d_name).name);
            char name[TASK_COMM_LEN];
            bpf_get_current_comm(&name, sizeof(name));
            bpf_probe_read_str((char *)val_file_data->task_name,sizeof(name),name);
        }
        val_ret_file_data->pid = pid;
        val_ret_file_data->tid = tid;
        val_ret_file_data->uid = (kuid_t)cred->uid;
        val_ret_file_data->euid = (kuid_t)cred->euid;
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

def print_who_write():
    cred_data = bpf["hash_cred_data"]
    file_data = bpf["hash_file_data"]
    ret_file_data = bpf["hash_ret_file_data"]
    is_alert = 0
    global print_type
    global first_time
    global is_print
    check = 0
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    #print(data_kmalloc.items())
    """
    for k, v in cred_data.items_lookup_and_delete_batch():
        process_name= (v.task_name).decode('utf-8')
        #print(v.i_ino)
        if v.i_ino == 1316102:
            write_data =[]
            write_data = [print_type,v.pid, v.tid, v.syscall_number, syscall_name(v.syscall_number).decode('utf-8'),process_name,v.dangerous,v.prev_uid.val,v.uid.val,v.prev_suid.val, v.suid.val, v.prev_euid.val, v.euid.val ,v.chuid, v.chsuid, v.cheuid, cur_time,'cred_data' ]
            print(write_data)
            #writer.writerow(write_data)
            is_print = 1
            check = 1
    """
    """
    for k, v in file_data.items_lookup_and_delete_batch():
        file_name = (v.file_name).decode('utf-8')
        process_name= (v.task_name).decode('utf-8')
        if file_name not in not_print_list:            
            write_data =[]
            write_data = [print_type,v.pid, v.tid, v.file, v.file_address, file_name,process_name,v.i_ino,v.file_uid.val,v.file_gid.val, v.uid.val,v.euid.val,v.setuid,cur_time,'file_data' ]
            print(write_data)
        #writer.writerow(write_data)
        is_print = 1
        check = 1
    """
    for k, v in ret_file_data.items_lookup_and_delete_batch():
        file_name = (v.file_name).decode('utf-8')
        process_name= (v.task_name).decode('utf-8')
        if file_name not in not_print_list:            
            write_data =[]
            write_data = [print_type,v.pid, v.tid, v.ret_file, v.ret_file_address, v.file, v.file_address, file_name,process_name,v.i_ino,v.ret_i_ino,v.file_uid.val,v.file_gid.val, v.uid.val,v.euid.val,v.setuid,cur_time,'ret_file_data' ]
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
