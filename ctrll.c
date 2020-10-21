#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mitchell Clay");
MODULE_DESCRIPTION("Rootkit for testing");

static int __init ctrll_rootkit_init(void)
{
    printk(KERN_INFO "ctrl-L rootkit loaded\n");
    return 0;
}

static void __exit ctrll_rootkit_exit(void)
{
    printk(KERN_INFO "ctrl-L rootkit unloaded\n");
}

module_init(ctrll_rootkit_init);
module_exit(ctrll_rootkit_exit);
