#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Structure for registering our function.
static struct nf_hook_ops nfho;

// Hook function
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // Drop all packets
    return NF_DROP;
}

// Initialization
int init_module() {
    // Fill in hook structure
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);
    return 0;
}

// Cleanup
void cleanup_module() {
    nf_unregister_hook(&nfho);
}

