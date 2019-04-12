#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>

#define EXAMPLE_COM_IP "93.184.216.34"
#define MACHINE_B "10.0.2.6"
#define SSH_PORT 22
#define SYR_IP "128.230.18.198"
#define TCP_PROTO 6
#define TELNET_PORT 23


// Structure for registering our function.
static struct nf_hook_ops incoming_hook;
static struct nf_hook_ops outgoing_hook;

// Hook function
unsigned int pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;

    // If it's a TCP request:
    if (ip_header->protocol==TCP_PROTO) {
    	struct tcphdr *tcp_header = (struct tcphdr*)skb_transport_header(skb);
    	unsigned int src_port = (unsigned int)ntohs(tcp_header->source);
    	unsigned int dest_port = (unsigned int)ntohs(tcp_header->dest);

        // Block incoming telnet from Machine B
    	if (src_ip == in_aton(MACHINE_B) && dest_port == TELNET_PORT) {
            printk(KERN_DEBUG "Dropping packet from %pI4:%d to %pI4:%d\n", &src_ip, src_port, &dest_ip, dest_port);

            return NF_DROP;
    	}

        // Block incoming SSH from Machine B
        if (src_ip == in_aton(MACHINE_B) && dest_port == SSH_PORT) {
            printk(KERN_DEBUG "Dropping SSH packet from %pI4:%d", &src_ip, src_port);

            return NF_DROP;
        }
    }

    // Default accept
    return NF_ACCEPT;
}

unsigned int post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);

    // We only care about TCP requests
    if (ip_header->protocol == TCP_PROTO) {
        struct tcphdr *tcp_header = (struct tcphdr*) skb_transport_header(skb);
        unsigned int dest_ip = (unsigned int) ip_header->daddr;
        unsigned int dest_port = (unsigned int) ntohs(tcp_header->dest);

        // Block outgoing telnet packets to Machine B
        if (dest_ip == in_aton(MACHINE_B) && dest_port == TELNET_PORT) {
            printk(KERN_DEBUG "Dropping packet to %pI4:%d\n", &dest_ip, dest_port);

            return NF_DROP;
        }

    	// Block outgoing packets to example.com
    	if (dest_ip == in_aton(EXAMPLE_COM_IP)) {
    	    printk(KERN_DEBUG "Dropping packet intended for 'example.com'\n");

    	    return NF_DROP;
    	}

        // Block outgoing packets to syr.edu
        if (dest_ip == in_aton(SYR_IP)) {
            printk(KERN_DEBUG "Dropping packet intended for 'syr.edu'\n");

            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// Initialization
int init_module() {
    printk(KERN_INFO "Loading custom filter module...\n");
    unsigned int machine_b_ip = in_aton(MACHINE_B);
    printk(KERN_DEBUG "Machine B IP: %pI4\n", &machine_b_ip);

    // Fill in incoming hook structure
    incoming_hook.hook = pre_routing_hook;
    incoming_hook.hooknum = NF_INET_PRE_ROUTING;
    incoming_hook.pf = PF_INET;
    incoming_hook.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&incoming_hook);

    outgoing_hook.hook = post_routing_hook;
    outgoing_hook.hooknum = NF_INET_POST_ROUTING;
    outgoing_hook.pf = PF_INET;
    outgoing_hook.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&outgoing_hook);

    printk(KERN_INFO "Finished loading custom filter module.\n");

    return 0;
}

// Cleanup
void cleanup_module() {
    nf_unregister_hook(&incoming_hook);
    nf_unregister_hook(&outgoing_hook);
    printk(KERN_INFO "Unregistered custom filter module.\n");
}
