#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_AUTHOR("Devin Vander Stelt");
MODULE_DESCRIPTION("Hello world driver");
MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;
const char * msg = "Hello World";

static unsigned int my_func(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
) {
    struct iphdr * iph;
    struct udphdr * udph;
    int msg_len;
    unsigned char * data;
    
    if (skb == 0)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    udph = udp_hdr(skb);

    iph->protocol = IPPROTO_UDP;
    iph->daddr = htonl(0xC0A8019A); // 192.168.1.154

    udph->dest = htons(8000);           // port 8000
    udph->check = 0;                    // no checksum

    // Set tail to end of udp header
    skb->tail = skb->transport_header + 8;
    skb->len = skb->transport_header + 8;

    // Copy msg to data
    msg_len = strlen(msg);
    data = skb_put(skb, msg_len);
    strcpy(data, msg);

    return NF_ACCEPT;
}

static int __init custom_init(void) {
    int ret = 0;
    struct net *n;

    nfho.hook = my_func;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);

    printk("Registered hooks");
    printk("nf_register_hook returned %d\n", ret);
    return 0;
}

static void __exit custom_exit(void) {
    struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);

    printk("kernel module exited");
}

module_init(custom_init);
module_exit(custom_exit);
