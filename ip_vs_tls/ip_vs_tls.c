#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>

#include <net/ip_vs.h>


#define SERVER_STRING "227 "
#define CLIENT_STRING "PORT"


/*
 * List of ports (up to IP_VS_APP_MAX_PORTS) to be handled by helper
 * First port is set to the default port.
 */
static unsigned int ports_count = 1;
static unsigned short ports[IP_VS_APP_MAX_PORTS] = {1111, 0};
module_param_array(ports, ushort, &ports_count, 0444);
MODULE_PARM_DESC(ports, "Ports to monitor for TLS control commands");

extern void  Tp_parse(void *ctx, unsigned char *buf, unsigned int len);
extern void  Tp_set_clnt_sni_cb(void *ctx, void* func);
extern void  *Tp_ctx_new(void);
extern void  Tp_ctx_free(void *ctx);
extern void  *Tp_ctx_get_pri(void *ctx);
extern void  Tp_ctx_set_pri(void *ctx, void *pri);
extern int   Tp_is_reject(void *ctx);
extern void  Tp_set_reject(void *ctx);
int get_clnt_sni(void *ctx, char *str, unsigned int len)
{
    struct ip_vs_conn *cp = Tp_ctx_get_pri(ctx);
    if (unlikely(!cp))
        return 0;

    if (len >= (sizeof("google") -1 )  && strstr(str, "google")) {

        /*block*/
        Tp_set_reject(ctx);
        return 0;
    }
    return 1;
}


static int
ip_vs_tls_init_conn(struct ip_vs_app *app, struct ip_vs_conn *cp)
{
        void *ctx = Tp_ctx_new();
        if (unlikely(!ctx)) {
            return 0;
        }
        /*set callback*/
        Tp_set_clnt_sni_cb(ctx, get_clnt_sni);
        /*save ipvs session to ctx*/
        Tp_ctx_set_pri(ctx, cp);
        /*save ctx to ipvs session*/
        cp->app_data = ctx;
	return 0;
}


static int
ip_vs_tls_done_conn(struct ip_vs_app *app, struct ip_vs_conn *cp)
{
        if (cp->app_data) {
            Tp_ctx_free(cp->app_data);
            cp->app_data = NULL;
        }
	return 0;
}

static int ip_vs_tls_out(struct ip_vs_app *app, struct ip_vs_conn *cp,
			 struct sk_buff *skb, int *diff)
{
	*diff = 0;
	return 1;
}


static int ip_vs_tls_in(struct ip_vs_app *app, struct ip_vs_conn *cp,
			struct sk_buff *skb, int *diff)
{
	struct iphdr *iph;
	struct tcphdr *th;
	char *data, *data_start, *data_limit;

	*diff = 0;

	/* Only useful for established sessions */
	if (cp->state != IP_VS_TCP_S_ESTABLISHED)
		return 1;

	/* Linear packets are much easier to deal with. */
	if (!skb_make_writable(skb, skb->len))
		return 0;

	iph = ip_hdr(skb);
	th = (struct tcphdr *)&(((char *)iph)[iph->ihl*4]);

	/* Since there may be OPTIONS in the TCP packet and the HLEN is
         * the length of the header in 32-bit multiples, it is accurate
         * to calculate data address by th+HLEN*4 */
	data = data_start = (char *)th + (th->doff << 2);
	data_limit = skb_tail_pointer(skb);

        if (cp->app_data && data_limit > data) {
            Tp_parse(cp->app_data, data, (unsigned int)(data_limit - data));
            if (Tp_is_reject(cp->app_data)) {
                return 0;
            }
        }

	return 1;
}


static struct ip_vs_app ip_vs_tls = {
	.name =		"tls",
	.type =		2,
	.protocol =	IPPROTO_TCP,
	.module =	THIS_MODULE,
	.incs_list =	LIST_HEAD_INIT(ip_vs_tls.incs_list),
	.init_conn =	ip_vs_tls_init_conn,
	.done_conn =	ip_vs_tls_done_conn,
	.bind_conn =	NULL,
	.unbind_conn =	NULL,
	.pkt_out =	ip_vs_tls_out,
	.pkt_in =	ip_vs_tls_in,
};

/*
 *per netns ip_vs_tls initialization
 */
static int __net_init __ip_vs_tls_init(struct net *net)
{
	int i, ret;
	struct ip_vs_app *app;
	struct netns_ipvs *ipvs = net_ipvs(net);

	if (!ipvs)
		return -ENOENT;

	app = register_ip_vs_app(net, &ip_vs_tls);
	if (IS_ERR(app))
		return PTR_ERR(app);

	for (i = 0; i < ports_count; i++) {
		if (!ports[i])
			continue;
		ret = register_ip_vs_app_inc(net, app, app->protocol, ports[i]);
		if (ret)
			goto err_unreg;
		pr_info("%s: loaded support on port[%d] = %d\n",
			app->name, i, ports[i]);
	}
	return 0;

err_unreg:
	unregister_ip_vs_app(net, &ip_vs_tls);
	return ret;
}
/*
 *netns exit
 */
static void __ip_vs_tls_exit(struct net *net)
{
	unregister_ip_vs_app(net, &ip_vs_tls);
}

static struct pernet_operations ip_vs_ftp_ops = {
	.init = __ip_vs_tls_init,
	.exit = __ip_vs_tls_exit,
};

static int __init ip_vs_tls_init(void)
{
	int rv;
	rv = register_pernet_subsys(&ip_vs_ftp_ops);
	/* rcu_barrier() is called by netns on error */
	return rv;
}

/*
 *ip_vs_tls finish.
 */
static void __exit ip_vs_tls_exit(void)
{
	unregister_pernet_subsys(&ip_vs_ftp_ops);
	/* rcu_barrier() is called by netns */
}


module_init(ip_vs_tls_init);
module_exit(ip_vs_tls_exit);
MODULE_LICENSE("GPL");

