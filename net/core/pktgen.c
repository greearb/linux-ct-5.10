// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors:
 * Copyright 2001, 2002 by Robert Olsson <robert.olsson@its.uu.se>
 *                             Uppsala University and
 *                             Swedish University of Agricultural Sciences
 *
 * Alexey Kuznetsov  <kuznet@ms2.inr.ac.ru>
 * Ben Greear <greearb@candelatech.com>
 * Jens Låås <jens.laas@data.slu.se>
 *
 * A tool for loading the network with preconfigurated packets.
 * The tool is implemented as a linux module.  Parameters are output
 * device, delay (to hard_xmit), number of packets, and whether
 * to use multiple SKBs or just the same one.
 * pktgen uses the installed interface's output routine.
 *
 * Additional hacking by:
 *
 * Jens.Laas@data.slu.se
 * Improved by ANK. 010120.
 * Improved by ANK even more. 010212.
 * MAC address typo fixed. 010417 --ro
 * Integrated.  020301 --DaveM
 * Added multiskb option 020301 --DaveM
 * Scaling of results. 020417--sigurdur@linpro.no
 * Significant re-work of the module:
 *   *  Convert to threaded model to more efficiently be able to transmit
 *       and receive on multiple interfaces at once.
 *   *  Converted many counters to __u64 to allow longer runs.
 *   *  Allow configuration of ranges, like min/max IP address, MACs,
 *       and UDP-ports, for both source and destination, and can
 *       set to use a random distribution or sequentially walk the range.
 *   *  Can now change most values after starting.
 *   *  Place 12-byte packet in UDP payload with magic number,
 *       sequence number, and timestamp.
 *   *  Add receiver code that detects dropped pkts, re-ordered pkts, and
 *       latencies (with micro-second) precision.
 *   *  Add IOCTL interface to easily get counters & configuration.
 *   --Ben Greear <greearb@candelatech.com>
 *
 * Renamed multiskb to clone_skb and cleaned up sending core for two distinct
 * skb modes. A clone_skb=0 mode for Ben "ranges" work and a clone_skb != 0
 * as a "fastpath" with a configurable number of clones after alloc's.
 * clone_skb=0 means all packets are allocated this also means ranges time
 * stamps etc can be used. clone_skb=100 means 1 malloc is followed by 100
 * clones.
 *
 * Also moved to /proc/net/pktgen/
 * --ro
 *
 * Sept 10:  Fixed threading/locking.  Lots of bone-headed and more clever
 *    mistakes.  Also merged in DaveM's patch in the -pre6 patch.
 * --Ben Greear <greearb@candelatech.com>
 *
 * Integrated to 2.5.x 021029 --Lucio Maciel (luciomaciel@zipmail.com.br)
 *
 *
 * 021124 Finished major redesign and rewrite for new functionality.
 * See Documentation/networking/pktgen.txt for how to use this.
 *
 * The new operation:
 * For each CPU one thread/process is created at start. This process checks
 * for running devices in the if_list and sends packets until count is 0 it
 * also the thread checks the thread->control which is used for inter-process
 * communication. controlling process "posts" operations to the threads this
 * way. The if_lock should be possible to remove when add/rem_device is merged
 * into this too.
 *
 * By design there should only be *one* "controlling" process. In practice
 * multiple write accesses gives unpredictable result. Understood by "write"
 * to /proc gives result code thats should be read be the "writer".
 * For practical use this should be no problem.
 *
 * Note when adding devices to a specific CPU there good idea to also assign
 * /proc/irq/XX/smp_affinity so TX-interrupts gets bound to the same CPU.
 * --ro
 *
 * Fix refcount off by one if first packet fails, potential null deref,
 * memleak 030710- KJP
 *
 * First "ranges" functionality for ipv6 030726 --ro
 *
 * Included flow support. 030802 ANK.
 *
 * Fixed unaligned access on IA-64 Grant Grundler <grundler@parisc-linux.org>
 *
 * Remove if fix from added Harald Welte <laforge@netfilter.org> 040419
 * ia64 compilation fix from  Aron Griffis <aron@hp.com> 040604
 *
 * New xmit() return, do_div and misc clean up by Stephen Hemminger
 * <shemminger@osdl.org> 040923
 *
 * Randy Dunlap fixed u64 printk compiler warning
 *
 * Remove FCS from BW calculation.  Lennert Buytenhek <buytenh@wantstofly.org>
 * New time handling. Lennert Buytenhek <buytenh@wantstofly.org> 041213
 *
 * Corrections from Nikolai Malykh (nmalykh@bilim.com)
 * Removed unused flags F_SET_SRCMAC & F_SET_SRCIP 041230
 *
 * interruptible_sleep_on_timeout() replaced Nishanth Aravamudan <nacc@us.ibm.com>
 * 050103
 *
 * MPLS support by Steven Whitehouse <steve@chygwyn.com>
 *
 * 802.1Q/Q-in-Q support by Francesco Fondelli (FF) <francesco.fondelli@gmail.com>
 *
 * Fixed src_mac command to set source mac of packet to value specified in
 * command by Adit Ranadive <adit.262@gmail.com>
 *
 */
#include <linux/sys.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/capability.h>
#include <linux/freezer.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/wait.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>
#include <linux/prefetch.h>
#include <net/net_namespace.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/ip6_checksum.h>
#include <net/addrconf.h>
#ifdef CONFIG_XFRM
#include <net/xfrm.h>
#endif
#include <net/netns/generic.h>
#include <asm/byteorder.h>
#include <linux/rcupdate.h>
#include <linux/bitops.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#include <asm/div64.h>		/* do_div */
#include <asm/timex.h>
#include <linux/sched.h> /* sched_clock() */
#include "pktgen.h"
#include <linux/ktime.h>

#define USE_NQW_CALLBACK
#ifdef USE_NQW_CALLBACK
#  include <linux/if_vlan.h>
#  include <linux/if_macvlan.h>
#endif
#define VERSION  "pktgen v3.9-ben: Packet Generator for packet performance testing.\n"

static int pg_net_id __read_mostly;

static int use_rel_ts = 0;

#define REMOVE 1
#define FIND   0

static const char *version = VERSION;

static struct pktgen_dev *__pktgen_NN_threads(const struct pktgen_net *pn,
					      const char *ifname, int remove);
static int pktgen_remove_device(struct pktgen_thread *t, struct pktgen_dev *i);
static int pktgen_add_device(struct pktgen_thread *t, const char *ifname);
static struct pktgen_dev *pktgen_find_dev(struct pktgen_thread *t, const char *ifname, bool exact);
static int pktgen_device_event(struct notifier_block *, unsigned long, void *);
static void pktgen_run_all_threads(struct pktgen_net *pn, int background);
static void pktgen_reset_all_threads(struct pktgen_net *pn);
static void pktgen_stop_all_threads_ifs(struct pktgen_net *pn);

static void pktgen_stop(struct pktgen_thread *t);
static void pg_reset_latency_counters(struct pktgen_dev* pkt_dev);
static void pktgen_clear_counters(struct pktgen_dev *pkt_dev, int seq_too,
				  const char* reason);
static void pktgen_mark_device(const struct pktgen_net *pn, const char *ifname);
static void clear_nqw_hook(struct pktgen_thread* t, struct net_device* dev);
static int set_nqw_hook(struct pktgen_thread* t, struct net_device* dev, int gfp);

/* Module parameters, defaults. */
static int pg_count_d __read_mostly = 1000;	  /* 1000 pkts by default */
static int pg_delay_d __read_mostly = 0x7FFFFFFF; /* Don't run until someone sets a different delay. */
static int pg_clone_skb_d __read_mostly;
static int debug __read_mostly;

static DEFINE_MUTEX(pktgen_thread_lock);

static struct notifier_block pktgen_notifier_block = {
	.notifier_call = pktgen_device_event,
};

/*  This code works around the fact that do_div cannot handle two 64-bit
    numbers, and regular 64-bit division doesn't work on x86 kernels.
    --Ben
*/

#define PG_DIV 0

/* This was emailed to LMKL by: Chris Caputo <ccaputo@alt.net>
 * Function copied/adapted/optimized from:
 *
 *  nemesis.sourceforge.net/browse/lib/static/intmath/ix86/intmath.c.html
 *
 * Copyright 1994, University of Cambridge Computer Laboratory
 * All Rights Reserved.
 *
 */
static inline s64 divremdi3(s64 x, s64 y, int type)
{
	u64 a = (x < 0) ? -x : x;
	u64 b = (y < 0) ? -y : y;
	u64 res = 0, d = 1;

	if (b > 0) {
		while (b < a) {
			b <<= 1;
			d <<= 1;
		}
	}

	do {
		if (a >= b) {
			a -= b;
			res += d;
		}
		b >>= 1;
		d >>= 1;
	}
	while (d);

	if (PG_DIV == type) {
		return (((x ^ y) & (1ll << 63)) == 0) ? res : -(s64) res;
	} else {
		return ((x & (1ll << 63)) == 0) ? a : -(s64) a;
	}
}

/* End of hacks to deal with 64-bit math on x86 */

/** Convert to micro-seconds */
static inline __u64 ts_to_us(const struct timespec64 *ts)
{
	__u64 us = ts->tv_nsec / NSEC_PER_USEC;
	us += ((__u64) ts->tv_sec) * 1000000ULL;
	return us;
}

static inline __s64 pg_div(__s64 n, __u32 base)
{
	if (n < 0) {
		__u64 tmp = -n;
		do_div(tmp, base);
		/* printk("pktgen: pg_div, n: %llu  base: %d  rv: %llu\n",
		   n, base, tmp); */
		return -tmp;
	}
	else {
		__u64 tmp = n;
		do_div(tmp, base);
		/* printk("pktgen: pg_div, n: %llu  base: %d  rv: %llu\n",
		   n, base, tmp); */
		return tmp;
	}
}

#if 0
static inline __u64 pg_div64(__u64 n, __u64 base)
{
	__u64 tmp = n;
/*
 * How do we know if the architecture we are running on
 * supports division with 64 bit base?
 *
 */
#if defined(__sparc_v9__) || defined(__powerpc64__) || defined(__alpha__) || defined(__x86_64__) || defined(__ia64__)

	do_div(tmp, base);
#else
	tmp = divremdi3(n, base, PG_DIV);
#endif
	return tmp;
}
#endif

static inline __u64 getCurUs(void)
{
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	return ts_to_us(&ts);
}


/* Since the machine booted. */
static __u64 getRelativeCurNs(void) {
	if (!use_rel_ts) {
		struct timespec64 ts;
		ktime_get_real_ts64(&ts);
		return timespec64_to_ns(&ts);
	}
	else {
		/* Seems you must disable pre-empt to call sched_clock. --Ben */
		unsigned long flags;
		__u64 rv;
		local_irq_save(flags);
		rv = sched_clock();
		local_irq_restore(flags);
		return rv;
	}
}

/* old include end */


static void timestamp_skb(struct pktgen_dev* pkt_dev, struct pktgen_hdr* pgh) {
	if (pkt_dev->flags & F_NO_TIMESTAMP) {
		pgh->tv_hi = 0;
		pgh->tv_lo = 0;
		return;
	}

	if (pkt_dev->flags & F_USE_REL_TS) {
		__u64 now = getRelativeCurNs();
		__u32 hi = (now >> 32);
		__u32 lo = now;
		pgh->tv_hi = htonl(hi);
		pgh->tv_lo = htonl(lo);
	}
	else {
		struct timespec64 ts;
		s64 n;
		__u32 hi;
		__u32 lo;
		ktime_get_real_ts64(&ts);
		n = timespec64_to_ns(&ts);
		hi = n >> 32;
		lo = n;
		pgh->tv_hi = htonl(hi);
		pgh->tv_lo = htonl(lo);
	}
}

/*
 * /proc handling functions
 *
 */

static int pgctrl_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, version);
	return 0;
}

static ssize_t pgctrl_write(struct file *file, const char __user * buf,
			    size_t count, loff_t * ppos)
{
	char data[128];
	struct pktgen_net *pn = net_generic(current->nsproxy->net_ns, pg_net_id);

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (count == 0)
		return -EINVAL;

	if (count > sizeof(data))
		count = sizeof(data);

	if (copy_from_user(data, buf, count))
		return -EFAULT;

	data[count - 1] = 0;	/* Strip trailing '\n' and terminate string */

	if (!strcmp(data, "stop"))
		pktgen_stop_all_threads_ifs(pn);

	else if (!strcmp(data, "start"))
		pktgen_run_all_threads(pn, 0);
	/* Run in the background. */
	else if (!strcmp(data, "bg_start"))
		pktgen_run_all_threads(pn, 1);
	else if (!strcmp(data, "reset"))
		pktgen_reset_all_threads(pn);
	else
		printk(KERN_WARNING "pktgen: Unknown command: %s\n", data);

	return count;
}

static int pgctrl_open(struct inode *inode, struct file *file)
{
	return single_open(file, pgctrl_show, PDE_DATA(inode));
}

static int pg_populate_report(struct pktgen_dev_report* rpt, struct pktgen_dev* pkt_dev) {
	int i;

	memset(rpt, 0, sizeof(*rpt));
	rpt->api_version = 1;
	rpt->flags = pkt_dev->flags;
	if (!pkt_dev->running)
		rpt->flags |= (F_PG_STOPPED);
	strncpy(rpt->thread_name, pkt_dev->pg_thread->tsk->comm, 32);
	strncpy(rpt->interface_name, pkt_dev->ifname, 32);
	rpt->min_pkt_size = pkt_dev->min_pkt_size;
	rpt->max_pkt_size = pkt_dev->max_pkt_size;
	rpt->clone_skb = pkt_dev->clone_skb;
	rpt->conn_id = pkt_dev->conn_id;
	rpt->peer_conn_id = pkt_dev->peer_conn_id;
	rpt->peer_clone_skb = pkt_dev->peer_clone_skb;
	rpt->nfrags = pkt_dev->nfrags;

	strncpy(rpt->dst_min, pkt_dev->dst_min, IP_NAME_SZ);
	strncpy(rpt->dst_max, pkt_dev->dst_max, IP_NAME_SZ);
	strncpy(rpt->src_min, pkt_dev->src_min, IP_NAME_SZ);
	strncpy(rpt->src_max, pkt_dev->src_max, IP_NAME_SZ);

	memcpy(&rpt->in6_saddr, &pkt_dev->in6_saddr, sizeof(struct in6_addr));
	memcpy(&rpt->in6_daddr, &pkt_dev->in6_daddr, sizeof(struct in6_addr));

	/* For ranges */
	memcpy(&rpt->min_in6_daddr, &pkt_dev->min_in6_daddr, sizeof(struct in6_addr));
	memcpy(&rpt->max_in6_daddr, &pkt_dev->max_in6_daddr, sizeof(struct in6_addr));
	memcpy(&rpt->min_in6_saddr, &pkt_dev->min_in6_saddr, sizeof(struct in6_addr));
	memcpy(&rpt->max_in6_saddr, &pkt_dev->max_in6_saddr, sizeof(struct in6_addr));

	/* If we're doing ranges, random or incremental, then this
	 * defines the min/max for those ranges.
	 */
	rpt->saddr_min = pkt_dev->saddr_min;
	rpt->saddr_max = pkt_dev->saddr_max;
	rpt->daddr_min = pkt_dev->daddr_min;
	rpt->daddr_max = pkt_dev->daddr_max;

	rpt->udp_src_min = pkt_dev->udp_src_min;
	rpt->udp_src_max = pkt_dev->udp_src_max;
	rpt->udp_dst_min = pkt_dev->udp_dst_min;
	rpt->udp_dst_max = pkt_dev->udp_dst_max;

	/* MPLS */
	rpt->nr_labels = pkt_dev->nr_labels;	/* Depth of stack, 0 = no MPLS */
	for (i = 0; i<MAX_MPLS_LABELS; i++) {
		rpt->labels[i] = pkt_dev->labels[i];
	}

	rpt->src_mac_count = pkt_dev->src_mac_count;
	rpt->dst_mac_count = pkt_dev->dst_mac_count;

	memcpy(&rpt->dst_mac, &pkt_dev->dst_mac, ETH_ALEN);
	memcpy(&rpt->src_mac, &pkt_dev->src_mac, ETH_ALEN);

	rpt->nflows = pkt_dev->nflows;
	rpt->cflows = pkt_dev->cflows;
	rpt->lflow = pkt_dev->lflow;

	rpt->delay_ns = pkt_dev->delay_ns;
	rpt->count = pkt_dev->count;  /* Default No packets to send */
	rpt->sofar = pkt_dev->sofar;  /* How many pkts we've sent so far */
	rpt->tx_bytes = pkt_dev->tx_bytes; /* How many bytes we've transmitted */
	rpt->tx_bytes_ll = pkt_dev->tx_bytes_ll; /* How many bytes we've transmitted, including framing */
	rpt->errors = pkt_dev->errors;    /* Errors when trying to transmit, pkts will be re-sent */

	/* Fields relating to receiving pkts */
	rpt->avg_latency = pkt_dev->avg_latency; /* in micro-seconds */
	rpt->min_latency = pkt_dev->min_latency;
	rpt->max_latency = pkt_dev->max_latency;
	for (i = 0; i<LAT_BUCKETS_MAX; i++) {
		rpt->latency_bkts[i] = pkt_dev->latency_bkts[i];
	}
	rpt->running_jitter = pkt_dev->running_jitter / 1024;
	rpt->burst = pkt_dev->burst;
	rpt->pkts_rcvd_since_clear_lat = pkt_dev->pkts_rcvd_since_clear_lat;
	rpt->total_lat = pkt_dev->total_lat;

        rpt->ooo_rcvd = pkt_dev->ooo_rcvd;
        rpt->pkts_rcvd = pkt_dev->pkts_rcvd;
	rpt->rx_crc_failed = pkt_dev->rx_crc_failed;
        rpt->dup_rcvd = pkt_dev->dup_rcvd;
        rpt->bytes_rcvd = pkt_dev->bytes_rcvd;
        rpt->bytes_rcvd_ll = pkt_dev->bytes_rcvd_ll;
	rpt->pkts_rcvd_wrong_conn = pkt_dev->pkts_rcvd_wrong_conn;
        rpt->seq_gap_rcvd = pkt_dev->seq_gap_rcvd;
	rpt->non_pg_pkts_rcvd = pkt_dev->non_pg_pkts_rcvd;
	return 0;
}; /* populate report */


long pktgen_proc_ioctl(struct file* file, unsigned int cmd,
                      unsigned long arg) {
        int err = 0;
        struct pktgen_ioctl_info args;
        struct pktgen_dev* pkt_dev = NULL;
	struct pktgen_net *pn = net_generic(current->nsproxy->net_ns, pg_net_id);

        if (copy_from_user(&args, (void*)arg, sizeof(args))) {
                return -EFAULT;
        }

        /* Null terminate the names */
        args.thread_name[31] = 0;
        args.interface_name[31] = 0;

        /* printk("pktgen:  thread_name: %s  interface_name: %s\n",
         *        args.thread_name, args.interface_name);
         */

        switch (cmd) {
         case GET_PKTGEN_INTERFACE_INFO: {
		 mutex_lock(&pktgen_thread_lock);
                 pkt_dev = __pktgen_NN_threads(pn, args.interface_name, FIND);
                 if (pkt_dev) {
			 pg_populate_report(&(args.report), pkt_dev);
			 if (copy_to_user((void*)(arg), &args, sizeof(args))) {
				 printk("ERROR: pktgen:  copy_to_user failed.\n");
				 err = -EFAULT;
			 }
			 else {
				 err = 0;
			 }
		 }
		 else {
			 printk("ERROR: pktgen:  Could not find interface -:%s:-\n",
				args.interface_name);
			 err = -ENODEV;
		 }
		 mutex_unlock(&pktgen_thread_lock);
                 break;
         }
         default:
		printk("%s: Unknown pktgen IOCTL: %x \n", __FUNCTION__,
			cmd);
		return -EINVAL;
        }

        return err;
}/* pktgen_proc_ioctl */

static const struct proc_ops pktgen_proc_ops = {
	.proc_open	= pgctrl_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= pgctrl_write,
	.proc_release	= single_release,
	.proc_ioctl     = pktgen_proc_ioctl,
};

static int pktgen_if_show(struct seq_file *seq, void *v)
{
	const struct pktgen_dev *pkt_dev = seq->private;
	__u64 sa;
	__u64 stopped;
	__u64 now = getCurUs();
	int i;
	struct netdev_queue *txq;

	seq_printf(seq,
		   "Params: count %llu  min_pkt_size: %u  max_pkt_size: %u conn_id: %u  peer_conn_id: %u\n",
		   (unsigned long long)pkt_dev->count, pkt_dev->min_pkt_size,
		   pkt_dev->max_pkt_size, pkt_dev->conn_id, pkt_dev->peer_conn_id);

	seq_printf(seq,
		   "     frags: %d  delay: %lluns  clone_skb: %d  peer_clone_skb: %d ifname: %s\n",
		   pkt_dev->nfrags,
		   (unsigned long long)pkt_dev->delay_ns,
		   pkt_dev->clone_skb, pkt_dev->peer_clone_skb,
		   pkt_dev->ifname);

	seq_printf(seq, "     flows: %u flowlen: %u\n", pkt_dev->cflows,
		   pkt_dev->lflow);

	seq_printf(seq,
		   "     queue_map_min: %u  queue_map_max: %u\n",
		   pkt_dev->queue_map_min,
		   pkt_dev->queue_map_max);

	if (pkt_dev->skb_priority)
		seq_printf(seq, "     skb_priority: %u\n",
			   pkt_dev->skb_priority);

	if (pkt_dev->flags & F_IPV6) {
		seq_printf(seq,
			   "     saddr: %pI6c  min_saddr: %pI6c  max_saddr: %pI6c\n"
			   "     daddr: %pI6c  min_daddr: %pI6c  max_daddr: %pI6c\n",
			   &pkt_dev->in6_saddr,
			   &pkt_dev->min_in6_saddr, &pkt_dev->max_in6_saddr,
			   &pkt_dev->in6_daddr,
			   &pkt_dev->min_in6_daddr, &pkt_dev->max_in6_daddr);

	} else
		seq_printf(seq,
			   "     dst_min: %s  dst_max: %s\n     src_min: %s  src_max: %s\n",
			   pkt_dev->dst_min, pkt_dev->dst_max, pkt_dev->src_min,
			   pkt_dev->src_max);

	seq_puts(seq, "     src_mac: ");

	seq_printf(seq, "%pM ",
		   is_zero_ether_addr(pkt_dev->src_mac) ?
			     pkt_dev->odev->dev_addr : pkt_dev->src_mac);

	seq_puts(seq, "dst_mac: ");
	seq_printf(seq, "%pM\n", pkt_dev->dst_mac);

	seq_printf(seq,
		   "     udp_src_min: %d  udp_src_max: %d  udp_dst_min: %d  udp_dst_max: %d\n",
		   pkt_dev->udp_src_min, pkt_dev->udp_src_max,
		   pkt_dev->udp_dst_min, pkt_dev->udp_dst_max);

	seq_printf(seq,
		   "     src_mac_count: %d  dst_mac_count: %d\n",
		   pkt_dev->src_mac_count, pkt_dev->dst_mac_count);

	if (pkt_dev->nr_labels) {
		unsigned int i;
		seq_puts(seq, "     mpls: ");
		for (i = 0; i < pkt_dev->nr_labels; i++)
			seq_printf(seq, "%08x%s", ntohl(pkt_dev->labels[i]),
				   i == pkt_dev->nr_labels-1 ? "\n" : ", ");
	}

	if (pkt_dev->vlan_id != 0xffff) {
		seq_printf(seq, "     vlan_id: %u  vlan_p: %u  vlan_cfi: %u\n",
			   pkt_dev->vlan_id, pkt_dev->vlan_p, pkt_dev->vlan_cfi);
	}

	if (pkt_dev->svlan_id != 0xffff) {
		seq_printf(seq, "     svlan_id: %u  vlan_p: %u  vlan_cfi: %u\n",
			   pkt_dev->svlan_id, pkt_dev->svlan_p, pkt_dev->svlan_cfi);
	}

	if (pkt_dev->tos) {
		seq_printf(seq, "     tos: 0x%02x\n", pkt_dev->tos);
	}

	if (pkt_dev->traffic_class) {
		seq_printf(seq, "     traffic_class: 0x%02x\n", pkt_dev->traffic_class);
	}

	if (pkt_dev->burst > 1)
		seq_printf(seq, "     burst: %d\n", pkt_dev->burst);

	if (pkt_dev->node >= 0)
		seq_printf(seq, "     node: %d\n", pkt_dev->node);

	seq_puts(seq, "     Flags: ");

	if (pkt_dev->flags & F_IPV6)
		seq_puts(seq, "IPV6  ");

	if (pkt_dev->flags & F_IPSRC_RND)
		seq_puts(seq, "IPSRC_RND  ");

	if (pkt_dev->flags & F_IPDST_RND)
		seq_puts(seq, "IPDST_RND  ");

	if (pkt_dev->flags & F_TXSIZE_RND)
		seq_puts(seq, "TXSIZE_RND  ");

	if (pkt_dev->flags & F_UDPSRC_RND)
		seq_puts(seq, "UDPSRC_RND  ");

	if (pkt_dev->flags & F_UDPDST_RND)
		seq_puts(seq, "UDPDST_RND  ");

	if (pkt_dev->flags & F_UDPCSUM)
		seq_puts(seq, "UDPCSUM  ");

	if (pkt_dev->flags & F_NO_TIMESTAMP)
		seq_puts(seq, "NO_TIMESTAMP  ");

	if (pkt_dev->flags & F_MPLS_RND)
		seq_puts(seq,  "MPLS_RND  ");

	if (pkt_dev->flags & F_QUEUE_MAP_RND)
		seq_puts(seq,  "QUEUE_MAP_RND  ");

	if (pkt_dev->flags & F_QUEUE_MAP_CPU)
		seq_puts(seq,  "QUEUE_MAP_CPU  ");

	if (pkt_dev->flags & F_PEER_LOCAL)
		seq_puts(seq,  "PEER_LOCAL  ");

	if (pkt_dev->flags & F_USE_REL_TS)
		seq_puts(seq,  "USE_REL_TS  ");

	if (pkt_dev->flags & F_TCP)
		seq_puts(seq,  "TCP  ");

	if (pkt_dev->cflows) {
		if (pkt_dev->flags & F_FLOW_SEQ)
			seq_puts(seq,  "FLOW_SEQ  "); /*in sequence flows*/
		else
			seq_puts(seq,  "FLOW_RND  ");
	}

#ifdef CONFIG_XFRM
	if (pkt_dev->flags & F_IPSEC_ON) {
		seq_puts(seq,  "IPSEC  ");
		if (pkt_dev->spi)
			seq_printf(seq, "spi:%u", pkt_dev->spi);
	}
#endif

	if (pkt_dev->flags & F_MACSRC_RND)
		seq_puts(seq, "MACSRC_RND  ");

	if (pkt_dev->flags & F_MACDST_RND)
		seq_puts(seq, "MACDST_RND  ");

	if (pkt_dev->flags & F_VID_RND)
		seq_puts(seq, "VID_RND  ");

	if (pkt_dev->flags & F_SVID_RND)
		seq_puts(seq, "SVID_RND  ");

	if (pkt_dev->flags & F_NODE)
		seq_puts(seq, "NODE_ALLOC  ");

	seq_puts(seq, "\n");

	sa = pkt_dev->started_at;
	stopped = pkt_dev->stopped_at;
	if (pkt_dev->running)
		stopped = now;	/* not really stopped, more like last-running-at */

	seq_printf(seq,
		   "Current:\n     tx-pkts: %llu  tx-errors: %llu tx-cn: %llu  tx-drop: %llu\n",
		   (unsigned long long)pkt_dev->sofar,
		   (unsigned long long)pkt_dev->errors,
		   (unsigned long long)pkt_dev->xmit_cn,
		   (unsigned long long)pkt_dev->xmit_dropped);

	seq_printf(seq, "    tx-bytes: %llu(%llu)\n",
		   (unsigned long long)pkt_dev->tx_bytes,
		   (unsigned long long)pkt_dev->tx_bytes_ll);


	txq = netdev_get_tx_queue(pkt_dev->odev, pkt_dev->cur_queue_map);
	seq_printf(seq,
		   "     odev: %s  tx-q-map: %i  txq: %p  q-stopped-or-frozen: %i carrier: %i\n",
		   pkt_dev->odevname, pkt_dev->cur_queue_map, txq,
		   netif_xmit_frozen_or_stopped(txq),
		   netif_carrier_ok(pkt_dev->odev));

	seq_printf(seq,
		   "     rx-pkts: %llu  rx-crc-failed: %llu rx-bytes: %llu(%llu) rx-wrong-conn: %llu alloc_skbs: %llu  oom_alloc_skbs: %llu\n",
		   (unsigned long long)pkt_dev->pkts_rcvd,
		   (unsigned long long)pkt_dev->rx_crc_failed,
		   (unsigned long long)pkt_dev->bytes_rcvd,
		   (unsigned long long)pkt_dev->bytes_rcvd_ll,
		   (unsigned long long)pkt_dev->pkts_rcvd_wrong_conn,
		   (unsigned long long)pkt_dev->allocated_skbs,
		   (unsigned long long)pkt_dev->oom_on_alloc_skb);


	seq_printf(seq,
		   "     blocked: %s  next-tx-ns: %llu (%lli)\n     started: %lluus  stopped: %lluus idle: %lluns\n",
		   pkt_dev->tx_blocked ? "TRUE" : "false",
		   (unsigned long long)pkt_dev->next_tx_ns,
		   (long long)(pkt_dev->next_tx_ns - getRelativeCurNs()),
		   (unsigned long long)sa,
		   (unsigned long long)stopped,
		   (unsigned long long)pkt_dev->idle_acc_ns);
	seq_printf(seq,
		   "     nanodelays: %llu  sleeps: %llu  queue_stopped: %llu  tx-early: %llu\n",
		   (unsigned long long)pkt_dev->nanodelays,
		   (unsigned long long)pkt_dev->sleeps,
		   (unsigned long long)pkt_dev->queue_stopped,
		   (unsigned long long)pkt_dev->req_tx_early);

	seq_printf(seq,
		   "     Total-Latency: %lli   Total-pkts-since-latency-clear: %llu  Avg-Jitter: %hu\n",
		   pkt_dev->total_lat, pkt_dev->pkts_rcvd_since_clear_lat, pkt_dev->running_jitter / 1024);
	seq_printf(seq,
		   "     Latency(us): %i - %i - %i [",
		   pkt_dev->min_latency, pkt_dev->avg_latency, pkt_dev->max_latency);
	for (i = 0; i<LAT_BUCKETS_MAX; i++)
		seq_printf(seq, "%llu ", pkt_dev->latency_bkts[i]);
	seq_printf(seq, "]\n     Neg-Latency-Fixups (PEER_LOCAL only): %llu\n",
		   pkt_dev->neg_latency);

	seq_printf(seq,
		   "     seq_num: %d  cur_dst_mac_offset: %d  cur_src_mac_offset: %d\n",
		   pkt_dev->seq_num, pkt_dev->cur_dst_mac_offset,
		   pkt_dev->cur_src_mac_offset);

	if (pkt_dev->flags & F_IPV6) {
		seq_printf(seq, "     cur_saddr: %pI6c  cur_daddr: %pI6c\n",
				&pkt_dev->cur_in6_saddr,
				&pkt_dev->cur_in6_daddr);
	} else
		seq_printf(seq, "     cur_saddr: %pI4  cur_daddr: %pI4\n",
			   &pkt_dev->cur_saddr, &pkt_dev->cur_daddr);

	seq_printf(seq, "     cur_udp_dst: %d  cur_udp_src: %d\n",
		   pkt_dev->cur_udp_dst, pkt_dev->cur_udp_src);

	seq_printf(seq, "     cur_queue_map: %u\n", pkt_dev->cur_queue_map);

	seq_printf(seq, "     flows: %u\n", pkt_dev->nflows);

	if (pkt_dev->result[0])
		seq_printf(seq, "Result: %s\n", pkt_dev->result);
	else
		seq_puts(seq, "Result: Idle\n");

	return 0;
}


static int hex32_arg(const char __user *user_buffer, unsigned long maxlen, __u32 *num)
{
	int i = 0;
	*num = 0;

	for (; i < maxlen; i++) {
		int value;
		char c;
		*num <<= 4;
		if (get_user(c, &user_buffer[i]))
			return -EFAULT;
		value = hex_to_bin(c);
		if (value >= 0)
			*num |= value;
		else
			break;
	}
	return i;
}

static int count_trail_chars(const char __user * user_buffer,
			     unsigned int maxlen)
{
	int i;

	for (i = 0; i < maxlen; i++) {
		char c;
		if (get_user(c, &user_buffer[i]))
			return -EFAULT;
		switch (c) {
		case '\"':
		case '\n':
		case '\r':
		case '\t':
		case ' ':
		case '=':
			break;
		default:
			goto done;
		}
	}
done:
	return i;
}

static long num_arg(const char __user * user_buffer, unsigned long maxlen,
		    unsigned long *num)
{
	int i;
	*num = 0;

	for (i = 0; i < maxlen; i++) {
		char c;
		if (get_user(c, &user_buffer[i]))
			return -EFAULT;
		if ((c >= '0') && (c <= '9')) {
			*num *= 10;
			*num += c - '0';
		} else
			break;
	}
	return i;
}

static int strn_len(const char __user * user_buffer, unsigned int maxlen)
{
	int i;

	for (i = 0; i < maxlen; i++) {
		char c;
		if (get_user(c, &user_buffer[i]))
			return -EFAULT;
		switch (c) {
		case '\"':
		case '\n':
		case '\r':
		case '\t':
		case ' ':
			goto done_str;
		default:
			break;
		}
	}
done_str:
	return i;
}

static ssize_t get_labels(const char __user *buffer, struct pktgen_dev *pkt_dev)
{
	unsigned int n = 0;
	char c;
	ssize_t i = 0;
	int len;

	pkt_dev->nr_labels = 0;
	do {
		__u32 tmp;
		len = hex32_arg(&buffer[i], 8, &tmp);
		if (len <= 0)
			return len;
		pkt_dev->labels[n] = htonl(tmp);
		if (pkt_dev->labels[n] & MPLS_STACK_BOTTOM)
			pkt_dev->flags |= F_MPLS_RND;
		i += len;
		if (get_user(c, &buffer[i]))
			return -EFAULT;
		i++;
		n++;
		if (n >= MAX_MPLS_LABELS)
			return -E2BIG;
	} while (c == ',');

	pkt_dev->nr_labels = n;
	return i;
}

static ssize_t pktgen_if_write(struct file *file,
			       const char __user * user_buffer, size_t count,
			       loff_t * offset)
{
	struct seq_file *seq = (struct seq_file *)file->private_data;
	struct pktgen_dev *pkt_dev = seq->private;
	int i, max, len;
	char name[16], valstr[32];
	unsigned long value = 0;
	char *pg_result = NULL;
	int tmp = 0;
	char buf[128];

	pg_result = &(pkt_dev->result[0]);

	if (count < 1) {
		printk(KERN_WARNING "pktgen: wrong command format\n");
		return -EINVAL;
	}

	max = count;
	tmp = count_trail_chars(user_buffer, max);
	if (tmp < 0) {
		printk(KERN_WARNING "pktgen: illegal format\n");
		return tmp;
	}
	i = tmp;

	/* Read variable name */

	len = strn_len(&user_buffer[i], sizeof(name) - 1);
	if (len < 0) {
		return len;
	}
	memset(name, 0, sizeof(name));
	if (copy_from_user(name, &user_buffer[i], len))
		return -EFAULT;
	i += len;

	max = count - i;
	len = count_trail_chars(&user_buffer[i], max);
	if (len < 0)
		return len;

	i += len;

	if (debug) {
		size_t copy = min_t(size_t, count + 1, 1024);
		char *tp = strndup_user(user_buffer, copy);

		if (IS_ERR(tp))
			return PTR_ERR(tp);

		pr_debug("%s,%zu  buffer -:%s:-\n", name, count, tp);
		kfree(tp);
	}

	if (!strcmp(name, "min_pkt_size")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value < 14 + 20 + 8)
			value = 14 + 20 + 8;
		if (value != pkt_dev->min_pkt_size) {
			pkt_dev->min_pkt_size = value;
			pkt_dev->cur_pkt_size = value;
		}
		sprintf(pg_result, "OK: min_pkt_size=%u",
			pkt_dev->min_pkt_size);
		return count;
	}

	if (!strcmp(name, "max_pkt_size")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value < 14 + 20 + 8)
			value = 14 + 20 + 8;
		if (value != pkt_dev->max_pkt_size) {
			pkt_dev->max_pkt_size = value;
			pkt_dev->cur_pkt_size = value;
		}
		sprintf(pg_result, "OK: max_pkt_size=%u",
			pkt_dev->max_pkt_size);
		return count;
	}

	/* Shortcut for min = max */

	if (!strcmp(name, "pkt_size")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value < 14 + 20 + 8)
			value = 14 + 20 + 8;
		if (value != pkt_dev->min_pkt_size) {
			pkt_dev->min_pkt_size = value;
			pkt_dev->max_pkt_size = value;
			pkt_dev->cur_pkt_size = value;
		}
		sprintf(pg_result, "OK: pkt_size=%u", pkt_dev->min_pkt_size);
		return count;
	}

	if (!strcmp(name, "debug")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		debug = value;
		sprintf(pg_result, "OK: debug=%u", debug);
		return count;
	}

	if (!strcmp(name, "frags")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->nfrags = value;
		sprintf(pg_result, "OK: frags=%u", pkt_dev->nfrags);
		return count;
	}

	/* This is basically a flush..causes new skb to be generated, regardless of
	 * current clone count.
	 */
	if (!strcmp(name, "force_new_skb")) {
		/* If this is our first flush, then we just started, and we need to set up
		 * the dup_since_incr to work properly.
		 */
		if (!pkt_dev->flushed_already) {
			pkt_dev->dup_since_incr = pkt_dev->peer_clone_skb - 1;
			pkt_dev->flushed_already = 1;
		}
		pkt_dev->force_new_skb = 1;
		sprintf(pg_result, "OK: Forcing new SKB.\n");

		return count;
	}

	if (!strcmp(name, "delay")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;

		/* If we are quiescing, then force delay to be quiesce value:
		 * Maybe user-space hasn't noticed yet.
		 */
		if ((pkt_dev->count != 0) && (pkt_dev->sofar >= pkt_dev->count)) {
			value = 0x7FFFFFFF;
		}

		/* If we are going from quiesce to running, We want to start with a new
		 * SKB right now, instead of waiting for multi-skb to take affect.
		 */
		if ((pkt_dev->delay_ns == 0x7FFFFFFF) &&
		    value != 0x7FFFFFFF)
			pkt_dev->force_new_skb = 1;

		pkt_dev->delay_ns = value;
		if ((getRelativeCurNs() + pkt_dev->delay_ns) < pkt_dev->next_tx_ns) {
			pkt_dev->next_tx_ns = getRelativeCurNs() + pkt_dev->delay_ns;
		}

		/* Break out of sleep loop if we were in it. */
		pkt_dev->accum_delay_ns = 0;

		sprintf(pg_result, "OK: delay=%lluns", (unsigned long long)pkt_dev->delay_ns);
		return count;
	}
	if (!strcmp(name, "udp_src_min")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value != pkt_dev->udp_src_min) {
			pkt_dev->udp_src_min = value;
			pkt_dev->cur_udp_src = value;
		}
		sprintf(pg_result, "OK: udp_src_min=%u", pkt_dev->udp_src_min);
		return count;
	}
	if (!strcmp(name, "udp_dst_min")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value != pkt_dev->udp_dst_min) {
			pkt_dev->udp_dst_min = value;
			pkt_dev->cur_udp_dst = value;
		}
		sprintf(pg_result, "OK: udp_dst_min=%u", pkt_dev->udp_dst_min);
		return count;
	}
	if (!strcmp(name, "udp_src_max")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value != pkt_dev->udp_src_max) {
			pkt_dev->udp_src_max = value;
			pkt_dev->cur_udp_src = value;
		}
		sprintf(pg_result, "OK: udp_src_max=%u", pkt_dev->udp_src_max);
		return count;
	}
	if (!strcmp(name, "udp_dst_max")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value != pkt_dev->udp_dst_max) {
			pkt_dev->udp_dst_max = value;
			pkt_dev->cur_udp_dst = value;
		}
		sprintf(pg_result, "OK: udp_dst_max=%u", pkt_dev->udp_dst_max);
		return count;
	}
        if (!strcmp(name, "conn_id")) {
                len = num_arg(&user_buffer[i], 10, &value);
                if (len < 0) {
                        return len;
                }
                i += len;
                pkt_dev->conn_id = value;

                sprintf(pg_result, "OK: conn_id=%d", pkt_dev->conn_id);
                return count;
        }
        if (!strcmp(name, "peer_conn_id")) {
                len = num_arg(&user_buffer[i], 10, &value);
                if (len < 0) {
                        return len;
                }
                i += len;
                pkt_dev->peer_conn_id = value;

                sprintf(pg_result, "OK: peer_conn_id=%d", pkt_dev->peer_conn_id);
                return count;
        }

	if (!strcmp(name, "clone_skb")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0)
			return len;
		if ((value > 0) &&
		    (!(pkt_dev->odev->priv_flags & IFF_TX_SKB_SHARING)))
			return -ENOTSUPP;
		i += len;
		pkt_dev->clone_skb = value;

		sprintf(pg_result, "OK: clone_skb=%d", pkt_dev->clone_skb);
		return count;
	}
	if (!strcmp(name, "peer_clone_skb")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->peer_clone_skb = value;

		sprintf(pg_result, "OK: peer_clone_skb=%d", pkt_dev->peer_clone_skb);
		return count;
	}
	if (!strcmp(name, "count")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->count = value;
		sprintf(pg_result, "OK: count=%llu",
			(unsigned long long)pkt_dev->count);
		return count;
	}
	if (!strcmp(name, "src_mac_count")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (pkt_dev->src_mac_count != value) {
			pkt_dev->src_mac_count = value;
			pkt_dev->cur_src_mac_offset = 0;
		}
		sprintf(pg_result, "OK: src_mac_count=%d",
			pkt_dev->src_mac_count);
		return count;
	}
	if (!strcmp(name, "dst_mac_count")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (pkt_dev->dst_mac_count != value) {
			pkt_dev->dst_mac_count = value;
			pkt_dev->cur_dst_mac_offset = 0;
		}
		sprintf(pg_result, "OK: dst_mac_count=%d",
			pkt_dev->dst_mac_count);
		return count;
	}
	if (!strcmp(name, "burst")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0)
			return len;

		i += len;
		if ((value > 1) &&
		    (!(pkt_dev->odev->priv_flags & IFF_TX_SKB_SHARING)))
			return -ENOTSUPP;
		pkt_dev->burst = value < 1 ? 1 : value;
		sprintf(pg_result, "OK: burst=%d", pkt_dev->burst);
		return count;
	}
	if (!strcmp(name, "node")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0)
			return len;

		i += len;

		if (node_possible(value)) {
			pkt_dev->node = value;
			sprintf(pg_result, "OK: node=%d", pkt_dev->node);
			if (pkt_dev->page) {
				put_page(pkt_dev->page);
				pkt_dev->page = NULL;
			}
		}
		else
			sprintf(pg_result, "ERROR: node not possible");
		return count;
	}
	if (!strcmp(name, "flag")) {
		char f[32];
		memset(f, 0, 32);
		len = strn_len(&user_buffer[i], sizeof(f) - 1);
		if (len < 0) {
			return len;
		}
		if (copy_from_user(f, &user_buffer[i], len))
			return -EFAULT;
		i += len;
		if (strcmp(f, "IPSRC_RND") == 0)
			pkt_dev->flags |= F_IPSRC_RND;

		else if (strcmp(f, "!IPSRC_RND") == 0)
			pkt_dev->flags &= ~F_IPSRC_RND;

		else if (strcmp(f, "TXSIZE_RND") == 0)
			pkt_dev->flags |= F_TXSIZE_RND;

		else if (strcmp(f, "!TXSIZE_RND") == 0)
			pkt_dev->flags &= ~F_TXSIZE_RND;

		else if (strcmp(f, "IPDST_RND") == 0)
			pkt_dev->flags |= F_IPDST_RND;

		else if (strcmp(f, "!IPDST_RND") == 0)
			pkt_dev->flags &= ~F_IPDST_RND;

		else if (strcmp(f, "UDPSRC_RND") == 0)
			pkt_dev->flags |= F_UDPSRC_RND;

		else if (strcmp(f, "!UDPSRC_RND") == 0)
			pkt_dev->flags &= ~F_UDPSRC_RND;

		else if (strcmp(f, "UDPDST_RND") == 0)
			pkt_dev->flags |= F_UDPDST_RND;

		else if ((strcmp(f, "UDPCSUM") == 0) ||
			 (strcmp(f, "CSUM") == 0))
			pkt_dev->flags |= F_UDPCSUM;

		else if ((strcmp(f, "!UDPCSUM") == 0) ||
			 (strcmp(f, "!CSUM") == 0))
			pkt_dev->flags &= ~F_UDPCSUM;

		else if (strcmp(f, "NO_TIMESTAMP") == 0)
			pkt_dev->flags |= F_NO_TIMESTAMP;

		else if (strcmp(f, "!NO_TIMESTAMP") == 0)
			pkt_dev->flags &= ~F_NO_TIMESTAMP;

		else if (strcmp(f, "!UDPDST_RND") == 0)
			pkt_dev->flags &= ~F_UDPDST_RND;

		else if (strcmp(f, "MACSRC_RND") == 0)
			pkt_dev->flags |= F_MACSRC_RND;

		else if (strcmp(f, "!MACSRC_RND") == 0)
			pkt_dev->flags &= ~F_MACSRC_RND;

		else if (strcmp(f, "MACDST_RND") == 0)
			pkt_dev->flags |= F_MACDST_RND;

		else if (strcmp(f, "!MACDST_RND") == 0)
			pkt_dev->flags &= ~F_MACDST_RND;

		else if (strcmp(f, "MPLS_RND") == 0)
			pkt_dev->flags |= F_MPLS_RND;

		else if (strcmp(f, "!MPLS_RND") == 0)
			pkt_dev->flags &= ~F_MPLS_RND;

		else if (strcmp(f, "VID_RND") == 0)
			pkt_dev->flags |= F_VID_RND;

		else if (strcmp(f, "!VID_RND") == 0)
			pkt_dev->flags &= ~F_VID_RND;

		else if (strcmp(f, "SVID_RND") == 0)
			pkt_dev->flags |= F_SVID_RND;

		else if (strcmp(f, "!SVID_RND") == 0)
			pkt_dev->flags &= ~F_SVID_RND;

		else if (strcmp(f, "FLOW_SEQ") == 0 || strcmp(f, "!FLOW_RND") == 0)
			pkt_dev->flags |= F_FLOW_SEQ;

		else if (strcmp(f, "FLOW_RND") == 0 || strcmp(f, "!FLOW_SEQ") == 0)
			pkt_dev->flags &= ~F_FLOW_SEQ;

		else if (strcmp(f, "QUEUE_MAP_RND") == 0)
			pkt_dev->flags |= F_QUEUE_MAP_RND;

		else if (strcmp(f, "!QUEUE_MAP_RND") == 0)
			pkt_dev->flags &= ~F_QUEUE_MAP_RND;

		else if (strcmp(f, "QUEUE_MAP_CPU") == 0)
			pkt_dev->flags |= F_QUEUE_MAP_CPU;

		else if (strcmp(f, "!QUEUE_MAP_CPU") == 0)
			pkt_dev->flags &= ~F_QUEUE_MAP_CPU;

		else if (strcmp(f, "PEER_LOCAL") == 0)
			pkt_dev->flags |= F_PEER_LOCAL;

		else if (strcmp(f, "!PEER_LOCAL") == 0)
			pkt_dev->flags &= ~F_PEER_LOCAL;

		else if (strcmp(f, "USE_REL_TS") == 0) {
			if (pkt_dev->running && !(pkt_dev->flags & F_USE_REL_TS)) {
				if (!use_rel_ts++)
					pkt_dev->next_tx_ns = getRelativeCurNs();
			}
			pkt_dev->flags |= F_USE_REL_TS;
		}
		else if (strcmp(f, "!USE_REL_TS") == 0) {
			if (pkt_dev->running && (pkt_dev->flags & F_USE_REL_TS))
				if (use_rel_ts--)
					pkt_dev->next_tx_ns = getRelativeCurNs();
			pkt_dev->flags &= ~F_USE_REL_TS;
		}
#ifdef CONFIG_XFRM
		else if (strcmp(f, "IPSEC") == 0)
			pkt_dev->flags |= F_IPSEC_ON;
		else if (strcmp(f, "!IPSEC") == 0)
			pkt_dev->flags &= ~F_IPSEC_ON;
#endif

		else if (strcmp(f, "!IPV6") == 0)
			pkt_dev->flags &= ~F_IPV6;

		else if (strcmp(f, "NODE_ALLOC") == 0)
			pkt_dev->flags |= F_NODE;

		else if (strcmp(f, "!NODE_ALLOC") == 0)
			pkt_dev->flags &= ~F_NODE;

		else if (strcmp(f, "TCP") == 0)
			pkt_dev->flags |= F_TCP;

		else if (strcmp(f, "!TCP") == 0)
			pkt_dev->flags &= ~F_TCP;

		else {
			printk("pktgen: Flag -:%s:- unknown\n", f);
			sprintf(pg_result,
				"Flag -:%s:- unknown\nAvailable flags, (prepend ! to un-set flag):\n%s",
				f,
				"IPSRC_RND, IPDST_RND, UDPSRC_RND, UDPDST_RND, "
				"MACSRC_RND, MACDST_RND, TXSIZE_RND, IPV6, "
				"MPLS_RND, VID_RND, SVID_RND, FLOW_SEQ, "
				"QUEUE_MAP_RND, QUEUE_MAP_CPU, UDPCSUM, "
				"NO_TIMESTAMP, "
#ifdef CONFIG_XFRM
				"IPSEC, "
#endif
				"NODE_ALLOC\n");
			return count;
		}
		sprintf(pg_result, "OK: flags=0x%x", pkt_dev->flags);
		return count;
	}
	if (!strcmp(name, "dst_min") || !strcmp(name, "dst")) {
		len = strn_len(&user_buffer[i], sizeof(pkt_dev->dst_min) - 1);
		if (len < 0) {
			return len;
		}

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;
		if (strcmp(buf, pkt_dev->dst_min) != 0) {
			memset(pkt_dev->dst_min, 0, sizeof(pkt_dev->dst_min));
			strcpy(pkt_dev->dst_min, buf);
			pkt_dev->daddr_min = in_aton(pkt_dev->dst_min);
			pkt_dev->cur_daddr = pkt_dev->daddr_min;
		}
		if (debug)
			pr_debug("dst_min set to: %s\n", pkt_dev->dst_min);
		i += len;
		sprintf(pg_result, "OK: dst_min=%s", pkt_dev->dst_min);
		return count;
	}
	if (!strcmp(name, "dst_max")) {
		len = strn_len(&user_buffer[i], sizeof(pkt_dev->dst_max) - 1);
		if (len < 0) {
			return len;
		}

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;

		buf[len] = 0;
		if (strcmp(buf, pkt_dev->dst_max) != 0) {
			memset(pkt_dev->dst_max, 0, sizeof(pkt_dev->dst_max));
			strcpy(pkt_dev->dst_max, buf);
			pkt_dev->daddr_max = in_aton(pkt_dev->dst_max);
			pkt_dev->cur_daddr = pkt_dev->daddr_max;
		}
		if (debug)
			pr_debug("dst_max set to: %s\n", pkt_dev->dst_max);
		i += len;
		sprintf(pg_result, "OK: dst_max=%s", pkt_dev->dst_max);
		return count;
	}
	if (!strcmp(name, "dst6")) {
		len = strn_len(&user_buffer[i], sizeof(buf) - 1);
		if (len < 0)
			return len;

		pkt_dev->flags |= F_IPV6;

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;

		in6_pton(buf, -1, pkt_dev->in6_daddr.s6_addr, -1, NULL);
		snprintf(buf, sizeof(buf), "%pI6c", &pkt_dev->in6_daddr);

		pkt_dev->cur_in6_daddr = pkt_dev->in6_daddr;

		if (debug)
			pr_debug("dst6 set to: %s\n", buf);

		i += len;
		sprintf(pg_result, "OK: dst6=%s", buf);
		return count;
	}
	if (!strcmp(name, "dst6_min")) {
		len = strn_len(&user_buffer[i], sizeof(buf) - 1);
		if (len < 0)
			return len;

		pkt_dev->flags |= F_IPV6;

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;

		in6_pton(buf, -1, pkt_dev->min_in6_daddr.s6_addr, -1, NULL);
		snprintf(buf, sizeof(buf), "%pI6c", &pkt_dev->min_in6_daddr);

		pkt_dev->cur_in6_daddr = pkt_dev->min_in6_daddr;
		if (debug)
			pr_debug("dst6_min set to: %s\n", buf);

		i += len;
		sprintf(pg_result, "OK: dst6_min=%s", buf);
		return count;
	}
	if (!strcmp(name, "dst6_max")) {
		len = strn_len(&user_buffer[i], sizeof(buf) - 1);
		if (len < 0)
			return len;

		pkt_dev->flags |= F_IPV6;

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;

		in6_pton(buf, -1, pkt_dev->max_in6_daddr.s6_addr, -1, NULL);
		snprintf(buf, sizeof(buf), "%pI6c", &pkt_dev->max_in6_daddr);

		if (debug)
			pr_debug("dst6_max set to: %s\n", buf);

		i += len;
		sprintf(pg_result, "OK: dst6_max=%s", buf);
		return count;
	}
	if (!strcmp(name, "src6")) {
		len = strn_len(&user_buffer[i], sizeof(buf) - 1);
		if (len < 0)
			return len;

		pkt_dev->flags |= F_IPV6;

		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;

		in6_pton(buf, -1, pkt_dev->in6_saddr.s6_addr, -1, NULL);
		snprintf(buf, sizeof(buf), "%pI6c", &pkt_dev->in6_saddr);

		pkt_dev->cur_in6_saddr = pkt_dev->in6_saddr;

		if (debug)
			pr_debug("src6 set to: %s\n", buf);

		i += len;
		sprintf(pg_result, "OK: src6=%s", buf);
		return count;
	}
	if (!strcmp(name, "src_min")) {
		len = strn_len(&user_buffer[i], sizeof(pkt_dev->src_min) - 1);
		if (len < 0) {
			return len;
		}
		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;
		if (strcmp(buf, pkt_dev->src_min) != 0) {
			memset(pkt_dev->src_min, 0, sizeof(pkt_dev->src_min));
			strcpy(pkt_dev->src_min, buf);
			pkt_dev->saddr_min = in_aton(pkt_dev->src_min);
			pkt_dev->cur_saddr = pkt_dev->saddr_min;
		}
		if (debug)
			pr_debug("src_min set to: %s\n", pkt_dev->src_min);
		i += len;
		sprintf(pg_result, "OK: src_min=%s", pkt_dev->src_min);
		return count;
	}
	if (!strcmp(name, "src_max")) {
		len = strn_len(&user_buffer[i], sizeof(pkt_dev->src_max) - 1);
		if (len < 0) {
			return len;
		}
		if (copy_from_user(buf, &user_buffer[i], len))
			return -EFAULT;
		buf[len] = 0;
		if (strcmp(buf, pkt_dev->src_max) != 0) {
			memset(pkt_dev->src_max, 0, sizeof(pkt_dev->src_max));
			strcpy(pkt_dev->src_max, buf);
			pkt_dev->saddr_max = in_aton(pkt_dev->src_max);
			pkt_dev->cur_saddr = pkt_dev->saddr_max;
		}
		if (debug)
			pr_debug("src_max set to: %s\n", pkt_dev->src_max);
		i += len;
		sprintf(pg_result, "OK: src_max=%s", pkt_dev->src_max);
		return count;
	}
	if (!strcmp(name, "dst_mac")) {
		len = strn_len(&user_buffer[i], sizeof(valstr) - 1);
		if (len < 0) {
			return len;
		}
		memset(valstr, 0, sizeof(valstr));
		if (copy_from_user(valstr, &user_buffer[i], len))
			return -EFAULT;

		if (!mac_pton(valstr, pkt_dev->dst_mac))
			return -EINVAL;
		/* Set up Dest MAC */
		ether_addr_copy(&pkt_dev->hh[0], pkt_dev->dst_mac);
		sprintf(pg_result, "OK: dstmac %pM", pkt_dev->dst_mac);
		return count;
	}
	if (!strcmp(name, "src_mac")) {
		len = strn_len(&user_buffer[i], sizeof(valstr) - 1);
		if (len < 0) {
			return len;
		}
		memset(valstr, 0, sizeof(valstr));
		if (copy_from_user(valstr, &user_buffer[i], len))
			return -EFAULT;

		if (!mac_pton(valstr, pkt_dev->src_mac))
			return -EINVAL;
		/* Set up Src MAC */
		ether_addr_copy(&pkt_dev->hh[6], pkt_dev->src_mac);
		sprintf(pg_result, "OK: srcmac %pM", pkt_dev->src_mac);
		return count;
	}

	if (!strcmp(name, "clear_counters")) {
		pktgen_clear_counters(pkt_dev, 0, "proc-write");
		sprintf(pg_result, "OK: Clearing counters.\n");
		return count;
	}

	if (!strcmp(name, "clear_latencies")) {
		pg_reset_latency_counters(pkt_dev);
		sprintf(pg_result, "OK: Clearing latency.\n");
		return count;
	}

	if (!strcmp(name, "flows")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value > MAX_CFLOWS)
			value = MAX_CFLOWS;

		pkt_dev->cflows = value;
		sprintf(pg_result, "OK: flows=%u", pkt_dev->cflows);
		return count;
	}

#ifdef CONFIG_XFRM
	if (!strcmp(name, "spi")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0)
			return len;

		i += len;
		pkt_dev->spi = value;
		sprintf(pg_result, "OK: spi=%u", pkt_dev->spi);
		return count;
	}
#endif

	if (!strcmp(name, "flowlen")) {
		len = num_arg(&user_buffer[i], 10, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->lflow = value;
		sprintf(pg_result, "OK: flowlen=%u", pkt_dev->lflow);
		return count;
	}

	if (!strcmp(name, "queue_map_min")) {
		len = num_arg(&user_buffer[i], 5, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->queue_map_min = value;
		sprintf(pg_result, "OK: queue_map_min=%u", pkt_dev->queue_map_min);
		return count;
	}

	if (!strcmp(name, "queue_map_max")) {
		len = num_arg(&user_buffer[i], 5, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		pkt_dev->queue_map_max = value;
		sprintf(pg_result, "OK: queue_map_max=%u", pkt_dev->queue_map_max);
		return count;
	}

	if (!strcmp(name, "mpls")) {
		unsigned int n, cnt;
		len = get_labels(&user_buffer[i], pkt_dev);
		if (len < 0)
			return len;

		i += len;
		cnt = sprintf(pg_result, "OK: mpls=");
		for (n = 0; n < pkt_dev->nr_labels; n++)
			cnt += sprintf(pg_result + cnt,
				       "%08x%s", ntohl(pkt_dev->labels[n]),
				       n == pkt_dev->nr_labels-1 ? "" : ",");

		if (pkt_dev->nr_labels && pkt_dev->vlan_id != 0xffff) {
			pkt_dev->vlan_id = 0xffff; /* turn off VLAN/SVLAN */
			pkt_dev->svlan_id = 0xffff;

			if (debug)
				pr_debug("VLAN/SVLAN auto turned off\n");
		}
		return count;
	}

	if (!strcmp(name, "vlan_id")) {
		len = num_arg(&user_buffer[i], 4, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (value <= 4095) {
			pkt_dev->vlan_id = value;  /* turn on VLAN */

			if (debug)
				pr_debug("VLAN turned on\n");

			if (debug && pkt_dev->nr_labels)
				pr_debug("MPLS auto turned off\n");

			pkt_dev->nr_labels = 0;    /* turn off MPLS */
			sprintf(pg_result, "OK: vlan_id=%u", pkt_dev->vlan_id);
		} else {
			pkt_dev->vlan_id = 0xffff; /* turn off VLAN/SVLAN */
			pkt_dev->svlan_id = 0xffff;

			if (debug)
				pr_debug("VLAN/SVLAN turned off\n");
		}
		return count;
	}

	if (!strcmp(name, "vlan_p")) {
		len = num_arg(&user_buffer[i], 1, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if ((value <= 7) && (pkt_dev->vlan_id != 0xffff)) {
			pkt_dev->vlan_p = value;
			sprintf(pg_result, "OK: vlan_p=%u", pkt_dev->vlan_p);
		} else {
			sprintf(pg_result, "ERROR: vlan_p must be 0-7");
		}
		return count;
	}

	if (!strcmp(name, "vlan_cfi")) {
		len = num_arg(&user_buffer[i], 1, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if ((value <= 1) && (pkt_dev->vlan_id != 0xffff)) {
			pkt_dev->vlan_cfi = value;
			sprintf(pg_result, "OK: vlan_cfi=%u", pkt_dev->vlan_cfi);
		} else {
			sprintf(pg_result, "ERROR: vlan_cfi must be 0-1");
		}
		return count;
	}

	if (!strcmp(name, "svlan_id")) {
		len = num_arg(&user_buffer[i], 4, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if ((value <= 4095) && ((pkt_dev->vlan_id != 0xffff))) {
			pkt_dev->svlan_id = value;  /* turn on SVLAN */

			if (debug)
				pr_debug("SVLAN turned on\n");

			if (debug && pkt_dev->nr_labels)
				pr_debug("MPLS auto turned off\n");

			pkt_dev->nr_labels = 0;    /* turn off MPLS */
			sprintf(pg_result, "OK: svlan_id=%u", pkt_dev->svlan_id);
		} else {
			pkt_dev->vlan_id = 0xffff; /* turn off VLAN/SVLAN */
			pkt_dev->svlan_id = 0xffff;

			if (debug)
				pr_debug("VLAN/SVLAN turned off\n");
		}
		return count;
	}

	if (!strcmp(name, "svlan_p")) {
		len = num_arg(&user_buffer[i], 1, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if ((value <= 7) && (pkt_dev->svlan_id != 0xffff)) {
			pkt_dev->svlan_p = value;
			sprintf(pg_result, "OK: svlan_p=%u", pkt_dev->svlan_p);
		} else {
			sprintf(pg_result, "ERROR: svlan_p must be 0-7");
		}
		return count;
	}

	if (!strcmp(name, "svlan_cfi")) {
		len = num_arg(&user_buffer[i], 1, &value);
		if (len < 0) {
			return len;
		}
		i += len;
		if ((value <= 1) && (pkt_dev->svlan_id != 0xffff)) {
			pkt_dev->svlan_cfi = value;
			sprintf(pg_result, "OK: svlan_cfi=%u", pkt_dev->svlan_cfi);
		} else {
			sprintf(pg_result, "ERROR: svlan_cfi must be 0-1");
		}
		return count;
	}

	if (!strcmp(name, "tos")) {
		__u32 tmp_value = 0;
		len = hex32_arg(&user_buffer[i], 2, &tmp_value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (len == 2) {
			pkt_dev->tos = tmp_value;
			sprintf(pg_result, "OK: tos=0x%02x", pkt_dev->tos);
		} else {
			sprintf(pg_result, "ERROR: tos must be 00-ff");
		}
		return count;
	}

	if (!strcmp(name, "traffic_class")) {
		__u32 tmp_value = 0;
		len = hex32_arg(&user_buffer[i], 2, &tmp_value);
		if (len < 0) {
			return len;
		}
		i += len;
		if (len == 2) {
			pkt_dev->traffic_class = tmp_value;
			sprintf(pg_result, "OK: traffic_class=0x%02x", pkt_dev->traffic_class);
		} else {
			sprintf(pg_result, "ERROR: traffic_class must be 00-ff");
		}
		return count;
	}

	if (!strcmp(name, "skb_priority")) {
		len = num_arg(&user_buffer[i], 9, &value);
		if (len < 0)
			return len;

		i += len;
		pkt_dev->skb_priority = value;
		sprintf(pg_result, "OK: skb_priority=%i",
			pkt_dev->skb_priority);
		return count;
	}

	printk("pktgen: No such parameter \"%s\"\n", name);
	sprintf(pkt_dev->result, "No such parameter \"%s\"", name);
	return -EINVAL;
}

static int pktgen_if_open(struct inode *inode, struct file *file)
{
	return single_open(file, pktgen_if_show, PDE_DATA(inode));
}

static const struct proc_ops pktgen_if_proc_ops = {
	.proc_open	= pktgen_if_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= pktgen_if_write,
	.proc_release	= single_release,
	.proc_ioctl     = pktgen_proc_ioctl,
};

static int pktgen_thread_show(struct seq_file *seq, void *v)
{
	struct pktgen_thread *t = seq->private;
	const struct pktgen_dev *pkt_dev;

	BUG_ON(!t);

	mutex_lock(&pktgen_thread_lock);
	/* versioning info.  CFG_RT means we do not busy-spin, so can be configured for
	 * real-time scheduling if user-space so desires. */
	seq_printf(seq, "VERSION-2 CFG_RT\n");
	seq_printf(seq, "PID: %d Name: %s  use_rel_ts: %i  nqw_callbacks:  %lu  nqw_wakeups: %lu\n",
		   t->pid, t->tsk->comm, use_rel_ts, t->nqw_callbacks, t->nqw_wakeups);
	seq_printf(seq, "  Sleeping: %i\n",
		   t->sleeping);

	seq_printf(seq, "Running: ");

	list_for_each_entry(pkt_dev, &t->if_list, list)
		if (pkt_dev->running)
			seq_printf(seq, "%s ", pkt_dev->odevname);

	seq_puts(seq, "\nStopped: ");

	list_for_each_entry(pkt_dev, &t->if_list, list)
		if (!pkt_dev->running)
			seq_printf(seq, "%s ", pkt_dev->odevname);

	if (t->result[0])
		seq_printf(seq, "\nResult: %s\n", t->result);
	else
		seq_puts(seq, "\nResult: NA\n");

	mutex_unlock(&pktgen_thread_lock);
	return 0;
}

static ssize_t pktgen_thread_write(struct file *file,
				   const char __user * user_buffer,
				   size_t count, loff_t * offset)
{
	struct seq_file *seq = (struct seq_file *)file->private_data;
	struct pktgen_thread *t = seq->private;
	int i, max, len, ret;
	char name[40];
	char *pg_result;

	if (count < 1)
		return -EINVAL;

	max = count;
	len = count_trail_chars(user_buffer, max);
	if (len < 0)
		return len;

	i = len;

	/* Read variable name */

	len = strn_len(&user_buffer[i], sizeof(name) - 1);
	if (len < 0)
		return len;

	memset(name, 0, sizeof(name));
	if (copy_from_user(name, &user_buffer[i], len))
		return -EFAULT;
	i += len;

	max = count - i;
	len = count_trail_chars(&user_buffer[i], max);
	if (len < 0)
		return len;

	i += len;

	if (debug)
		pr_debug("t=%s, count=%lu\n", name, (unsigned long)count);

	if (!t) {
		printk(KERN_ERR "pktgen: ERROR: No thread\n");
		ret = -EINVAL;
		goto out;
	}

	pg_result = &(t->result[0]);

	if (!strcmp(name, "add_device")) {
		char f[32];
		memset(f, 0, 32);
		len = strn_len(&user_buffer[i], sizeof(f) - 1);
		if (len < 0) {
			ret = len;
			goto out;
		}
		if (copy_from_user(f, &user_buffer[i], len))
			return -EFAULT;
		i += len;
		mutex_lock(&pktgen_thread_lock);
		t->control_arg = f;
		t->control |= T_ADD_DEV;
		while (t->control & T_ADD_DEV) {
			schedule_timeout_interruptible(msecs_to_jiffies(10));
		}
		t->control_arg = 0;
		mutex_unlock(&pktgen_thread_lock);
		ret = count;
		sprintf(pg_result, "OK: add_device=%s", f);
		goto out;
	}

	if (!strcmp(name, "rem_device")) {
		char f[32];
		memset(f, 0, 32);
		len = strn_len(&user_buffer[i], sizeof(f) - 1);
		if (len < 0) {
			ret = len;
			goto out;
		}
		if (copy_from_user(f, &user_buffer[i], len))
			return -EFAULT;
		i += len;
		pktgen_mark_device(t->net, f);
		ret = count;
		sprintf(pg_result, "OK: rem_device=%s", f);
		goto out;
	}

	if (!strcmp(name, "rem_device_all")) {
		mutex_lock(&pktgen_thread_lock);
		t->control |= T_REMDEVALL;
		mutex_unlock(&pktgen_thread_lock);
		while (t->control & T_REMDEVALL) {
			schedule_timeout_interruptible(msecs_to_jiffies(10));
		}
		ret = count;
		sprintf(pg_result, "OK: rem_device_all");
		goto out;
	}

	if (!strcmp(name, "max_before_softirq")) {
		 ret = count;
                sprintf(pg_result, "ERROR: max_before_softirq no longer supported");
                goto out;
        }

	printk("pktgen:  un-known command to pktgen_thread: -:%s:-\n", name);

	ret = -EINVAL;
out:
	return ret;
}

static int pktgen_thread_open(struct inode *inode, struct file *file)
{
	return single_open(file, pktgen_thread_show, PDE_DATA(inode));
}

static const struct proc_ops pktgen_thread_proc_ops = {
	.proc_open	= pktgen_thread_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= pktgen_thread_write,
	.proc_release	= single_release,
	.proc_ioctl     = pktgen_proc_ioctl,
};

/* Think find or remove for NN */
static struct pktgen_dev *__pktgen_NN_threads(const struct pktgen_net *pn,
					      const char *ifname, int remove)
{
	struct pktgen_thread *t;
	struct pktgen_dev *pkt_dev = NULL;
	bool exact = (remove == FIND);

	list_for_each_entry(t, &pn->pktgen_threads, th_list) {
		pkt_dev = pktgen_find_dev(t, ifname, exact);
		if (pkt_dev) {
			if (remove) {
				pkt_dev->removal_mark = 1;
				t->control |= T_REMDEV;
			}
			break;
		}
	}
	return pkt_dev;
}

/*
 * mark a device for removal
 */
static void pktgen_mark_device(const struct pktgen_net *pn, const char *ifname)
{
	struct pktgen_dev *pkt_dev = NULL;
	const int max_tries = 10, msec_per_try = 125;
	int i = 0;

	mutex_lock(&pktgen_thread_lock);
	pr_debug("pktgen: pktgen_mark_device marking %s for removal\n", ifname);

	while (1) {

		pkt_dev = __pktgen_NN_threads(pn, ifname, REMOVE);
		if (pkt_dev == NULL)
			break;	/* success */

		mutex_unlock(&pktgen_thread_lock);
		pr_debug("pktgen: pktgen_mark_device waiting for %s to disappear....\n",
			 ifname);
		schedule_timeout_interruptible(msecs_to_jiffies(msec_per_try));
		mutex_lock(&pktgen_thread_lock);

		if (++i >= max_tries) {
			printk(KERN_ERR "pktgen_mark_device: timed out after "
			       "waiting %d msec for device %s to be removed\n",
			       msec_per_try * i, ifname);
			break;
		}
	}

	mutex_unlock(&pktgen_thread_lock);
}

static void pktgen_change_name(const struct pktgen_net *pn, struct net_device *dev)
{
	struct pktgen_thread *t;

	list_for_each_entry(t, &pn->pktgen_threads, th_list) {
		struct pktgen_dev *pkt_dev;

		list_for_each_entry(pkt_dev, &t->if_list, list) {
			if (pkt_dev->odev != dev)
				continue;

			proc_remove(pkt_dev->entry);

			pkt_dev->entry = proc_create_data(dev->name, 0600,
							  pn->proc_dir,
							  &pktgen_if_proc_ops,
							  pkt_dev);
			if (!pkt_dev->entry)
				printk(KERN_ERR "pktgen: can't move proc "
				       " entry for '%s'\n", dev->name);
			break;
		}
	}
}

static int pktgen_device_event(struct notifier_block *unused,
			       unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct pktgen_net *pn = net_generic(dev_net(dev), pg_net_id);

	if (pn->pktgen_exiting)
		return NOTIFY_DONE;

	/* It is OK that we do not hold the group lock right now,
	 * as we run under the RTNL lock.
	 */

	switch (event) {
	case NETDEV_CHANGENAME:
		pktgen_change_name(pn, dev);
		break;

	case NETDEV_UNREGISTER:
		pktgen_mark_device(pn, dev->name);
		break;
	}

	return NOTIFY_DONE;
}


static struct net_device *pktgen_dev_get_by_name(const struct pktgen_net *pn,
						 struct pktgen_dev *pkt_dev,
						 const char *ifname)
{
	char b[IFNAMSIZ+5];
	int i;

	for(i=0; ifname[i] != '@'; i++) {
		if(i == IFNAMSIZ)
			break;

		b[i] = ifname[i];
	}
	b[i] = 0;

	return dev_get_by_name(pn->net, b);
}

/* Associate pktgen_dev with a device. */

static int pktgen_setup_dev(const struct pktgen_net *pn,
			    struct pktgen_dev *pkt_dev, struct pktgen_thread* t)
{
	struct net_device *odev;
	int err;

	/* Clean old setups */
	if (pkt_dev->odev) {
#ifdef USE_NQW_CALLBACK
		/* Set the nqw callback hooks */
		rtnl_lock();
		clear_nqw_hook(t, pkt_dev->odev);
		rtnl_unlock();
#endif
		pkt_dev->odev->pkt_dev = NULL;
		dev_put(pkt_dev->odev);
		pkt_dev->odev = NULL;
	}

	odev = pktgen_dev_get_by_name(pn, pkt_dev, pkt_dev->ifname);
	if (!odev) {
		printk(KERN_ERR "pktgen: no such netdevice: \"%s\"\n", pkt_dev->ifname);
		return -ENODEV;
	}

	if (odev->type != ARPHRD_ETHER && odev->type != ARPHRD_LOOPBACK) {
		printk(KERN_ERR "pktgen: not an ethernet or loopback device: \"%s\"\n", pkt_dev->ifname);
		err = -EINVAL;
	} else if (!netif_running(odev)) {
		printk(KERN_ERR "pktgen: device is down: \"%s\"\n", pkt_dev->ifname);
		err = -ENETDOWN;
	} else {
		pkt_dev->odev = odev;
#ifdef USE_NQW_CALLBACK
		/* Set the nqw callback hooks */
		rtnl_lock();
		set_nqw_hook(t, pkt_dev->odev, GFP_ATOMIC);
		rtnl_unlock();
#endif
		pkt_dev->odev->pkt_dev = pkt_dev;
		return 0;
	}

	dev_put(odev);
	return err;
}

/* Read pkt_dev from the interface and set up internal pktgen_dev
 * structure to have the right information to create/send packets
 */
static void pktgen_setup_inject(struct pktgen_net *pn, struct pktgen_dev *pkt_dev)
{
	int ntxq;

	/* Try once more, just in case it works now. */
	if (!pkt_dev->odev)
		pktgen_setup_dev(pn, pkt_dev, pkt_dev->pg_thread);

	if (!pkt_dev->odev) {
		printk(KERN_ERR "pktgen: ERROR: pkt_dev->odev == NULL in "
		       "setup_inject.\n");
		sprintf(pkt_dev->result,
			"ERROR: pkt_dev->odev == NULL in setup_inject.\n");
		return;
	}

	/* make sure that we don't pick a non-existing transmit queue */
	ntxq = pkt_dev->odev->real_num_tx_queues;
	if (ntxq <= pkt_dev->queue_map_min) {
		printk(KERN_WARNING "pktgen: WARNING: Requested "
		       "queue_map_min (zero-based) (%d) exceeds valid range "
		       "[0 - %d] for (%d) queues on %s, resetting\n",
		       pkt_dev->queue_map_min, (ntxq ?: 1)- 1, ntxq,
		       pkt_dev->odevname);
		pkt_dev->queue_map_min = (ntxq ?: 1) - 1;
	}
	if (pkt_dev->queue_map_max >= ntxq) {
		printk(KERN_WARNING "pktgen: WARNING: Requested "
		       "queue_map_max (zero-based) (%d) exceeds valid range "
		       "[0 - %d] for (%d) queues on %s, resetting\n",
		       pkt_dev->queue_map_max, (ntxq ?: 1)- 1, ntxq,
		       pkt_dev->odevname);
		pkt_dev->queue_map_max = (ntxq ?: 1) - 1;
	}

	/* Default to the interface's mac if not explicitly set. */

	if (is_zero_ether_addr(pkt_dev->src_mac))
		ether_addr_copy(&(pkt_dev->hh[6]), pkt_dev->odev->dev_addr);
	else
		memcpy(&(pkt_dev->hh[6]), pkt_dev->src_mac, ETH_ALEN);


	/* Set up Dest MAC */
	ether_addr_copy(&pkt_dev->hh[0], pkt_dev->dst_mac);

	if (pkt_dev->flags & F_IPV6) {
		int i, set = 0, err = 1;
		struct inet6_dev *idev;

		if (pkt_dev->min_pkt_size == 0) {
			pkt_dev->min_pkt_size = 14 + sizeof(struct ipv6hdr)
						+ sizeof(struct udphdr)
						+ sizeof(struct pktgen_hdr)
						+ pkt_dev->pkt_overhead;
		}

		for (i = 0; i < sizeof(struct in6_addr); i++)
			if (pkt_dev->cur_in6_saddr.s6_addr[i]) {
				set = 1;
				break;
			}

		if (!set) {

			/*
			 * Use linklevel address if unconfigured.
			 *
			 * use ipv6_get_lladdr if/when it's get exported
			 */

			rcu_read_lock();
			if ((idev = __in6_dev_get(pkt_dev->odev)) != NULL) {
				struct inet6_ifaddr *ifp;

				read_lock_bh(&idev->lock);
				list_for_each_entry(ifp, &idev->addr_list, if_list) {
					if ((ifp->scope & IFA_LINK) &&
					    !(ifp->flags & IFA_F_TENTATIVE)) {
						pkt_dev->cur_in6_saddr = ifp->addr;
						err = 0;
						break;
					}
				}
				read_unlock_bh(&idev->lock);
			}
			rcu_read_unlock();
			if (err)
				printk(KERN_ERR "pktgen: ERROR: IPv6 link address not availble.\n");
		}
	} else {
		if (pkt_dev->min_pkt_size == 0) {
			pkt_dev->min_pkt_size = 14 + sizeof(struct iphdr)
						+ sizeof(struct udphdr)
						+ sizeof(struct pktgen_hdr)
						+ pkt_dev->pkt_overhead;
		}

		pkt_dev->saddr_min = 0;
		pkt_dev->saddr_max = 0;
		if (strlen(pkt_dev->src_min) == 0) {

			struct in_device *in_dev;

			rcu_read_lock();
			in_dev = __in_dev_get_rcu(pkt_dev->odev);
			if (in_dev) {
				const struct in_ifaddr *ifa;

				ifa = rcu_dereference(in_dev->ifa_list);
				if (ifa) {
					pkt_dev->saddr_min = ifa->ifa_address;
					pkt_dev->saddr_max = pkt_dev->saddr_min;
				}
			}
			rcu_read_unlock();
		} else {
			pkt_dev->saddr_min = in_aton(pkt_dev->src_min);
			pkt_dev->saddr_max = in_aton(pkt_dev->src_max);
		}

		pkt_dev->daddr_min = in_aton(pkt_dev->dst_min);
		pkt_dev->daddr_max = in_aton(pkt_dev->dst_max);
	}
	/* Initialize current values. */
	pkt_dev->cur_pkt_size = pkt_dev->min_pkt_size;
	if (pkt_dev->min_pkt_size > pkt_dev->max_pkt_size)
		pkt_dev->max_pkt_size = pkt_dev->min_pkt_size;

	pkt_dev->cur_dst_mac_offset = 0;
	pkt_dev->cur_src_mac_offset = 0;
	pkt_dev->cur_saddr = pkt_dev->saddr_min;
	pkt_dev->cur_daddr = pkt_dev->daddr_min;
	pkt_dev->cur_udp_dst = pkt_dev->udp_dst_min;
	pkt_dev->cur_udp_src = pkt_dev->udp_src_min;
	pkt_dev->nflows = 0;
}


#ifdef USE_NQW_CALLBACK
/* Runs from interrupt */
int pg_notify_queue_woken(struct net_device* dev) {
	/* Find the thread that needs waking. */
	struct pg_nqw_data* nqwd = ((struct pg_nqw_data*)(dev->nqw_data));
	while (nqwd) {
		struct pktgen_thread* t = nqwd->pg_thread;
		t->control |= T_WAKE_BLOCKED;
		/* It's not the end of the world if this races and we mis a wake...it will
		   always wake up within one tick anyway.
		*/
		t->nqw_callbacks++;
		if (t->sleeping) {
			t->nqw_wakeups++;
			wake_up_interruptible(&(t->queue));
			t->sleeping = 0;
		}
		nqwd = nqwd->next;
	}
	return 0;
}

/* Must hold RTNL lock while calling this. */
static int set_nqw_hook(struct pktgen_thread* t, struct net_device* dev, int gfp) {
	/* The notify-queue-woken magic only works for physical
	 * devices at this time.  So, apply hook to underlying
	 * device.
	 */
	struct pg_nqw_data* nqwd;
	ASSERT_RTNL();
	BUG_ON(!t);

	if (!dev) {
		WARN_ON(!dev);
		return -ENODEV;
	}

	if (dev->rtnl_link_ops && (strcmp(dev->rtnl_link_ops->kind, "macvlan") == 0)) {
		struct macvlan_dev *vlan = netdev_priv(dev);
		if (debug)
			printk("pktgen: setting nqw_hook on lower mac-vlan dev: %p\n", vlan->lowerdev);
		return set_nqw_hook(t, vlan->lowerdev, gfp);
	}

	if (dev->priv_flags & IFF_802_1Q_VLAN) {
		if (debug)
			printk("pktgen: setting nqw_hook on real-dev of .1q vlan: %s\n", dev->name);
		return set_nqw_hook(t, vlan_dev_real_dev(dev), gfp);
	}

	nqwd = (struct pg_nqw_data*)(dev->nqw_data);

	if (nqwd) {
		if (nqwd->magic == PG_NQW_MAGIC) {
			while (nqwd) {
				if (nqwd->pg_thread == t) {
					atomic_inc(&(nqwd->nqw_ref_count));
					if (debug)
						printk("pktgen: Incremented nqw_ref_count: %d"
						       "  device: %s  thread: %p\n",
						       (int)(atomic_read(&(nqwd->nqw_ref_count))),
						       dev->name, t);
					return 0;
				}
				nqwd = nqwd->next;
			}
			goto new_nqwd;
		}
		else {
			printk("pktgen:  WARNING:  set_nqw_hook: nqwd magic is NOT pktgen, dev: %s  magic: 0x%x\n",
			       dev->name, nqwd->magic);
			return 0;
		}
	}
	else {
	new_nqwd:
		nqwd = kmalloc(sizeof(*nqwd), gfp);
		if (nqwd) {
			memset(nqwd, 0, sizeof(*nqwd));
			nqwd->magic = PG_NQW_MAGIC;
			atomic_inc(&(nqwd->nqw_ref_count));
			nqwd->pg_thread = t;
			nqwd->next = dev->nqw_data;
			dev->nqw_data = nqwd;
			dev->notify_queue_woken = pg_notify_queue_woken;
			if (debug)
				printk("pktgen: Added nqw callback to device: %s  thread: %p\n",
				       dev->name, t);
			return 0;
		}
		else {
			printk("pktgen: ERROR:  could not allocate nqwd for dev: %s\n", dev->name);
			return -ENOBUFS;
		}
	}
}


/* Must hold RTNL lock while calling this. */
static void clear_nqw_hook(struct pktgen_thread* t, struct net_device* dev) {
	/* The notify-queue-woken magic only works for physical
	 * devices at this time.  So, apply hook to underlying
	 * device.
	 */
	ASSERT_RTNL();
	BUG_ON(!t);

	if (dev->rtnl_link_ops && (strcmp(dev->rtnl_link_ops->kind, "macvlan") == 0)) {
		struct macvlan_dev *vlan = netdev_priv(dev);
		clear_nqw_hook(t, vlan->lowerdev);
		return;
	}

	if (dev->priv_flags & IFF_802_1Q_VLAN) {
		clear_nqw_hook(t, vlan_dev_real_dev(dev));
		return;
	}

	if (dev->nqw_data) {
		struct pg_nqw_data* nqwd = (struct pg_nqw_data*)(dev->nqw_data);
		struct pg_nqw_data* prev = nqwd;
		if (nqwd->magic == PG_NQW_MAGIC) {
			while (nqwd) {
				if (t != nqwd->pg_thread) {
					prev = nqwd;
					nqwd = nqwd->next;
				}
				else {
					break;
				}
			}
			if (!nqwd) {
				printk("pktgen ERROR: Counld not find nqwd for thread: %p  device: %s\n",
				       t, dev->name);
				return;
			}

			atomic_dec(&(nqwd->nqw_ref_count));

			if (debug)
				printk("pktgen: Decremented nqw_ref_count: %d  device: %s  thread: %p\n",
				       (int)(atomic_read(&(nqwd->nqw_ref_count))),
				       dev->name, t);

			BUG_ON(atomic_read(&(nqwd->nqw_ref_count)) < 0);

			if (atomic_read(&(nqwd->nqw_ref_count)) == 0) {
				if (debug)
					printk("pktgen: Removing nqw reference from device: %s  thread: %p\n",
					       dev->name, t);
				if (nqwd == dev->nqw_data) {
					if (!nqwd->next) {
						dev->notify_queue_woken = NULL;
					}
					dev->nqw_data = nqwd->next;
				}
				else {
					prev->next = nqwd->next;
				}
				nqwd->next = NULL;
				kfree(nqwd);
			}
		}
		else {
			printk("pktgen:  WARNING:  clear_nqw_hook: nqwd magic is NOT PKT-GEN, dev: %s  magic: 0x%x",
			       dev->name, nqwd->magic);
		}
	}
	else {
		printk("pktgen:  Warning: nqw_data is null in clear_nqw_hook, dev: %s\n",
		       dev->name);
	}
}

#endif


/* delay_ns is in nano-seconds */
static void pg_nanodelay(u64 delay_ns, struct pktgen_dev* info) {
	u64 idle_start = getRelativeCurNs();
	u64 last_time;
	u64 _diff;
	u64 itmp = idle_start;
	struct pktgen_dev *p = NULL;
	struct pktgen_thread* t = info->pg_thread;

	info->nanodelays++;
	info->accum_delay_ns += delay_ns;
	while (info->accum_delay_ns > PG_MAX_ACCUM_DELAY_NS) {
		int delay_max_us;
		int delay_min_us = info->accum_delay_ns >> 10;
		if (delay_min_us < 50)
			delay_min_us = 50;
		delay_max_us = delay_min_us + 50;
		info->sleeps++;
		info->pg_thread->sleeping = 1;
		if (delay_min_us < 1000 * (1000 / HZ)) {
			usleep_range(delay_min_us, delay_max_us);
		}
		else {
			wait_event_interruptible_timeout(t->queue, false, 1);
		}
		info->pg_thread->sleeping = 0;
		/* will wake after one tick */
		last_time = itmp;

		/* Subtract delay from all interfaces for this thread, since all are blocked when
		 * any are blocked.
		 */
		itmp = getRelativeCurNs();
		_diff = (itmp - last_time);
		list_for_each_entry(p, &t->if_list, list) {
			p->accum_delay_ns -= _diff;
			/* Limit saving up too much time... */
			if (p->accum_delay_ns < -10000000) {
				p->accum_delay_ns = -10000000;
			}
		}

		/* For accounting, only charge this guy for the idle though...*/
		info->idle_acc_ns += _diff;

		/* break out if we are stopped or if we should transmit (maybe our ipg changed?) */
		if (info->removal_mark || (itmp >= info->next_tx_ns) ||
		    (t->control && T_WAKE_BLOCKED) ||
		    (t->control && T_STOP)) {
			break;
		}
	}/* while */
}


static inline void set_pkt_overhead(struct pktgen_dev *pkt_dev)
{
	pkt_dev->pkt_overhead = 0;
	pkt_dev->pkt_overhead += pkt_dev->nr_labels*sizeof(u32);
	pkt_dev->pkt_overhead += VLAN_TAG_SIZE(pkt_dev);
	pkt_dev->pkt_overhead += SVLAN_TAG_SIZE(pkt_dev);
}

static inline int f_seen(const struct pktgen_dev *pkt_dev, int flow)
{
	return !!(pkt_dev->flows[flow].flags & F_INIT);
}

static inline int f_pick(struct pktgen_dev *pkt_dev)
{
	int flow = pkt_dev->curfl;

	if (pkt_dev->flags & F_FLOW_SEQ) {
		if (pkt_dev->flows[flow].count >= pkt_dev->lflow) {
			/* reset time */
			pkt_dev->flows[flow].count = 0;
			pkt_dev->flows[flow].flags = 0;
			pkt_dev->curfl += 1;
			if (pkt_dev->curfl >= pkt_dev->cflows)
				pkt_dev->curfl = 0; /*reset */
		}
	} else {
		flow = prandom_u32() % pkt_dev->cflows;
		pkt_dev->curfl = flow;

		if (pkt_dev->flows[flow].count > pkt_dev->lflow) {
			pkt_dev->flows[flow].count = 0;
			pkt_dev->flows[flow].flags = 0;
		}
	}

	return pkt_dev->curfl;
}


#ifdef CONFIG_XFRM
/* If there was already an IPSEC SA, we keep it as is, else
 * we go look for it ...
*/
#define DUMMY_MARK 0
static void get_ipsec_sa(struct pktgen_dev *pkt_dev, int flow)
{
	struct xfrm_state *x = pkt_dev->flows[flow].x;
	struct pktgen_net *pn = net_generic(dev_net(pkt_dev->odev), pg_net_id);

	if (!x) {

		if (pkt_dev->spi) {
			/* We need as quick as possible to find the right SA
			 * Searching with minimum criteria to archieve this.
			 */
			x = xfrm_state_lookup_byspi(pn->net, htonl(pkt_dev->spi), AF_INET);
		} else {
			/* slow path: we dont already have xfrm_state */
			x = xfrm_stateonly_find(pn->net, DUMMY_MARK, 0,
						(xfrm_address_t *)&pkt_dev->cur_daddr,
						(xfrm_address_t *)&pkt_dev->cur_saddr,
						AF_INET,
						pkt_dev->ipsmode,
						pkt_dev->ipsproto, 0);
		}
		if (x) {
			pkt_dev->flows[flow].x = x;
			set_pkt_overhead(pkt_dev);
			pkt_dev->pkt_overhead+=x->props.header_len;
		}

	}
}
#endif

static void set_cur_queue_map(struct pktgen_dev *pkt_dev)
{
	if (pkt_dev->flags & F_QUEUE_MAP_CPU)
		pkt_dev->cur_queue_map = smp_processor_id();

	else if (pkt_dev->queue_map_min <= pkt_dev->queue_map_max) {
		__u16 t;
		if (pkt_dev->flags & F_QUEUE_MAP_RND) {
			t = prandom_u32() %
				(pkt_dev->queue_map_max -
				 pkt_dev->queue_map_min + 1)
				+ pkt_dev->queue_map_min;
		} else {
			t = pkt_dev->cur_queue_map + 1;
			if (t > pkt_dev->queue_map_max)
				t = pkt_dev->queue_map_min;
		}
		pkt_dev->cur_queue_map = t;
	}
	if (pkt_dev->odev->real_num_tx_queues)
		pkt_dev->cur_queue_map  = pkt_dev->cur_queue_map % pkt_dev->odev->real_num_tx_queues;
	else
		pkt_dev->cur_queue_map = 0;
}

/* Increment/randomize headers according to flags and current values
 * for IP src/dest, UDP src/dst port, MAC-Addr src/dst
 */
static void mod_cur_headers(struct pktgen_dev *pkt_dev)
{
	__u32 imn;
	__u32 imx;
	int flow = 0;

	if (pkt_dev->cflows)
		flow = f_pick(pkt_dev);

	/*  Deal with source MAC */
	if (pkt_dev->src_mac_count > 1) {
		__u32 mc;
		__u32 tmp;

		if (pkt_dev->flags & F_MACSRC_RND)
			mc = prandom_u32() % pkt_dev->src_mac_count;
		else {
			mc = pkt_dev->cur_src_mac_offset++;
			if (pkt_dev->cur_src_mac_offset >=
			    pkt_dev->src_mac_count)
				pkt_dev->cur_src_mac_offset = 0;
		}

		tmp = pkt_dev->src_mac[5] + (mc & 0xFF);
		pkt_dev->hh[11] = tmp;
		tmp = (pkt_dev->src_mac[4] + ((mc >> 8) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[10] = tmp;
		tmp = (pkt_dev->src_mac[3] + ((mc >> 16) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[9] = tmp;
		tmp = (pkt_dev->src_mac[2] + ((mc >> 24) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[8] = tmp;
		tmp = (pkt_dev->src_mac[1] + (tmp >> 8));
		pkt_dev->hh[7] = tmp;
	}

	/*  Deal with Destination MAC */
	if (pkt_dev->dst_mac_count > 1) {
		__u32 mc;
		__u32 tmp;

		if (pkt_dev->flags & F_MACDST_RND)
			mc = prandom_u32() % pkt_dev->dst_mac_count;

		else {
			mc = pkt_dev->cur_dst_mac_offset++;
			if (pkt_dev->cur_dst_mac_offset >=
			    pkt_dev->dst_mac_count) {
				pkt_dev->cur_dst_mac_offset = 0;
			}
		}

		tmp = pkt_dev->dst_mac[5] + (mc & 0xFF);
		pkt_dev->hh[5] = tmp;
		tmp = (pkt_dev->dst_mac[4] + ((mc >> 8) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[4] = tmp;
		tmp = (pkt_dev->dst_mac[3] + ((mc >> 16) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[3] = tmp;
		tmp = (pkt_dev->dst_mac[2] + ((mc >> 24) & 0xFF) + (tmp >> 8));
		pkt_dev->hh[2] = tmp;
		tmp = (pkt_dev->dst_mac[1] + (tmp >> 8));
		pkt_dev->hh[1] = tmp;
	}

	if (pkt_dev->flags & F_MPLS_RND) {
		unsigned int i;
		for (i = 0; i < pkt_dev->nr_labels; i++)
			if (pkt_dev->labels[i] & MPLS_STACK_BOTTOM)
				pkt_dev->labels[i] = MPLS_STACK_BOTTOM |
					     ((__force __be32)prandom_u32() &
						      htonl(0x000fffff));
	}

	if ((pkt_dev->flags & F_VID_RND) && (pkt_dev->vlan_id != 0xffff)) {
		pkt_dev->vlan_id = prandom_u32() & (4096-1);
	}

	if ((pkt_dev->flags & F_SVID_RND) && (pkt_dev->svlan_id != 0xffff)) {
		pkt_dev->svlan_id = prandom_u32() & (4096 - 1);
	}

	if (pkt_dev->udp_src_min < pkt_dev->udp_src_max) {
		if (pkt_dev->flags & F_UDPSRC_RND)
			pkt_dev->cur_udp_src = prandom_u32() %
				(pkt_dev->udp_src_max - pkt_dev->udp_src_min)
				+ pkt_dev->udp_src_min;

		else {
			pkt_dev->cur_udp_src++;
			if (pkt_dev->cur_udp_src >= pkt_dev->udp_src_max)
				pkt_dev->cur_udp_src = pkt_dev->udp_src_min;
		}
	}

	if (pkt_dev->udp_dst_min < pkt_dev->udp_dst_max) {
		if (pkt_dev->flags & F_UDPDST_RND) {
			pkt_dev->cur_udp_dst = prandom_u32() %
				(pkt_dev->udp_dst_max - pkt_dev->udp_dst_min)
				+ pkt_dev->udp_dst_min;
		} else {
			pkt_dev->cur_udp_dst++;
			if (pkt_dev->cur_udp_dst >= pkt_dev->udp_dst_max)
				pkt_dev->cur_udp_dst = pkt_dev->udp_dst_min;
		}
	}

	if (!(pkt_dev->flags & F_IPV6)) {

		if ((imn = ntohl(pkt_dev->saddr_min)) < (imx =
							 ntohl(pkt_dev->
							       saddr_max))) {
			__u32 t;
			if (pkt_dev->flags & F_IPSRC_RND) {
				if (imx - imn) {
					t = (prandom_u32() % (imx - imn)) + imn;
				}
				else {
					t = imn;
				}
			}
			else {
				t = ntohl(pkt_dev->cur_saddr);
				t++;
				if (t > imx) {
					t = imn;
				}
			}
			pkt_dev->cur_saddr = htonl(t);
		}

		if (pkt_dev->cflows && f_seen(pkt_dev, flow)) {
			pkt_dev->cur_daddr = pkt_dev->flows[flow].cur_daddr;
		} else {
			imn = ntohl(pkt_dev->daddr_min);
			imx = ntohl(pkt_dev->daddr_max);
			if (imn < imx) {
				__u32 t;
				__be32 s;
				if (pkt_dev->flags & F_IPDST_RND) {
					if (imx - imn) {
						t = (prandom_u32() % (imx - imn)) + imn;
					}
					else {
						t = imn;
					}
					s = htonl(t);

					while (ipv4_is_loopback(s) || ipv4_is_multicast(s)
					       || ipv4_is_lbcast(s) || ipv4_is_zeronet(s)
					       || ipv4_is_local_multicast(s)) {
						if (imx - imn) {
							t = (prandom_u32() % (imx - imn)) + imn;
						}
						else {
							t = imn;
						}
						s = htonl(t);
					}
					pkt_dev->cur_daddr = s;
				} else {
					t = ntohl(pkt_dev->cur_daddr);
					t++;
					if (t > imx) {
						t = imn;
					}
					pkt_dev->cur_daddr = htonl(t);
				}
			}
			if (pkt_dev->cflows) {
				pkt_dev->flows[flow].flags |= F_INIT;
				pkt_dev->flows[flow].cur_daddr =
				    pkt_dev->cur_daddr;
#ifdef CONFIG_XFRM
				if (pkt_dev->flags & F_IPSEC_ON)
					get_ipsec_sa(pkt_dev, flow);
#endif
				pkt_dev->nflows++;
			}
		}
	} else {		/* IPV6 * */

		if (!ipv6_addr_any(&pkt_dev->min_in6_daddr)) {
			int i;

			/* Only random destinations yet */

			for (i = 0; i < 4; i++) {
				pkt_dev->cur_in6_daddr.s6_addr32[i] =
				    (((__force __be32)prandom_u32() |
				      pkt_dev->min_in6_daddr.s6_addr32[i]) &
				     pkt_dev->max_in6_daddr.s6_addr32[i]);
			}
		}
	}

	if (pkt_dev->min_pkt_size < pkt_dev->max_pkt_size) {
		__u32 t;
		if (pkt_dev->flags & F_TXSIZE_RND) {
			t = prandom_u32() %
				(pkt_dev->max_pkt_size - pkt_dev->min_pkt_size)
				+ pkt_dev->min_pkt_size;
		} else {
			t = pkt_dev->cur_pkt_size + 1;
			if (t > pkt_dev->max_pkt_size)
				t = pkt_dev->min_pkt_size;
		}
		pkt_dev->cur_pkt_size = t;
	}

	set_cur_queue_map(pkt_dev);

	pkt_dev->flows[flow].count++;
}

static u32 pktgen_dst_metrics[RTAX_MAX + 1] = {

	[RTAX_HOPLIMIT] = 0x5, /* Set a static hoplimit */
};

static int pktgen_output_ipsec(struct sk_buff *skb, struct pktgen_dev *pkt_dev)
{
	struct xfrm_state *x = pkt_dev->flows[pkt_dev->curfl].x;
	int err = 0;
	struct net *net = dev_net(pkt_dev->odev);

	if (!x)
		return 0;
	/* XXX: we dont support tunnel mode for now until
	 * we resolve the dst issue */
	if ((x->props.mode != XFRM_MODE_TRANSPORT) && (pkt_dev->spi == 0))
		return 0;

	/* But when user specify an valid SPI, transformation
	 * supports both transport/tunnel mode + ESP/AH type.
	 */
	if ((x->props.mode == XFRM_MODE_TUNNEL) && (pkt_dev->spi != 0))
		skb->_skb_refdst = (unsigned long)&pkt_dev->xdst.u.dst | SKB_DST_NOREF;

	rcu_read_lock_bh();
	err = pktgen_xfrm_outer_mode_output(x, skb);
	rcu_read_unlock_bh();
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
		goto error;
	}
	err = x->type->output(x, skb);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
		goto error;
	}

	spin_lock(&x->lock);
	x->curlft.bytes +=skb->len;
	x->curlft.packets++;
	spin_unlock(&x->lock);

error:
	return err;
}

static void free_SAs(struct pktgen_dev *pkt_dev)
{
	if (pkt_dev->cflows) {
		/* let go of the SAs if we have them */
		int i;
		for (i = 0; i < pkt_dev->cflows; i++) {
			struct xfrm_state *x = pkt_dev->flows[i].x;
			if (x) {
				xfrm_state_put(x);
				pkt_dev->flows[i].x = NULL;
			}
		}
	}
}

static int process_ipsec(struct pktgen_dev *pkt_dev,
			      struct sk_buff *skb, __be16 protocol)
{
	if (pkt_dev->flags & F_IPSEC_ON) {
		struct xfrm_state *x = pkt_dev->flows[pkt_dev->curfl].x;
		int nhead = 0;
		if (x) {
			int ret;
			__u8 *eth;
			struct iphdr *iph;

			nhead = x->props.header_len - skb_headroom(skb);
			if (nhead >0) {
				ret = pskb_expand_head(skb, nhead, 0, GFP_ATOMIC);
				if (ret < 0) {
					printk(KERN_ERR "Error expanding "
					       "ipsec packet %d\n",ret);
					goto err;
				}
			}

			/* ipsec is not expecting ll header */
			skb_pull(skb, ETH_HLEN);
			ret = pktgen_output_ipsec(skb, pkt_dev);
			if (ret) {
				printk(KERN_ERR "Error creating ipsec "
				       "packet %d\n",ret);
				goto err;
			}
			/* restore ll */
			eth = (__u8 *) skb_push(skb, ETH_HLEN);
			memcpy(eth, pkt_dev->hh, 12);
			*(u16 *) & eth[12] = protocol;

			/* Update IPv4 header len as well as checksum value */
			iph = ip_hdr(skb);
			iph->tot_len = htons(skb->len - ETH_HLEN);
			ip_send_check(iph);
		}
	}
	return 1;
err:
	kfree_skb(skb);
	return 0;
}

static void mpls_push(__be32 *mpls, struct pktgen_dev *pkt_dev)
{
	unsigned int i;
	for (i = 0; i < pkt_dev->nr_labels; i++) {
		*mpls++ = pkt_dev->labels[i] & ~MPLS_STACK_BOTTOM;
	}
	mpls--;
	*mpls |= MPLS_STACK_BOTTOM;
}

static inline __be16 build_tci(unsigned int id, unsigned int cfi,
			       unsigned int prio)
{
	return htons(id | (cfi << 12) | (prio << 13));
}

static void pktgen_finalize_skb(struct pktgen_dev *pkt_dev, struct sk_buff *skb,
				int datalen)
{
	struct pktgen_hdr *pgh;

	pkt_dev->pgh = (struct pktgen_hdr *)skb_put(skb, sizeof(*pgh));
	pgh = pkt_dev->pgh;
	datalen -= sizeof(*pgh);

	if (pkt_dev->nfrags <= 0) {
		skb_put(skb, datalen);
		/* memset(skb_put(skb, datalen), 0, datalen); BEN */
	} else {
		int frags = pkt_dev->nfrags;
		int i, len;
		int frag_len;

		if (frags > MAX_SKB_FRAGS)
			frags = MAX_SKB_FRAGS;
		len = datalen - frags * PAGE_SIZE;
		if (len > 0) {
			/* memset(skb_put(skb, len), 0, len); BEN */
			datalen = frags * PAGE_SIZE;
		}

		i = 0;
		frag_len = (datalen/frags) < PAGE_SIZE ?
			   (datalen/frags) : PAGE_SIZE;
		while (datalen > 0) {
			if (unlikely(!pkt_dev->page)) {
				int node = numa_node_id();

				if (pkt_dev->node >= 0 && (pkt_dev->flags & F_NODE))
					node = pkt_dev->node;
				pkt_dev->page = alloc_pages_node(node, GFP_KERNEL/* | __GFP_ZERO BEN */, 0);
				if (!pkt_dev->page)
					break;
			}
			get_page(pkt_dev->page);
			skb_frag_set_page(skb, i, pkt_dev->page);
			skb_frag_off_set(&skb_shinfo(skb)->frags[i], 0);
			/*last fragment, fill rest of data*/
			if (i == (frags - 1))
				skb_frag_size_set(&skb_shinfo(skb)->frags[i],
				    (datalen < PAGE_SIZE ? datalen : PAGE_SIZE));

			else
				skb_frag_size_set(&skb_shinfo(skb)->frags[i], frag_len);
			datalen -= skb_frag_size(&skb_shinfo(skb)->frags[i]);
			skb->len += skb_frag_size(&skb_shinfo(skb)->frags[i]);
			skb->data_len += skb_frag_size(&skb_shinfo(skb)->frags[i]);
			i++;
			skb_shinfo(skb)->nr_frags = i;
		}
	}

	/* Stamp the time, and sequence number,
	 * convert them to network byte order
	 */
	pgh->pgh_magic = htonl(PKTGEN_MAGIC);
	pgh->seq_num = htonl(pkt_dev->seq_num);
	pgh->conn_id = htons((unsigned short)(pkt_dev->conn_id));

	timestamp_skb(pkt_dev, pgh);
}

static struct sk_buff *pktgen_alloc_skb(struct net_device *dev,
					struct pktgen_dev *pkt_dev,
					unsigned int extralen)
{
	struct sk_buff *skb = NULL;
	unsigned int size = pkt_dev->cur_pkt_size + 64 + extralen +
			    pkt_dev->pkt_overhead + LL_RESERVED_SPACE(pkt_dev->odev);

	if (pkt_dev->flags & F_NODE) {
		int node = pkt_dev->node >= 0 ? pkt_dev->node : numa_node_id();

		skb = __alloc_skb(NET_SKB_PAD + size, GFP_NOWAIT, 0, node);
		if (likely(skb)) {
			skb_reserve(skb, NET_SKB_PAD);
			skb->dev = dev;
		}
	} else {
		 skb = __netdev_alloc_skb(dev, size, GFP_NOWAIT);
	}

	if (likely(skb))
		skb_reserve(skb, LL_RESERVED_SPACE(dev));

	return skb;
}

static void pg_do_csum(struct pktgen_dev *pkt_dev, struct sk_buff *skb) {
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *uh;
	struct net_device *odev = pkt_dev->odev;

	if (pkt_dev->flags & F_TCP) {
		struct tcphdr *th = tcp_hdr(skb);
		unsigned int prefix_len = (unsigned int)((unsigned char*)th - skb->data);

		if (odev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)) {
			skb->ip_summed = CHECKSUM_PARTIAL;
			/* Subtract out IP hdr and before */
			th->check = ~tcp_v4_check(skb->len - prefix_len, iph->saddr, iph->daddr, 0);
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
		} else {
			skb->ip_summed = CHECKSUM_NONE;
			th->check = 0;
			skb->csum = 0;
			th->check = tcp_v4_check(skb->len - prefix_len, iph->saddr, iph->daddr,
						 csum_partial(th, th->doff << 2, skb->csum));
		}
		//pr_err("check: 0x%x  csum-start: %d  offset: %d summed: 0x%x  saddr: 0x%x  daddr: 0x%x len: %d headroom: %d tcphdr-offset: %d prefix-len: %d\n",
		//       th->check, skb->csum_start, skb->csum_offset, skb->ip_summed, iph->saddr, iph->daddr,
		//       skb->len, skb_headroom(skb), (unsigned int)((unsigned char*)th - skb->data), prefix_len);
	} else {
		if (odev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)) {
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum = 0;
			udp4_hwcsum(skb, iph->saddr, iph->daddr);
		} else {
			unsigned int offset = skb_transport_offset(skb);
			__wsum csum = skb_checksum(skb, offset, skb->len - offset, 0);
			uh = udp_hdr(skb);

			/* add protocol-dependent pseudo-header */
			uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						      skb->len - offset, IPPROTO_UDP, csum);

			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		}
	}
}

static struct sk_buff *fill_packet_ipv4(struct net_device *odev,
					struct pktgen_dev *pkt_dev)
{
	struct sk_buff *skb = NULL;
	__u8 *eth;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph;
	int datalen, iplen;
	struct iphdr *iph;
	__be16 protocol = htons(ETH_P_IP);
	__be32 *mpls;
	__be16 *vlan_tci = NULL;                 /* Encapsulates priority and VLAN ID */
	__be16 *vlan_encapsulated_proto = NULL;  /* packet type ID field (or len) for VLAN tag */
	__be16 *svlan_tci = NULL;                /* Encapsulates priority and SVLAN ID */
	__be16 *svlan_encapsulated_proto = NULL; /* packet type ID field (or len) for SVLAN tag */
	int cur_pkt_size;

	if (pkt_dev->nr_labels)
		protocol = htons(ETH_P_MPLS_UC);

	if (pkt_dev->vlan_id != 0xffff)
		protocol = htons(ETH_P_8021Q);

	/* Update any of the values, used when we're incrementing various
	 * fields.
	 */
	mod_cur_headers(pkt_dev);

	datalen = (odev->hard_header_len + 16) & ~0xf;
	cur_pkt_size = pkt_dev->cur_pkt_size; /* protect against race */
	skb = pktgen_alloc_skb(odev, pkt_dev, datalen);
	if (!skb) {
		sprintf(pkt_dev->result, "No memory");
		return NULL;
	}
	pkt_dev->seq_num++; /* Increase the pktgen sequence number for the next packet. */

	prefetchw(skb->data);
	skb_reserve(skb, datalen);

	/*  Reserve for ethernet and IP header  */
	eth = (__u8 *) skb_push(skb, 14);
	mpls = (__be32 *)skb_put(skb, pkt_dev->nr_labels*sizeof(__u32));
	if (pkt_dev->nr_labels)
		mpls_push(mpls, pkt_dev);

	if (pkt_dev->vlan_id != 0xffff) {
		if (pkt_dev->svlan_id != 0xffff) {
			svlan_tci = (__be16 *)skb_put(skb, sizeof(__be16));
			*svlan_tci = build_tci(pkt_dev->svlan_id,
					       pkt_dev->svlan_cfi,
					       pkt_dev->svlan_p);
			svlan_encapsulated_proto = (__be16 *)skb_put(skb, sizeof(__be16));
			*svlan_encapsulated_proto = htons(ETH_P_8021Q);
		}
		vlan_tci = (__be16 *)skb_put(skb, sizeof(__be16));
		*vlan_tci = build_tci(pkt_dev->vlan_id,
				      pkt_dev->vlan_cfi,
				      pkt_dev->vlan_p);
		vlan_encapsulated_proto = (__be16 *)skb_put(skb, sizeof(__be16));
		*vlan_encapsulated_proto = htons(ETH_P_IP);
	}

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb->len);
	iph = (struct iphdr *) skb_put(skb, sizeof(struct iphdr));

	skb_set_transport_header(skb, skb->len);

	if (pkt_dev->flags & F_TCP) {
		datalen = pkt_dev->cur_pkt_size - ETH_HLEN - 20 -
			  sizeof(struct tcphdr) - pkt_dev->pkt_overhead;
		if (datalen < sizeof(struct pktgen_hdr))
			datalen = sizeof(struct pktgen_hdr);
		tcph = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));
		memset(tcph, 0, sizeof(*tcph));
		tcph->source = htons(pkt_dev->cur_udp_src);
		tcph->dest = htons(pkt_dev->cur_udp_dst);
		tcph->doff = sizeof(struct tcphdr) >> 2;
		tcph->seq = htonl(pkt_dev->tcp_seqno);
		pkt_dev->tcp_seqno += datalen;
		tcph->window = htons(0x7FFF);
		iplen = 20 + sizeof(struct tcphdr) + datalen;
	} else {
		/* Eth + IPh + UDPh + mpls */
		datalen = cur_pkt_size - 14 - 20 - 8 -
			pkt_dev->pkt_overhead;
		if (datalen < sizeof(struct pktgen_hdr))
			datalen = sizeof(struct pktgen_hdr);
		udph = (struct udphdr *)skb_put(skb, sizeof(struct udphdr));

		udph->source = htons(pkt_dev->cur_udp_src);
		udph->dest = htons(pkt_dev->cur_udp_dst);
		udph->len = htons(datalen + 8);	/* DATA + udphdr */
		udph->check = 0;
		iplen = 20 + 8 + datalen;
	}

	skb->priority = pkt_dev->skb_priority;

	memcpy(eth, pkt_dev->hh, 12);
	*(__be16 *) & eth[12] = protocol;

	iph->ihl = 5;
	iph->version = 4;
	iph->ttl = 32;
	iph->tos = pkt_dev->tos;
	iph->protocol = pkt_dev->flags & F_TCP ? IPPROTO_TCP : IPPROTO_UDP;
	iph->saddr = pkt_dev->cur_saddr;
	iph->daddr = pkt_dev->cur_daddr;
	iph->id = htons(pkt_dev->ip_id++);
	iph->frag_off = 0;
	iph->tot_len = htons(iplen);
	ip_send_check(iph);
	skb->protocol = protocol;
	skb->dev = odev;
	skb->pkt_type = PACKET_HOST;

	pktgen_finalize_skb(pkt_dev, skb, datalen);

	if ((odev->mtu + ETH_HLEN) < skb->len) {
		int hdrlen = skb_transport_header(skb) - skb_mac_header(skb);

		if (pkt_dev->flags & F_TCP) {
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			hdrlen += tcp_hdrlen(skb);
		} else {
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
			hdrlen += sizeof(struct udphdr);
		}
		skb_shinfo(skb)->gso_size = odev->mtu - hdrlen;
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len - hdrlen, skb_shinfo(skb)->gso_size);
	} else {
		skb_shinfo(skb)->gso_type = 0;
	}

#ifdef CONFIG_XFRM
	if (!process_ipsec(pkt_dev, skb, protocol))
		return NULL;
#endif

	if (pkt_dev->flags & F_UDPCSUM)
		pg_do_csum(pkt_dev, skb);
	else
		skb->ip_summed = CHECKSUM_NONE;

	return skb;
}

static struct sk_buff *fill_packet_ipv6(struct net_device *odev,
					struct pktgen_dev *pkt_dev)
{
	struct sk_buff *skb = NULL;
	__u8 *eth;
	struct udphdr *udph;
	int datalen, udplen;
	struct ipv6hdr *iph;
	__be16 protocol = htons(ETH_P_IPV6);
	__be32 *mpls;
	__be16 *vlan_tci = NULL;                 /* Encapsulates priority and VLAN ID */
	__be16 *vlan_encapsulated_proto = NULL;  /* packet type ID field (or len) for VLAN tag */
	__be16 *svlan_tci = NULL;                /* Encapsulates priority and SVLAN ID */
	__be16 *svlan_encapsulated_proto = NULL; /* packet type ID field (or len) for SVLAN tag */
	int cur_pkt_size;

	if (pkt_dev->nr_labels)
		protocol = htons(ETH_P_MPLS_UC);

	if (pkt_dev->vlan_id != 0xffff)
		protocol = htons(ETH_P_8021Q);

	/* Update any of the values, used when we're incrementing various
	 * fields.
	 */
	mod_cur_headers(pkt_dev);

	cur_pkt_size = pkt_dev->cur_pkt_size;
	skb = pktgen_alloc_skb(odev, pkt_dev, 16);
	if (!skb) {
		sprintf(pkt_dev->result, "No memory");
		return NULL;
	}

	prefetchw(skb->data);
	skb_reserve(skb, 16);

	/*  Reserve for ethernet and IP header  */
	eth = (__u8 *) skb_push(skb, 14);
	mpls = (__be32 *)skb_put(skb, pkt_dev->nr_labels*sizeof(__u32));
	if (pkt_dev->nr_labels)
		mpls_push(mpls, pkt_dev);

	if (pkt_dev->vlan_id != 0xffff) {
		if (pkt_dev->svlan_id != 0xffff) {
			svlan_tci = (__be16 *)skb_put(skb, sizeof(__be16));
			*svlan_tci = build_tci(pkt_dev->svlan_id,
					       pkt_dev->svlan_cfi,
					       pkt_dev->svlan_p);
			svlan_encapsulated_proto = (__be16 *)skb_put(skb, sizeof(__be16));
			*svlan_encapsulated_proto = htons(ETH_P_8021Q);
		}
		vlan_tci = (__be16 *)skb_put(skb, sizeof(__be16));
		*vlan_tci = build_tci(pkt_dev->vlan_id,
				      pkt_dev->vlan_cfi,
				      pkt_dev->vlan_p);
		vlan_encapsulated_proto = (__be16 *)skb_put(skb, sizeof(__be16));
		*vlan_encapsulated_proto = htons(ETH_P_IPV6);
	}

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb->len);
	iph = (struct ipv6hdr *) skb_put(skb, sizeof(struct ipv6hdr));

	skb_set_transport_header(skb, skb->len);
	udph = (struct udphdr *) skb_put(skb, sizeof(struct udphdr));
	skb->priority = pkt_dev->skb_priority;

	memcpy(eth, pkt_dev->hh, 12);
	*(__be16 *) & eth[12] = protocol;

	/* Eth + IPh + UDPh + mpls */
	datalen = cur_pkt_size - 14 -
		  sizeof(struct ipv6hdr) - sizeof(struct udphdr) -
		  pkt_dev->pkt_overhead;

	if (datalen < 0 || datalen < sizeof(struct pktgen_hdr)) {
		datalen = sizeof(struct pktgen_hdr);
		net_info_ratelimited("increased datalen to %d\n", datalen);
	}

	udplen = datalen + sizeof(struct udphdr);
	udph->source = htons(pkt_dev->cur_udp_src);
	udph->dest = htons(pkt_dev->cur_udp_dst);
	udph->len = htons(udplen);
	udph->check = 0;

	*(__be32 *) iph = htonl(0x60000000);	/* Version + flow */

	if (pkt_dev->traffic_class) {
		/* Version + traffic class + flow (0) */
		*(__be32 *)iph |= htonl(0x60000000 | (pkt_dev->traffic_class << 20));
	}

	iph->hop_limit = 32;

	iph->payload_len = htons(udplen);
	iph->nexthdr = IPPROTO_UDP;

	iph->daddr = pkt_dev->cur_in6_daddr;
	iph->saddr =pkt_dev->cur_in6_saddr;

	skb->protocol = protocol;
	skb->dev = odev;
	skb->pkt_type = PACKET_HOST;

	pktgen_finalize_skb(pkt_dev, skb, datalen);

	if (!(pkt_dev->flags & F_UDPCSUM)) {
		skb->ip_summed = CHECKSUM_NONE;
	} else if (odev->features & (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM)) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		udph->check = ~csum_ipv6_magic(&iph->saddr, &iph->daddr, udplen, IPPROTO_UDP, 0);
	} else {
		__wsum csum = skb_checksum(skb, skb_transport_offset(skb), udplen, 0);

		/* add protocol-dependent pseudo-header */
		udph->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, udplen, IPPROTO_UDP, csum);

		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;
	}

	return skb;
}

static struct sk_buff *fill_packet(struct net_device *odev,
				   struct pktgen_dev *pkt_dev)
{
	if (pkt_dev->flags & F_IPV6)
		return fill_packet_ipv6(odev, pkt_dev);
	else
		return fill_packet_ipv4(odev, pkt_dev);
}


static void record_latency(struct pktgen_dev* pkt_dev, int latency) {
        /* NOTE:  Latency can be negative */
        int div = 100;
        int i;
	int jit;

	/* If peer is local, then we can never actually have negative times.  Probable
	 * cause is ntp or similar changing the clock while pkt is in flight.  Count this
	 * event for debugging purposes, and set latency to zero.
	 */
	if (pkt_dev->flags & F_PEER_LOCAL) {
		if (latency < 0) {
			pkt_dev->neg_latency++;
			latency = 0;
		}
	}

        pkt_dev->pkts_rcvd_since_clear_lat++;
	pkt_dev->total_lat += latency;

        if (pkt_dev->pkts_rcvd_since_clear_lat < 100) {
                div = pkt_dev->pkts_rcvd_since_clear_lat;
                if (pkt_dev->pkts_rcvd_since_clear_lat == 1) {
                        pkt_dev->avg_latency = latency;
                }
        }

        if ((div + 1) == 0) {
                pkt_dev->avg_latency = 0;
        }
        else {
                pkt_dev->avg_latency = ((pkt_dev->avg_latency * div + latency) / (div + 1));
        }

        if (latency < pkt_dev->min_latency) {
                pkt_dev->min_latency = latency;
        }
        if (latency > pkt_dev->max_latency) {
                pkt_dev->max_latency = latency;
        }

        /* Place the latency in the right 'bucket' */
        for (i = 0; i<LAT_BUCKETS_MAX; i++) {
                if (latency < (1<<(i+1))) {
                        pkt_dev->latency_bkts[i]++;
                        break;
                }
        }

	/* Calculate jitter */
	if (latency > pkt_dev->last_rx_lat)
		jit = latency - pkt_dev->last_rx_lat;
	else
		jit = pkt_dev->last_rx_lat - latency;
	/* pkt_dev->running_jitter = pkt_dev->running_jitter * 15/16 + jit * 1/16; */
	/* Multiply by 1024 to decrease fixed-point rounding errors */
	pkt_dev->running_jitter = ((pkt_dev->running_jitter * 15) >> 4) + ((jit * 1024) >> 4);

	pkt_dev->last_rx_lat = latency;
}/* record latency */


/* Returns < 0 if the skb is not a pktgen buffer. */
int pktgen_receive(struct sk_buff* skb) {
	bool is_tcp;

        /* See if we have a pktgen packet */
	/* TODO:  Add support for detecting IPv6, TCP packets too.  This will only
	 * catch UDP at the moment. --Ben
	 */
	/* printk("pktgen-rcv, skb->len: %d\n", skb->len); */

	/* If this is a paged skb, make sure we pull up
	 * whatever data we need to look at. */
	if (!pskb_may_pull(skb, 20 + 8 + sizeof(struct pktgen_hdr))) {
		return -1;
	}

        if ((skb->len >= (20 + 8 + sizeof(struct pktgen_hdr))) &&
            (skb->protocol == __constant_htons(ETH_P_IP))) {
		struct pktgen_hdr* pgh;

                /* It's IP, and long enough, lets check the magic number.
                 * TODO:  This is a hack not always guaranteed to catch the right
                 * packets.
                 */

		/* printk("Length & protocol passed, skb->data: %p, raw: %p\n",
		   skb->data, skb->h.raw); */

                pgh = (struct pktgen_hdr*)(skb->data + 20 + 8);

		if (pgh->pgh_magic != __constant_ntohl(PKTGEN_MAGIC)) {
			/* Maybe TCP packet? */
			if (!pskb_may_pull(skb, 20 + sizeof(struct tcphdr) + sizeof(struct pktgen_hdr))) {
				return -1;
			}

			pgh = (struct pktgen_hdr*)(skb->data + 20 + sizeof(struct tcphdr));
			is_tcp = true;
		}
		else {
			is_tcp = false;
		}

                /*
                tmp = (char*)(skb->data);
                for (i = 0; i<90; i++) {
                        printk("%02hx ", tmp[i]);
                        if (((i + 1) % 15) == 0) {
                                printk("\n");
                        }
                }
                printk("\n");
                */

                if (pgh->pgh_magic == __constant_ntohl(PKTGEN_MAGIC)) {
                        struct net_device* dev = skb->dev;
                        struct pktgen_dev* pkt_dev;
                        __u32 seq = ntohl(pgh->seq_num);
			int hdr_len = 0;
			bool skip_seq_update = false;

			/* TODO:  Need lock..maybe */
			pkt_dev = dev->pkt_dev;

                        if (!pkt_dev) {
				return -1;
                        }

			if (likely(skb_mac_header(skb) < skb->data)) {
				hdr_len = skb->data - skb_mac_header(skb);
			}

                        pkt_dev->pkts_rcvd++;
			/*printk("%s:  rcvd pkt, last_seq_rcvd: %i  seq: %i  pkts_rcvd: %llu\n",
			       pkt_dev->ifname, pkt_dev->last_seq_rcvd, seq, pkt_dev->pkts_rcvd);
			*/
                        pkt_dev->bytes_rcvd += (skb->len + hdr_len);
			/* account for pre-amble and inter-frame gap, crc */
                        pkt_dev->bytes_rcvd_ll += (skb->len + hdr_len + 24);

			/* Check for bad checksums. */
			if (pkt_dev->flags & F_UDPCSUM) {
				if (is_tcp) {
					if (tcp_checksum_complete(skb)) {
						pkt_dev->rx_crc_failed++;
						goto out_free_skb;
					}
				} else {
					if (udp_lib_checksum_complete(skb)) {
						pkt_dev->rx_crc_failed++;
						goto out_free_skb;
					}
				}
			}

			if (ntohs(pgh->conn_id) != (pkt_dev->peer_conn_id & 0xFFFF)) {
				pkt_dev->pkts_rcvd_wrong_conn++;
				net_info_ratelimited("%s rx-wrong-dev  skb->dev: %s  pgh->seq: %u"
						     " pgh->conn_id: 0x%hx (%u)  peer_conn_id: %u\n",
						     pkt_dev->ifname, skb->dev->name, seq, pgh->conn_id,
						     ntohs(pgh->conn_id), pkt_dev->peer_conn_id);
				goto out_free_skb;
			}

                        /* Check for out-of-sequence packets */
                        if (pkt_dev->last_seq_rcvd == seq) {
				/*printk("%s:  got dup, last_seq_rcvd: %i  seq: %i  pkts_rcvd: %llu\n",
				       pkt_dev->ifname, pkt_dev->last_seq_rcvd, seq, pkt_dev->pkts_rcvd);
				*/
                                pkt_dev->dup_rcvd++;
                                pkt_dev->dup_since_incr++;
				skip_seq_update = true;
                        }
                        else {
				if (!(pkt_dev->flags & F_NO_TIMESTAMP)) {
					if (pkt_dev->flags & F_USE_REL_TS) {
						__u64 now = getRelativeCurNs();
						__u64 txat = ntohl(pgh->tv_hi);
						__u64 d;
						txat = txat << 32;
						txat |= ntohl(pgh->tv_lo);
						d = pg_div(now - txat, 1000);
						record_latency(pkt_dev, d);
					}
					else {
						s64 tx;
						s64 rx;
						struct __kernel_old_timespec rxts;
						s64 d;
						if (! skb->tstamp)
							__net_timestamp(skb);
						skb_get_timestampns(skb, &rxts);
						rx = rxts.tv_sec;
						rx *= 1000000000; /* convert sec to ns */
						rx += rxts.tv_nsec;

						tx = ntohl(pgh->tv_hi);
						tx = tx << 32;
						tx |= ntohl(pgh->tv_lo);
						d = pg_div(rx - tx, 1000);
						record_latency(pkt_dev, d);
					}
				}

                                if ((pkt_dev->last_seq_rcvd + 1) == seq) {
                                        if ((pkt_dev->peer_clone_skb > 1) &&
                                            (pkt_dev->peer_clone_skb > (pkt_dev->dup_since_incr + 1))) {

                                                pkt_dev->seq_gap_rcvd += (pkt_dev->peer_clone_skb -
                                                                       pkt_dev->dup_since_incr - 1);
                                        }
                                        /* Great, in order...all is well */
                                }
                                else if (pkt_dev->last_seq_rcvd < seq) {
                                        /* sequence gap, means we dropped a pkt most likely */
                                        if (pkt_dev->peer_clone_skb > 1) {
                                                /* We dropped more than one sequence number's worth,
                                                 * and if we're using clone_skb, then this is quite
                                                 * a few.  This number still will not be exact, but
                                                 * it will be closer.
                                                 */
                                                pkt_dev->seq_gap_rcvd += (((seq - pkt_dev->last_seq_rcvd) *
                                                                        pkt_dev->peer_clone_skb) -
                                                                       pkt_dev->dup_since_incr);
                                        }
                                        else {
                                                pkt_dev->seq_gap_rcvd += (seq - pkt_dev->last_seq_rcvd - 1);
                                        }
                                }
                                else {
                                        pkt_dev->ooo_rcvd++; /* out-of-order */
					skip_seq_update = true;
                                }

                                pkt_dev->dup_since_incr = 0;
                        }
			if (!skip_seq_update) {
				pkt_dev->last_seq_rcvd = seq;
			}
		out_free_skb:
                        kfree_skb(skb);
                        if (debug > 1) {
                                printk("done with pktgen_receive, free'd pkt\n");
                        }
                        return 0;
                }
        }
        return -1; /* Let another protocol handle it, it's not for us! */
}/* pktgen_receive */

static void pg_reset_latency_counters(struct pktgen_dev* pkt_dev) {
        int i;
	pkt_dev->last_rx_lat = 0;
	pkt_dev->running_jitter = 0;
        pkt_dev->avg_latency = 0;
        pkt_dev->min_latency = 0x7fffffff; /* largest integer */
        pkt_dev->max_latency = 0x80000000; /* smallest integer */
        pkt_dev->pkts_rcvd_since_clear_lat = 0;
	pkt_dev->total_lat = 0;
        for (i = 0; i<LAT_BUCKETS_MAX; i++) {
                pkt_dev->latency_bkts[i] = 0;
        }
}


static void pktgen_clear_counters(struct pktgen_dev *pkt_dev, int seq_too,
				  const char* reason) {
	/*printk("%s clear_counters, seq_too: %i reason: %s  sofar: %llu  count: %llu\n",
	 *       pkt_dev->ifname, seq_too, reason, pkt_dev->sofar, pkt_dev->count);
	 */
	pkt_dev->idle_acc_ns = 0;
	pkt_dev->sofar = 0;
	pkt_dev->tx_bytes = 0;
	pkt_dev->tx_bytes_ll = 0;
	pkt_dev->errors = 0;
	pkt_dev->xmit_dropped = 0;
	pkt_dev->xmit_cn = 0;

        pkt_dev->ooo_rcvd = 0;
        pkt_dev->dup_rcvd = 0;
        pkt_dev->pkts_rcvd = 0;
	pkt_dev->rx_crc_failed = 0;
        pkt_dev->bytes_rcvd = 0;
        pkt_dev->bytes_rcvd_ll = 0;
	pkt_dev->pkts_rcvd_wrong_conn = 0;
        pkt_dev->non_pg_pkts_rcvd = 0;
        pkt_dev->seq_gap_rcvd = 0; /* dropped */

	/* Clear some transient state */
	pkt_dev->accum_delay_ns = 0;
	pkt_dev->sleeps = 0;
	pkt_dev->nanodelays = 0;

        /* This is a bit of a hack, but it gets the dup counters
         * in line so we don't have false alarms on dropped pkts.
         */
        if (seq_too) {
		pkt_dev->dup_since_incr = pkt_dev->peer_clone_skb - 1;
		pkt_dev->seq_num = 0;
		pkt_dev->last_seq_rcvd = 0;
        }

        pg_reset_latency_counters(pkt_dev);
}

/* Set up structure for sending pkts, clear counters */

static void pktgen_run(struct pktgen_thread *t)
{
	struct pktgen_dev *pkt_dev;
	int started = 0;

	pr_debug("pktgen: entering pktgen_run. %p\n", t);

	list_for_each_entry(pkt_dev, &t->if_list, list) {
		/* If already running (or has completed it's allotment), then ignore. */
		if ((! pkt_dev->running) &&
		    ((pkt_dev->count == 0) || (pkt_dev->sofar < pkt_dev->count))) {

			/** Clear counters before we setup the first inject.
			 * We may have already received pkts, so don't want to clear here
			 * after all. --Ben
			 */
			/* pktgen_clear_counters(pkt_dev, 1, "pktgen_run"); */

			/*
			 * setup odev and create initial packet.
			 */
			pktgen_setup_inject(t->net, pkt_dev);

			if (pkt_dev->odev) {
				pkt_dev->running = 1;	/* Cranke yeself! */
				if (pkt_dev->flags & F_USE_REL_TS)
					use_rel_ts++;

				pkt_dev->skb = NULL;
				pkt_dev->started_at = getCurUs();
				/* Transmit first pkt after 20ms to let listener get started. */
				pkt_dev->next_tx_ns = getRelativeCurNs() + 20 * 1000000;

				set_pkt_overhead(pkt_dev);

				strcpy(pkt_dev->result, "Starting");
				started++;
			} else
				strcpy(pkt_dev->result, "Error starting");
		}
	}
}

static void pktgen_stop_all_threads_ifs(struct pktgen_net *pn)
{
	struct pktgen_thread *t;

	pr_debug("pktgen: entering pktgen_stop_all_threads_ifs.\n");

	mutex_lock(&pktgen_thread_lock);

	list_for_each_entry(t, &pn->pktgen_threads, th_list)
		t->control |= T_STOP;

	mutex_unlock(&pktgen_thread_lock);
}
static void pktgen_run_all_threads(struct pktgen_net *pn, int background) {
	struct pktgen_thread *t;

	pr_debug("pktgen: entering pktgen_run_all_threads, background: %d\n",
		 background);

	mutex_lock(&pktgen_thread_lock);

	list_for_each_entry(t, &pn->pktgen_threads, th_list)
		t->control |= (T_RUN);

	mutex_unlock(&pktgen_thread_lock);

	/* Much harder to get rid of the if_lock if we allow this to block... */
	if (!background) {
		printk("ERROR:  non-background mode no longer supported.\n");
	}
}


static void pktgen_reset_all_threads(struct pktgen_net *pn)
{
	struct pktgen_thread *t;

	pr_debug("pktgen: entering pktgen_reset_all_threads.\n");

	mutex_lock(&pktgen_thread_lock);

	list_for_each_entry(t, &pn->pktgen_threads, th_list)
		t->control |= (T_REMDEVALL);

	mutex_unlock(&pktgen_thread_lock);

}


static void show_results(struct pktgen_dev *pkt_dev, int nr_frags)
{
	__u64 total_us, bps, mbps, pps, idle;
	char *p = pkt_dev->result;

	total_us = pkt_dev->stopped_at - pkt_dev->started_at;

	idle = pkt_dev->idle_acc_ns;
	do_div(idle, 1000);

	p += sprintf(p, "OK: %llu(c%llu+d%llu) usec, %llu (%dbyte,%dfrags)\n",
		     (unsigned long long)total_us,
		     (unsigned long long)(total_us - idle),
		     (unsigned long long)idle,
		     (unsigned long long)pkt_dev->sofar,
		     pkt_dev->cur_pkt_size, nr_frags);

	pps = pkt_dev->sofar * USEC_PER_SEC;

	while ((total_us >> 32) != 0) {
		pps >>= 1;
		total_us >>= 1;
	}

	/* Fixup total_us in case it was zero..don't want div-by-zero. */
	if (total_us == 0)
		total_us = 1;

	do_div(pps, total_us);

	bps = pps * 8 * pkt_dev->cur_pkt_size;

	mbps = bps;
	do_div(mbps, 1000000);
	p += sprintf(p, "  %llupps %lluMb/sec (%llubps) errors: %llu",
		     (unsigned long long)pps,
		     (unsigned long long)mbps,
		     (unsigned long long)bps,
		     (unsigned long long)pkt_dev->errors);
}

/* Set stopped-at timer, remove from running list, do counters & statistics */
static int pktgen_stop_device(struct pktgen_dev *pkt_dev)
{
	int nr_frags = pkt_dev->skb ? skb_shinfo(pkt_dev->skb)->nr_frags : -1;

	if (!pkt_dev->running)
		return -EINVAL;

	kfree_skb(pkt_dev->skb);
	pkt_dev->skb = NULL;
	pkt_dev->stopped_at = getCurUs();
	pkt_dev->running = 0;
	if (pkt_dev->flags & F_USE_REL_TS)
		use_rel_ts--;

	show_results(pkt_dev, nr_frags);

	return 0;
}

/**  Find the adapter that needs to tx next.
 *  We need to take the blocked adapters into account, but can't ignore
 * them forever just in case we missed the tx-queue-wake event for some
 * reason.
 */
static struct pktgen_dev *next_to_run(struct pktgen_thread *t, u64 now, u64* next_running_delay) {
	struct pktgen_dev *pkt_dev = NULL;
	struct pktgen_dev *best = NULL;
	struct pktgen_dev *best_blocked = NULL;
	struct pktgen_dev *rv = NULL;

	list_for_each_entry(pkt_dev, &t->if_list, list) {
		if (!pkt_dev->running)
			continue;
		if (pkt_dev->tx_blocked) {
			if (best_blocked == NULL)
				best_blocked = pkt_dev;
			else {
				if (pkt_dev->next_tx_ns < best_blocked->next_tx_ns) {
					best_blocked = pkt_dev;
				}
			}
		}
		else {
			if (best == NULL)
				best = pkt_dev;
			else {
				if (pkt_dev->next_tx_ns < best->next_tx_ns) {
					best = pkt_dev;
				}
			}
		}
	}

	/** If we have both blocked and non-blocked, and non-blocked wants to transmit now, then
	 * choose it.  Otherwise, just choose whoever wants to run next.
	 */
	if (best_blocked && best) {
		if (((best_blocked->next_tx_ns + PG_TRY_TX_ANYWAY_NS) < now) &&
		    (best_blocked->next_tx_ns < best->next_tx_ns)) {
			rv = best_blocked;
		}
		else if (best->next_tx_ns <= now) {
			rv = best;
		}
		else if (best->next_tx_ns < best_blocked->next_tx_ns) {
			rv = best;
		}
		else {
			rv = best_blocked;
		}
	}

	if (!rv) {
		if (best_blocked && (best_blocked->next_tx_ns < (now - PG_TRY_TX_ANYWAY_NS))) {
			rv = best_blocked;
		}
	}
	if (!rv) {
		rv = best;
	}
	if (!rv) {
		rv = best_blocked;
	}

	if (rv) {
		/* If best is blocked, we should delay a bit */
		if (rv->tx_blocked) {
			*next_running_delay = PG_TRY_TX_ANYWAY_NS;
		}
		else {
			if (rv->next_tx_ns <= now) {
				*next_running_delay = 0;
			}
			else {
				*next_running_delay = rv->next_tx_ns - now;
			}
		}
	}
	else {
		*next_running_delay = 10000000; /* 10ms */
	}
	return rv;
}

static void pktgen_stop(struct pktgen_thread *t)
{
	struct pktgen_dev *pkt_dev;

	pr_debug("pktgen: entering pktgen_stop\n");

	list_for_each_entry(pkt_dev, &t->if_list, list) {
		pktgen_stop_device(pkt_dev);
	}
}

/*
 * one of our devices needs to be removed - find it
 * and remove it
 */
static void pktgen_rem_one_if(struct pktgen_thread *t)
{
	struct list_head *q, *n;
	struct pktgen_dev *cur;

	pr_debug("pktgen: entering pktgen_rem_one_if\n");

	list_for_each_safe(q, n, &t->if_list) {
		cur = list_entry(q, struct pktgen_dev, list);

		if (!cur->removal_mark)
			continue;

		kfree_skb(cur->skb);
		cur->skb = NULL;

		pktgen_remove_device(t, cur);

		break;
	}
}

static void pktgen_unblock_all_ifs(struct pktgen_thread *t) {
	struct pktgen_dev *p = NULL;;
	list_for_each_entry(p, &t->if_list, list)
		p->tx_blocked = 0;
}/* wake all writers */


static void pktgen_rem_all_ifs(struct pktgen_thread *t)
{
	struct list_head *q, *n;
	struct pktgen_dev *cur;

	/* Remove all devices, free mem */

	pr_debug("pktgen: entering pktgen_rem_all_ifs\n");
	list_for_each_safe(q, n, &t->if_list) {
		cur = list_entry(q, struct pktgen_dev, list);

		kfree_skb(cur->skb);
		cur->skb = NULL;

		pktgen_remove_device(t, cur);
	}
}

static void pktgen_rem_thread(struct pktgen_thread *t)
{
	/* Remove from the thread list */

	remove_proc_entry(t->tsk->comm, t->net->proc_dir);
}

static void pktgen_xmit(struct pktgen_dev *pkt_dev, u64 now)
{
	static int do_once_hsx_wrn = 1;
	unsigned int burst = READ_ONCE(pkt_dev->burst);
	struct net_device *odev = pkt_dev->odev;
	struct netdev_queue *txq;
	u16 queue_map;
	int ret;
	unsigned long burst_sofar_ns = 0;

	/* printk("pktgen_xmit, pkt_dev: %s  now: %llu\n", pkt_dev->ifname, now); */

	if (pkt_dev->delay_ns || (pkt_dev->accum_delay_ns > 0)) {
		if (now < pkt_dev->next_tx_ns) {
			/* Don't tx early..*/
			pkt_dev->req_tx_early++;
			goto out;
		}

		/* This is max DELAY, this has special meaning of
		 * "never transmit"
		 */
		if (pkt_dev->delay_ns == 0x7FFFFFFF) {
			pkt_dev->next_tx_ns = getRelativeCurNs() + pkt_dev->delay_ns;
			goto out;
		}
	}

	queue_map = pkt_dev->cur_queue_map;
	BUG_ON(queue_map >= odev->num_tx_queues);
	txq = netdev_get_tx_queue(odev, queue_map);

	if (netif_xmit_frozen_or_drv_stopped(txq) ||
	    (!netif_carrier_ok(odev)) ||
	    need_resched()) {
		/*printk("pktgen: xmit_frozen_or_stopped: %i (state: 0x%lx) carrier_ok: %i"
		       "  need_resched: %i  iface: %s  queue_map: %i  num_tx_queues: %i.\n",
		       netif_xmit_frozen_or_stopped(txq), txq->state,
		       netif_carrier_ok(odev), need_resched(), pkt_dev->odevname,
		       queue_map, odev->num_tx_queues);*/

		pkt_dev->queue_stopped++;
		pkt_dev->tx_blocked = 1;
		/* change tx time to now to show work was at least attempted. */
		pkt_dev->next_tx_ns = now;
		if (!netif_running(odev)) {
			pktgen_stop_device(pkt_dev);
		}
		goto out; /* try next interface */
	}

	if (pkt_dev->last_ok || !pkt_dev->skb || pkt_dev->force_new_skb) {
		if ((++pkt_dev->clone_count >= pkt_dev->clone_skb)
		    || pkt_dev->force_new_skb
		    || (!pkt_dev->skb)) {
			short forced = 0;
			if (unlikely(pkt_dev->force_new_skb && pkt_dev->skb
				     && pkt_dev->clone_count < pkt_dev->clone_skb)) {
				/* want to keep same seq num, so decrement it before fill-pkt */
				/* printk("%s:  force-new-skb was true, seq: %i\n",
				       pkt_dev->ifname, pkt_dev->seq_num);
				*/
				forced = 1;
				pkt_dev->seq_num--;
			}
			/* build a new pkt */
			kfree_skb(pkt_dev->skb);

			pkt_dev->skb = fill_packet(odev, pkt_dev);
			if (pkt_dev->skb == NULL) {
				/* printk(KERN_ERR "pktgen: ERROR: couldn't "
				 *       "allocate skb in fill_packet.\n");
				 */
				schedule();
				if (unlikely(forced))
					pkt_dev->seq_num++; /* back this out */

				pkt_dev->clone_count--;	/* back out increment, OOM */
				pkt_dev->oom_on_alloc_skb++;
				goto out;
			}
			pkt_dev->last_pkt_size = pkt_dev->skb->len;
			pkt_dev->allocated_skbs++;
			if (likely(!forced)) {
				pkt_dev->clone_count = 0;	/* reset counter */

				if (netif_needs_gso(pkt_dev->skb, netif_skb_features(pkt_dev->skb))) {
					pr_err("Device doesn't have necessary GSO features! netif_skb_features: %llX summed %u skb-gso: %d gso-ok: %d\n",
					       netif_skb_features(pkt_dev->skb),
					       pkt_dev->skb->ip_summed, skb_is_gso(pkt_dev->skb),
					       skb_gso_ok(pkt_dev->skb, netif_skb_features(pkt_dev->skb)));
					pktgen_stop_device(pkt_dev);
					goto out;
				}
			}
			pkt_dev->force_new_skb = 0;
			queue_map = pkt_dev->cur_queue_map;
		}
	}

	/*
	 * tells skb_tx_hash() to use this tx queue.
	 * We should reset skb->mapping before each xmit() because
	 * xmit() might change it.
	 */
	skb_set_queue_mapping(pkt_dev->skb, queue_map);

	BUG_ON(queue_map >= odev->num_tx_queues);
	txq = netdev_get_tx_queue(odev, queue_map);

	local_bh_disable();

	HARD_TX_LOCK(odev, txq, smp_processor_id());

	if (!(netif_xmit_frozen_or_stopped(txq))) {

		refcount_add(burst, &pkt_dev->skb->users);
		/* If we were blocked or had errors last time, then our skb most likely needs
		   a timer update. */
		if (pkt_dev->pgh && (pkt_dev->tx_blocked || !pkt_dev->last_ok)) {
			timestamp_skb(pkt_dev, pkt_dev->pgh);

			if (pkt_dev->flags & F_UDPCSUM)
				pg_do_csum(pkt_dev, pkt_dev->skb);
		}
	retry_now:
		ret = netdev_start_xmit(pkt_dev->skb, odev, txq, --burst > 0);
		burst_sofar_ns += pkt_dev->delay_ns;
		/* printk("%s tx skb, rv: %i  s: %llu  c: %llu\n",
		 *      pkt_dev->ifname, ret, pkt_dev->sofar, pkt_dev->count);
		 */
		switch (ret) {
		case NETDEV_TX_OK:
			pkt_dev->last_ok = 1;
			pkt_dev->sofar++;
			pkt_dev->tx_bytes += pkt_dev->last_pkt_size;
			pkt_dev->tx_bytes_ll += pkt_dev->last_pkt_size + 24; /* pre-amble, frame gap, crc */
			pkt_dev->tx_blocked = 0;
			if (burst > 0 && !netif_xmit_frozen_or_drv_stopped(txq)) {
				if (burst_sofar_ns < PG_MAX_ACCUM_DELAY_NS)
					goto retry_now;
			}
			pkt_dev->next_tx_ns = getRelativeCurNs() + burst_sofar_ns;
			break;
		case NET_XMIT_DROP: /* skb has been consumed if we get these next 3 */
			pkt_dev->xmit_dropped++;
			goto retry_next_time;
		case NET_XMIT_CN:
			pkt_dev->xmit_cn++;
			goto retry_next_time;
		default: /* Drivers are not supposed to return other values! */
			net_info_ratelimited("%s xmit error: %d\n",
					pkt_dev->odevname, ret);
			/* fallthru */
		case NETDEV_TX_BUSY:
			/* Retry it next time */
			if (do_once_hsx_wrn) {
				printk(KERN_INFO "pktgen: Hard xmit error: 0x%x, driver for %s doesn't do queue-stopped quite right.\n",
				       ret, pkt_dev->odevname);
				printk(KERN_INFO "pktgen:  Transmit request will be retried, and this error msg will not be printed again..\n");
				do_once_hsx_wrn = 0;
			}

			if (ret == NETDEV_TX_BUSY)
				refcount_dec(&(pkt_dev->skb->users));

			pkt_dev->queue_stopped++;

		retry_next_time:
			pkt_dev->errors++;
			pkt_dev->last_ok = 0;

			/* Try a little later..flag us as wanting to tx, but unable.  Will try again shortly.
			 */
			pkt_dev->tx_blocked = 1;
			/* change tx time to now to show work was at least attempted. */
			pkt_dev->next_tx_ns = now;
		}
		if (unlikely(burst))
			WARN_ON(refcount_sub_and_test(burst, &pkt_dev->skb->users));
	}
	else {			/* Retry it next time */
		/* printk("pktgen: xmit_frozen_or_stopped: %i iface: %s  queue_map: %i.\n",
		       netif_xmit_frozen_or_stopped(txq),
		       pkt_dev->odevname, queue_map); */
		pkt_dev->queue_stopped++;
		pkt_dev->last_ok = 0;
		/* Try a little later..flag us as wanting to tx, but unable.  Will try again shortly.
		 */
		pkt_dev->tx_blocked = 1;
		/* change tx time to now to show work was at least attempted. */
		pkt_dev->next_tx_ns = now;
	}

	HARD_TX_UNLOCK(odev, txq);

	local_bh_enable();

	/* If pkt_dev->count is zero, then run forever */
	if ((pkt_dev->count != 0) && (pkt_dev->sofar >= pkt_dev->count)) {
		if (refcount_read(&(pkt_dev->skb->users)) != 1) {
			u64 idle_start = getRelativeCurNs();
			while (refcount_read(&(pkt_dev->skb->users)) != 1) {
				if (signal_pending(current)) {
					break;
				}
				schedule();
			}
			pkt_dev->idle_acc_ns += getRelativeCurNs() - idle_start;
		}

		/* Done with requested work, quiesce.  Let user-space actually
		 * do the stopping.
		 */
		pkt_dev->delay_ns = 0x7FFFFFFF;
		/*pktgen_stop_device(pkt_dev); */
	}
out:;
}

/*
 * Main loop of the thread goes here
 */

static int pktgen_thread_worker(void *arg)
{
	DEFINE_WAIT(wait);
	struct pktgen_thread *t = arg;
	struct pktgen_dev *pkt_dev = NULL;
	int cpu = t->cpu;
	u64 now;
	u64 next_running_delay;

	WARN_ON(smp_processor_id() != cpu);

	init_waitqueue_head(&t->queue);
	complete(&t->start_done);

	pr_debug("pktgen: starting pktgen/%d:  pid=%d\n", cpu, task_pid_nr(current));

	set_freezable();

	__set_current_state(TASK_RUNNING);

	while (!kthread_should_stop()) {
		if (t->control & T_WAKE_BLOCKED) {
			pktgen_unblock_all_ifs(t);
			t->control &= ~(T_WAKE_BLOCKED);
		}

		now = getRelativeCurNs();
		pkt_dev = next_to_run(t, now, &next_running_delay);
		/* if (pkt_dev) {
		 *	printk("pkt_dev: %s is_blocked %i, now: %llu\n",
		 *	       pkt_dev->ifname, pkt_dev->tx_blocked, now);
		 *}
		 */

		if (!pkt_dev &&
		    (t->control & (T_STOP | T_RUN | T_REMDEVALL | T_REMDEV))
		    == 0) {
			if (t->net->pktgen_exiting)
				break;
			prepare_to_wait(&(t->queue), &wait,
					TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
			finish_wait(&(t->queue), &wait);
		}

		if (pkt_dev) {
			if (pkt_dev->tx_blocked) {
				/* Potentially sleep for a bit.  If the
				 * device un-blocks, then we will be woken by the wait-queue callback.
				 */
				u64 tx_anyway_ns = (now - PG_TRY_TX_ANYWAY_NS);
				if (pkt_dev->next_tx_ns > tx_anyway_ns) {
					/* printk("pkt_dev: %s blocked, now: %llu next_tx_ns: %llu  tx_anyway_ns: %llu  next_running_delay: %lluns\n",
					         pkt_dev->ifname, now, pkt_dev->next_tx_ns,
					         tx_anyway_ns, next_running_delay);
					 */
					pg_nanodelay(min(next_running_delay, (u64)(PG_TRY_TX_ANYWAY_NS)),
						     pkt_dev);
					/* Maybe things have changed since we went to sleep. */
					continue;
				}
				/* Been PG_TRY_TX_ANYWAY_NS, Fall through and attempt to transmit anyway. */
			}

			/* If the best to run should not run yet, then sleep (or accumulate sleep) */
			if (now < pkt_dev->next_tx_ns) {
				/* spin(pkt_dev, pkt_dev->next_tx_us); */
				u64 next_ipg = pkt_dev->next_tx_ns - now;

				/* These will not actually busy-spin now.  Will run as
				 * much as 1ms fast, and will sleep in 1ms units, assuming
				 * our tick is 1ms.
				 * Unless we are using high-res timers to sleep, then we get
				 * better granularity.
				 */
				pg_nanodelay(next_ipg, pkt_dev);
				now = getRelativeCurNs();
				if (pkt_dev->removal_mark ||
				    (pkt_dev->pg_thread->control && T_STOP)) {
					goto skip_tx;
				}
			}

			pktgen_xmit(pkt_dev, now);
		}
	skip_tx:

		if (t->control & T_STOP) {
			pktgen_stop(t);
			t->control &= ~(T_STOP);
		}

		if (t->control & T_RUN) {
			pktgen_run(t);
			t->control &= ~(T_RUN);
		}

		if (t->control & T_ADD_DEV) {
			pktgen_add_device(t, (char*)(t->control_arg));
			t->control &= ~(T_ADD_DEV);
		}

		if (t->control & T_REMDEVALL) {
			pktgen_rem_all_ifs(t);
			t->control &= ~(T_REMDEVALL);
		}

		if (t->control & T_REMDEV) {
			pktgen_rem_one_if(t);
			t->control &= ~(T_REMDEV);
		}

		try_to_freeze();
	}

	set_current_state(TASK_INTERRUPTIBLE);

	pr_debug("pktgen: %s stopping all device\n", t->tsk->comm);
	pktgen_stop(t);

	pr_debug("pktgen: %s removing all device\n", t->tsk->comm);
	pktgen_rem_all_ifs(t);

	pr_debug("pktgen: %s removing thread.\n", t->tsk->comm);
	pktgen_rem_thread(t);

	/* Wait for kthread_stop */
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}

static struct pktgen_dev *pktgen_find_dev(struct pktgen_thread *t,
					  const char *ifname, bool exact)
{
	struct pktgen_dev *p, *pkt_dev = NULL;
	size_t len = strlen(ifname);

	list_for_each_entry(p, &t->if_list, list)
		if (strncmp(p->odevname, ifname, len) == 0) {
			if (p->odevname[len]) {
				if (exact || p->odevname[len] != '@')
					continue;
			}
			pkt_dev = p;
			break;
		}
	return pkt_dev;
}

/*
 * Adds a dev at front of if_list.
 */

static int add_dev_to_thread(struct pktgen_thread *t,
			     struct pktgen_dev *pkt_dev)
{
	int rv = 0;

	if (pkt_dev->pg_thread) {
		printk(KERN_ERR "pktgen: ERROR: already assigned "
		       "to a thread.\n");
		rv = -EBUSY;
		goto out;
	}

	list_add(&pkt_dev->list, &t->if_list);
	pkt_dev->pg_thread = t;
	if (pkt_dev->running) {
		pkt_dev->running = 0;
		if (pkt_dev->flags & F_USE_REL_TS)
			use_rel_ts--;
	}

out:
	return rv;
}

static int pktgen_add_device(struct pktgen_thread *t, const char *ifname)
{
	struct pktgen_dev *pkt_dev;
	int err;
	int node = cpu_to_node(t->cpu);

	/* We don't allow a device to be on several threads */

	pkt_dev = __pktgen_NN_threads(t->net, ifname, FIND);
	if (pkt_dev) {
		printk(KERN_ERR "pktgen: ERROR: interface already used.\n");
		return -EBUSY;
	}
	else {
		if (debug)
			printk("pktgen:  Attempting to add device: %s\n", ifname);
	}

	pkt_dev = kzalloc_node(sizeof(struct pktgen_dev), GFP_KERNEL, node);
	if (!pkt_dev)
		return -ENOMEM;

	strcpy(pkt_dev->odevname, ifname);
	pkt_dev->flows = vzalloc_node(array_size(MAX_CFLOWS,
						 sizeof(struct flow_state)),
				      node);
	if (pkt_dev->flows == NULL) {
		kfree(pkt_dev);
		return -ENOMEM;
	}

	pktgen_clear_counters(pkt_dev, 1, "pktgen_add_device");

	pkt_dev->removal_mark = 0;
	pkt_dev->nfrags = 0;
	pkt_dev->clone_skb = pg_clone_skb_d;
	pkt_dev->delay_ns = pg_delay_d;
	pkt_dev->count = pg_count_d;
	pkt_dev->sofar = 0;
	pkt_dev->udp_src_min = 9;	/* sink port */
	pkt_dev->udp_src_max = 9;
	pkt_dev->udp_dst_min = 9;
	pkt_dev->udp_dst_max = 9;
	pkt_dev->vlan_p = 0;
	pkt_dev->vlan_cfi = 0;
	pkt_dev->vlan_id = 0xffff;
	pkt_dev->svlan_p = 0;
	pkt_dev->svlan_cfi = 0;
	pkt_dev->svlan_id = 0xffff;
	pkt_dev->burst = 1;
	pkt_dev->node = -1;
	strncpy(pkt_dev->ifname, ifname, sizeof(pkt_dev->ifname));

	err = pktgen_setup_dev(t->net, pkt_dev, t);
	if (err)
		goto out1;
	if (pkt_dev->odev->priv_flags & IFF_TX_SKB_SHARING)
		pkt_dev->clone_skb = pg_clone_skb_d;

	pkt_dev->entry = proc_create_data(ifname, 0600, t->net->proc_dir,
					  &pktgen_if_proc_ops, pkt_dev);

	if (!pkt_dev->entry) {
		printk(KERN_ERR "pktgen: cannot create %s/%s procfs entry.\n",
		       PG_PROC_DIR, ifname);
		err = -EINVAL;
		goto out2;
	}
#ifdef CONFIG_XFRM
	pkt_dev->ipsmode = XFRM_MODE_TRANSPORT;
	pkt_dev->ipsproto = IPPROTO_ESP;

	/* xfrm tunnel mode needs additional dst to extract outter
	 * ip header protocol/ttl/id field, here creat a phony one.
	 * instead of looking for a valid rt, which definitely hurting
	 * performance under such circumstance.
	 */
	pkt_dev->dstops.family = AF_INET;
	pkt_dev->xdst.u.dst.dev = pkt_dev->odev;
	dst_init_metrics(&pkt_dev->xdst.u.dst, pktgen_dst_metrics, false);
	pkt_dev->xdst.child = &pkt_dev->xdst.u.dst;
	pkt_dev->xdst.u.dst.ops = &pkt_dev->dstops;
#endif

	return add_dev_to_thread(t, pkt_dev);
out2:
	dev_put(pkt_dev->odev);
out1:
#ifdef CONFIG_XFRM
	free_SAs(pkt_dev);
#endif
	vfree(pkt_dev->flows);
	kfree(pkt_dev);
	return err;
}

static int __init pktgen_create_thread(int cpu, struct pktgen_net *pn)
{
	struct pktgen_thread *t;
	struct proc_dir_entry *pe;
	struct task_struct *p;

	t = kzalloc_node(sizeof(struct pktgen_thread), GFP_KERNEL,
			 cpu_to_node(cpu));
	if (!t) {
		printk(KERN_ERR "pktgen: ERROR: out of memory, can't "
		       "create new thread.\n");
		return -ENOMEM;
	}

	t->cpu = cpu;

	INIT_LIST_HEAD(&t->if_list);

	list_add_tail(&t->th_list, &pn->pktgen_threads);
	init_completion(&t->start_done);

	p = kthread_create_on_node(pktgen_thread_worker,
				   t,
				   cpu_to_node(cpu),
				   "kpktgend_%d", cpu);
	if (IS_ERR(p)) {
		printk(KERN_ERR "pktgen: kernel_thread() failed "
		       "for cpu %d\n", t->cpu);
		list_del(&t->th_list);
		kfree(t);
		return PTR_ERR(p);
	}
	kthread_bind(p, cpu);
	t->tsk = p;

	pe = proc_create_data(t->tsk->comm, 0600, pn->proc_dir,
			      &pktgen_thread_proc_ops, t);
	if (!pe) {
		printk(KERN_ERR "pktgen: cannot create %s/%s procfs entry.\n",
		       PG_PROC_DIR, t->tsk->comm);
		kthread_stop(p);
		list_del(&t->th_list);
		kfree(t);
		return -EINVAL;
	}

	t->net = pn;
	wake_up_process(p);
	wait_for_completion(&t->start_done);

	return 0;
}

/*
 * Removes a device from the thread if_list.
 */
static void _rem_dev_from_if_list(struct pktgen_thread *t,
				  struct pktgen_dev *pkt_dev)
{
	struct list_head *q, *n;
	struct pktgen_dev *p;

	list_for_each_safe(q, n, &t->if_list) {
		p = list_entry(q, struct pktgen_dev, list);
		if (p == pkt_dev)
			list_del(&p->list);
	}
}

static int pktgen_remove_device(struct pktgen_thread *t,
				struct pktgen_dev *pkt_dev)
{
	pr_debug("pktgen: remove_device pkt_dev=%p\n", pkt_dev);

	if (pkt_dev->running) {
		/*printk(KERN_WARNING "pktgen: WARNING: trying to remove a "
		        "running interface, stopping it now.\n");
		 */
		pktgen_stop_device(pkt_dev);
	}

	/* Dis-associate from the interface */

	if (pkt_dev->odev) {

#ifdef USE_NQW_CALLBACK
		/* Set the nqw callback hooks */
		rtnl_lock();
		clear_nqw_hook(t, pkt_dev->odev);
		rtnl_unlock();
#endif
		pkt_dev->odev->pkt_dev = NULL;
		dev_put(pkt_dev->odev);
		pkt_dev->odev = NULL;
	}

	/* And update the thread if_list */

	_rem_dev_from_if_list(t, pkt_dev);

	proc_remove(pkt_dev->entry);

#ifdef CONFIG_XFRM
	free_SAs(pkt_dev);
#endif
	vfree(pkt_dev->flows);
	if (pkt_dev->page)
		put_page(pkt_dev->page);
	kfree(pkt_dev);
	return 0;
}

static int __net_init pg_net_init(struct net *net)
{
	struct pktgen_net *pn = net_generic(net, pg_net_id);
	struct proc_dir_entry *pe;
	int cpu, ret = 0;

	pr_info("sizeof report: %d, in6_addr: %d  pktgen_hdr: %i HZ: %i  TICK_NSEC: %lu net: %p\n",
		(int)(sizeof(struct pktgen_dev_report)),
		(int)(sizeof(struct in6_addr)), (int)(sizeof(struct pktgen_hdr)),
		HZ, TICK_NSEC, net);

	pn->net = net;
	INIT_LIST_HEAD(&pn->pktgen_threads);
	pn->pktgen_exiting = false;
	pn->proc_dir = proc_mkdir(PG_PROC_DIR, pn->net->proc_net);
	if (!pn->proc_dir) {
		pr_warn("cannot create /proc/net/%s\n", PG_PROC_DIR);
		return -ENODEV;
	}

	pe = proc_create(PGCTRL, 0600, pn->proc_dir, &pktgen_proc_ops);
	if (pe == NULL) {
		pr_err("cannot create %s procfs entry.\n", PGCTRL);
		ret = -EINVAL;
		goto remove;
	}

	for_each_online_cpu(cpu) {
		int err;

		err = pktgen_create_thread(cpu, pn);
		if (err)
			pr_warn("Cannot create thread for cpu %d (%d)\n",
				cpu, err);
	}

	if (list_empty(&pn->pktgen_threads)) {
		pr_err("Initialization failed for all threads\n");
		ret = -ENODEV;
		goto remove_entry;
	}

	pr_debug("pktgen initialization complete.\n");

	return 0;

remove_entry:
	remove_proc_entry(PGCTRL, pn->proc_dir);
remove:
	remove_proc_entry(PG_PROC_DIR, pn->net->proc_net);
	return ret;
}

static void __net_exit pg_net_exit(struct net *net)
{
	struct pktgen_net *pn = net_generic(net, pg_net_id);
	struct pktgen_thread *t;
	struct list_head *q, *n;
	LIST_HEAD(list);

	/* Stop all interfaces & threads */
	pn->pktgen_exiting = true;

	mutex_lock(&pktgen_thread_lock);
	list_splice(&pn->pktgen_threads, &list);
	mutex_unlock(&pktgen_thread_lock);

	list_for_each_safe(q, n, &list) {
		t = list_entry(q, struct pktgen_thread, th_list);
		list_del(&t->th_list);
		kthread_stop(t->tsk);
		kfree(t);
	}

	remove_proc_entry(PGCTRL, pn->proc_dir);
	remove_proc_entry(PG_PROC_DIR, pn->net->proc_net);
}

static struct pernet_operations pg_net_ops = {
	.init = pg_net_init,
	.exit = pg_net_exit,
	.id   = &pg_net_id,
	.size = sizeof(struct pktgen_net),
};

static int __init pg_init(void)
{
	int ret = 0;
	pr_info("%s", version);
	ret = register_pernet_subsys(&pg_net_ops);
	if (ret)
		return ret;
	ret = register_netdevice_notifier(&pktgen_notifier_block);
	if (ret)
		unregister_pernet_subsys(&pg_net_ops);

	handle_pktgen_hook = pktgen_receive;
	return ret;
}

static void __exit pg_cleanup(void)
{
	handle_pktgen_hook = NULL;
	unregister_netdevice_notifier(&pktgen_notifier_block);
	unregister_pernet_subsys(&pg_net_ops);
}

module_init(pg_init);
module_exit(pg_cleanup);

MODULE_AUTHOR("Robert Olsson <robert.olsson@its.uu.se");
MODULE_DESCRIPTION("Packet Generator tool");
MODULE_LICENSE("GPL");
module_param(pg_count_d, int, 0);
module_param(pg_delay_d, int, 0);
module_param(pg_clone_skb_d, int, 0);
module_param(debug, int, 0);
