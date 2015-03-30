/* -*-linux-c-*-
 * $Id: candela_2.6.13.patch,v 1.3 2005/09/30 04:45:31 greear Exp $
 * pktgen.c: Packet Generator for performance evaluation.
 *
 * See pktgen.c for details of changes, etc.
*/


#ifndef PKTGEN_H_INCLUDE_KERNEL__
#define PKTGEN_H_INCLUDE_KERNEL__

#include <linux/version.h>
#include <linux/in6.h>

/* The buckets are exponential in 'width' */
#define LAT_BUCKETS_MAX 32
#define PG_MAX_ACCUM_DELAY_NS (50 * 1000) /* 50 us */
#define PG_TRY_TX_ANYWAY_NS 50000 /* try a blocked tx queue after 50 us. */

#define IP_NAME_SZ 32
#define MAX_MPLS_LABELS 16 /* This is the max label stack depth */
#define MPLS_STACK_BOTTOM __constant_htonl(0x00000100)

/* Device flag bits */
#define F_IPSRC_RND   (1<<0)	/* IP-Src Random  */
#define F_IPDST_RND   (1<<1)	/* IP-Dst Random  */
#define F_UDPSRC_RND  (1<<2)	/* UDP-Src Random */
#define F_UDPDST_RND  (1<<3)	/* UDP-Dst Random */
#define F_MACSRC_RND  (1<<4)	/* MAC-Src Random */
#define F_MACDST_RND  (1<<5)	/* MAC-Dst Random */
#define F_TXSIZE_RND  (1<<6)      /* Transmit packet size is random */
#define F_IPV6        (1<<7)	/* Interface in IPV6 Mode */
#define F_MPLS_RND    (1<<8)	/* Random MPLS labels */
#define F_VID_RND     (1<<9)	/* Random VLAN ID */
#define F_SVID_RND    (1<<10)	/* Random SVLAN ID */
#define F_FLOW_SEQ    (1<<11)	/* Sequential flows */
#define F_IPSEC_ON    (1<<12)	/* ipsec on for flows */
#define F_QUEUE_MAP_RND (1<<13)	/* queue map Random */
#define F_QUEUE_MAP_CPU (1<<14)	/* queue map mirrors smp_processor_id() */
#define F_NODE          (1<<15)	/* Node memory alloc*/
#define F_UDPCSUM       (1<<16)	/* Include UDP checksum */
#define F_NO_TIMESTAMP  (1<<17)	/* Don't timestamp packets (default TS) */

#define F_PG_STOPPED  (1<<28)   /* Endpoint is stopped, report only */
#define F_TCP         (1<<29)   /* Send TCP packet instead of UDP */
#define F_USE_REL_TS  (1<<30)	/* Use relative time-stamps, ie TSC or similar */
#define F_PEER_LOCAL  (1<<31)	/* peer endpoint is local, allows some optimizations */

/* Thread control flag bits */
#define T_TERMINATE   (1<<0)
#define T_STOP        (1<<1)	/* Stop run */
#define T_RUN         (1<<2)	/* Start run */
#define T_REMDEVALL   (1<<3)	/* Remove all devs */
#define T_REMDEV      (1<<4)	/* Remove one dev */
#define T_WAKE_BLOCKED (1<<5)	/* Wake up all blocked net-devices. */
#define T_ADD_DEV     (1<<6)	/* Add a device. */

/* Used to help with determining the pkts on receive */
#define PKTGEN_MAGIC 0xbe9be955
#define PG_PROC_DIR "pktgen"
#define PGCTRL	    "pgctrl"

#define MAX_CFLOWS  65536

#define VLAN_TAG_SIZE(x) ((x)->vlan_id == 0xffff ? 0 : 4)
#define SVLAN_TAG_SIZE(x) ((x)->svlan_id == 0xffff ? 0 : 4)

struct flow_state {
	__be32 cur_daddr;
	int count;
#ifdef CONFIG_XFRM
	struct xfrm_state *x;
#endif
	__u32 flags;
};

/* flow flag bits */
#define F_INIT   (1<<0)		/* flow has been initialized */

struct pktgen_dev {

	/*
	 * Try to keep frequent/infrequent used vars. separated.
	 */
	char ifname[IFNAMSIZ];
	char result[512];

	struct proc_dir_entry *entry;	/* proc file */
	struct pktgen_thread *pg_thread;	/* the owner */
	struct list_head list;		/* Used for chaining in the thread's run-queue */

	int running;		/* if this changes to false, the test will stop */

	/* If min != max, then we will either do a linear iteration, or
	 * we will do a random selection from within the range.
	 */
	__u32 flags;
	int removal_mark;	/* non-zero => the device is marked for
				 * removal by worker thread */

	__u32 min_pkt_size;	/* = ETH_ZLEN; */
	__u32 max_pkt_size;	/* = ETH_ZLEN; */
	int pkt_overhead;	/* overhead for MPLS, VLANs, IPSEC etc */
	__u32 nfrags;
	struct page *page;
	__u64 delay_ns;          /* Delay this much between sending packets. */
	__u64 count;		/* Default No packets to send */
	__u64 sofar;		/* How many pkts we've sent so far */
	__u64 tx_bytes;		/* How many bytes we've transmitted */
	__u64 tx_bytes_ll;	/* How many bytes we've transmitted, counting lower-level framing */
	__u64 errors;		/* Errors when trying to transmit, pkts will be re-sent */
	__u64 xmit_dropped;     /* got NET_XMIT_DROP return value on xmit */
	__u64 xmit_cn;          /* got NET_XMIT_CN return value on xmit */
	__u64 nanodelays;        /* how many times have we called nano-delay on this device? */
	__s64 accum_delay_ns;    /* Accumulated delay..when >= 1ms, we'll sleep on a wait queue. */
	__u64 sleeps;            /* How many times have we gone to sleep on the wait queue. */
	__u64 queue_stopped;     /* How many times was queue stopped when we tried to xmit? */
	/* runtime counters relating to clone_skb */
	__u64 next_tx_ns;	/* timestamp of when to tx next */
	__u64 req_tx_early; /* requested to tx, but is too early for us to tx. */

	__u64 oom_on_alloc_skb;
	__u64 allocated_skbs;
	__u32 clone_count;

	int tx_blocked; /* Need to tx as soon as able... */
	int last_ok;		/* Was last skb sent?
				 * Or a failed transmit of some sort?  This will keep
				 * sequence numbers in order, for example.
				 */
	__u64 started_at;	/* micro-seconds */
	__u64 stopped_at;	/* micro-seconds */
	__u64 idle_acc_ns; /* nano-seconds */
	__u32 seq_num;

	__u32 conn_id; /* Identifier for pkts generated by this device */
	__u32 peer_conn_id; /* Identifier for pkts that peer generates */
	__u32 clone_skb;		/* Use multiple SKBs during packet gen.  If this number
				 * is greater than 1, then that many copies of the same
				 * packet will be sent before a new packet is allocated.
				 * For instance, if you want to send 1024 identical packets
				 * before creating a new packet, set clone_skb to 1024.
				 */
	__u32 peer_clone_skb;      /* Peer (transmitter's) clone setting. */
	__u32 force_new_skb; /** flag:  If set, will act as if clone_skb max has been reached,
			      * except new skb will have old seq-no, and existing skb-cloned
			      * count will not be reset.  This will force a new pkt to be generated
			      * w/out distrurbing pkt-drop counters, etc.  Useful for when changing
			      * pkt-sizes with a large clone-skb setting.
			      */

	char dst_min[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char dst_max[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char src_min[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char src_max[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */

	struct in6_addr in6_saddr;
	struct in6_addr in6_daddr;
	struct in6_addr cur_in6_daddr;
	struct in6_addr cur_in6_saddr;
	/* For ranges */
	struct in6_addr min_in6_daddr;
	struct in6_addr max_in6_daddr;
	struct in6_addr min_in6_saddr;
	struct in6_addr max_in6_saddr;

	/* If we're doing ranges, random or incremental, then this
	 * defines the min/max for those ranges.
	 */
	__u32 saddr_min;	/* inclusive, source IP address */
	__u32 saddr_max;	/* exclusive, source IP address */
	__u32 daddr_min;	/* inclusive, dest IP address */
	__u32 daddr_max;	/* exclusive, dest IP address */

	__u16 udp_src_min;	/* inclusive, source UDP port */
	__u16 udp_src_max;	/* exclusive, source UDP port */
	__u16 udp_dst_min;	/* inclusive, dest UDP port */
	__u16 udp_dst_max;	/* exclusive, dest UDP port */

	/* DSCP + ECN */
	__u8 tos;            /* six most significant bits of (former) IPv4 TOS are for dscp codepoint */
	__u8 traffic_class;  /* ditto for the (former) Traffic Class in IPv6 (see RFC 3260, sec. 4) */

	/* MPLS */
	unsigned int nr_labels;	/* Depth of stack, 0 = no MPLS */
	__be32 labels[MAX_MPLS_LABELS];


	/* VLAN/SVLAN (802.1Q/Q-in-Q) */
	__u8  vlan_p;
	__u8  vlan_cfi;
	__u16 vlan_id;  /* 0xffff means no vlan tag */

	__u8  svlan_p;
	__u8  svlan_cfi;
	__u16 svlan_id; /* 0xffff means no svlan tag */


	__u32 src_mac_count;	/* How many MACs to iterate through */
	__u32 dst_mac_count;	/* How many MACs to iterate through */

	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];

	__u32 cur_dst_mac_offset;
	__u32 cur_src_mac_offset;
	__u32 cur_saddr;
	__u32 cur_daddr;
	__u32 tcp_seqno;
	__u16 ip_id;
	__u16 cur_udp_dst;
	__u16 cur_udp_src;
	__u16 cur_queue_map;
	__u16 flushed_already; // Have we seen the first force_new_skb flush?
	__u32 cur_pkt_size;
	__u32 last_pkt_size;

	__u8 hh[14];
	/* = {
	   0x00, 0x80, 0xC8, 0x79, 0xB3, 0xCB,

	   We fill in SRC address later
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x08, 0x00
	   };
	 */
	__u16 pad;		/* pad out the hh struct to an even 16 bytes */

	struct sk_buff *skb;	/* skb we are to transmit next, mainly used for when we
				 * are transmitting the same one multiple times
				 */
	struct pktgen_hdr *pgh; /* pointer into skb where pkt-gen header lies */
	struct net_device *odev;	/* The out-going device.  Note that the device should
					 * have it's pg_info pointer pointing back to this
					 * device.  This will be set when the user specifies
					 * the out-going device name (not when the inject is
					 * started as it used to do.)
					 */
	char odevname[32];
	struct flow_state *flows;
	unsigned int cflows;	/* Concurrent flows (config) */
	unsigned int lflow;	/* Flow length  (config) */
	unsigned int nflows;	/* accumulated flows (stats) */
	unsigned int curfl;	/* current sequenced flow (state)*/
	__u16 queue_map_min;
	__u16 queue_map_max;
	__u32 skb_priority;	/* skb priority field */
	unsigned int burst;	/* number of duplicated packets to burst */
	int node;		/* Memory node */

#ifdef CONFIG_XFRM
	__u8	ipsmode;		/* IPSEC mode (config) */
	__u8	ipsproto;		/* IPSEC type (config) */
	__u32	spi;
	struct xfrm_dst xdst;
	struct dst_ops dstops;
#endif

	int last_rx_lat;
	int running_jitter; /* in micro-seconds * 1024 */
	int avg_latency; /* in micro-seconds */
	int min_latency;
	int max_latency;
	__u64 latency_bkts[LAT_BUCKETS_MAX];
	__u64 pkts_rcvd_since_clear_lat; /* with regard to clearing/resetting the latency logic */
	__s64 total_lat; /* add all latencies together...then can divide later for over-all average */


	/* Fields relating to receiving pkts */
        __u32 last_seq_rcvd;
        __u64 ooo_rcvd;  /* out-of-order packets received */
        __u64 pkts_rcvd; /* packets received */
	__u64 rx_crc_failed; /* pkts received with bad checksums. */
        __u64 dup_rcvd;  /* duplicate packets received */
        __u64 bytes_rcvd; /* total bytes received, as obtained from the skb */
        __u64 bytes_rcvd_ll; /* total bytes received, as obtained from the skb, includes lower-level framing */
        __u64 seq_gap_rcvd; /* how many gaps we received.  This coorelates to
                             * dropped pkts, except perhaps in cases where we also
                             * have re-ordered pkts.  In that case, you have to tie-break
                             * by looking at send v/s received pkt totals for the interfaces
                             * involved.
                             */
        __u64 non_pg_pkts_rcvd; /* Count how many non-pktgen skb's we are sent to check. */
        __u64 dup_since_incr; /* How many dumplicates since the last seq number increment,
                               * used to detect gaps when multiskb > 1
                               */
	__u64 pkts_rcvd_wrong_conn; /* Packets received with wrong connection id */
	__u64 neg_latency;
};

/** Cannot make this bigger without increasing minimum ethernet frame above 60 bytes. */
struct pktgen_hdr {
	__u32 pgh_magic;
	__u32 seq_num;
	__u32 tv_hi; // top 32-bits of 64-bit nano-sec timer.
	__u32 tv_lo; // bottom 32-bits of 64-bit nano-sec timer.
	__u16 conn_id; // Identifier for this pktgen flow.
} __attribute__((__packed__));


struct pktgen_net {
	struct net		*net;
	struct proc_dir_entry	*proc_dir;
	struct list_head	pktgen_threads;
	/* This helps speed up exit since otherwise one might wait
	 * HZ/10 for each thread.
	 */
	bool			pktgen_exiting;
};


struct pktgen_thread {
	struct list_head if_list;	/* All device here */
	struct list_head th_list;
	struct task_struct* tsk;
	int removed;
	char result[512];

	/* Field for thread to receive "posted" events terminate, stop ifs etc. */

	u32 control;
	char* control_arg;
	int pid;
	int cpu;
	int sleeping;
	unsigned long nqw_callbacks;
	unsigned long nqw_wakeups;

	wait_queue_head_t queue;
	struct completion start_done;
	struct pktgen_net *net;
};

struct pg_nqw_data {
	#define PG_NQW_MAGIC 0x82743ab6
	u32 magic;
	struct pg_nqw_data* next;
	atomic_t nqw_ref_count;
	struct pktgen_thread* pg_thread;
};

struct pktgen_dev_report {
	__u32 api_version;
	__u32 flags;
	__u32 min_pkt_size;
	__u32 max_pkt_size;
	__u32 nfrags;

	__u32 clone_skb;		/* Use multiple SKBs during packet gen.  If this number
				 * is greater than 1, then that many copies of the same
				 * packet will be sent before a new packet is allocated.
				 * For instance, if you want to send 1024 identical packets
				 * before creating a new packet, set clone_skb to 1024.
				 */
	__u32 peer_clone_skb;      /* Peer (transmitter's) clone setting. */
	__s32 avg_latency; /* in micro-seconds */
	__s32 min_latency;
	__s32 max_latency;

	char thread_name[32];
	char interface_name[32];
	char dst_min[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char dst_max[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char src_min[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	char src_max[IP_NAME_SZ];	/* IP, ie 1.2.3.4 */
	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	__u16 running_jitter; /* in micro-seconds */
	__u16 burst; /* pad to 8-byte boundary */

	/* If we're doing ranges, random or incremental, then this
	 * defines the min/max for those ranges.
	 */
	__u32 saddr_min;	/* inclusive, source IP address */
	__u32 saddr_max;	/* exclusive, source IP address */
	__u32 daddr_min;	/* inclusive, dest IP address */
	__u32 daddr_max;	/* exclusive, dest IP address */

	__u16 udp_src_min;	/* inclusive, source UDP port */
	__u16 udp_src_max;	/* exclusive, source UDP port */
	__u16 udp_dst_min;	/* inclusive, dest UDP port */
	__u16 udp_dst_max;	/* exclusive, dest UDP port */

	/* MPLS */
	__u32 nr_labels;	/* Depth of stack, 0 = no MPLS */
	__be32 labels[MAX_MPLS_LABELS];

	__u32 src_mac_count;	/* How many MACs to iterate through */
	__u32 dst_mac_count;	/* How many MACs to iterate through */

	__u64 nflows;	/* accumulated flows (stats) */
	__u32 cflows;	/* Concurrent flows (config) */
	__u32 lflow;	/* Flow length  (config) */

	__u64 delay_ns; /* Delay this much between sending packets. */
	__u64 count;  /* Default No packets to send */
	__u64 sofar;  /* How many pkts we've sent so far */
	__u64 tx_bytes; /* How many bytes we've transmitted */
	__u64 errors;    /* Errors when trying to transmit, pkts will be re-sent */
	__u64 latency_bkts[LAT_BUCKETS_MAX];
	__u64 pkts_rcvd_since_clear_lat; /* with regard to clearing/resetting the latency logic */

		/* Fields relating to receiving pkts */
        __u64 ooo_rcvd;  /* out-of-order packets received */
        __u64 pkts_rcvd; /* packets received */
        __u64 dup_rcvd;  /* duplicate packets received */
        __u64 bytes_rcvd; /* total bytes received, as obtained from the skb */
        __u64 seq_gap_rcvd; /* how many gaps we received.  This coorelates to
                             * dropped pkts, except perhaps in cases where we also
                             * have re-ordered pkts.  In that case, you have to tie-break
                             * by looking at send v/s received pkt totals for the interfaces
                             * involved.
                             */
        __u64 non_pg_pkts_rcvd; /* Count how many non-pktgen skb's we are sent to check. */

	struct in6_addr in6_saddr;
	struct in6_addr in6_daddr;
	/* For ranges */
	struct in6_addr min_in6_daddr;
	struct in6_addr max_in6_daddr;
	struct in6_addr min_in6_saddr;
	struct in6_addr max_in6_saddr;

	__u64 bytes_rcvd_ll; /* total bytes received, as obtained from the skb, includes lower-level framing */
	__u64 tx_bytes_ll; /* total bytes transmitted, as obtained from the skb, includes lower-level framing */
	__s64 total_lat; /* add all latencies together...then can divide later for over-all average */
	__u64 pkts_rcvd_wrong_conn; /* How many pkts received with wrong connection id? */
	__u32 conn_id; /* reported connection ID */
	__u32 peer_conn_id; /* reported peer connection ID */
	__u64 rx_crc_failed; /* pkts received with bad checksums. */
	char future_use[208]; /* Give us some room for growth w/out changing structure size */
} __attribute__((__packed__));

/* Define some IOCTLs.  Just picking random numbers, basically. */
#define GET_PKTGEN_INTERFACE_INFO 0x7450
struct pktgen_ioctl_info {
        char thread_name[32];
        char interface_name[32];
        struct pktgen_dev_report report;
};


/* Defined in dev.c */
extern int (*handle_pktgen_hook)(struct sk_buff *skb);

/* Returns < 0 if the skb is not a pktgen buffer. */
int pktgen_receive(struct sk_buff* skb);


#endif
