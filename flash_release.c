
// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP FLASH-CUBIC: CUBIC with FLASH-TCP Acceleration v1.0
 *
 * This is based on the TCP CUBIC implementation v2.3 from Linux 
 * (see below for TCP CUBIC’s original License information).
 *
 * The FLASH-TCP acceleration module was designed and implemented by
 * Lingfeng Guo and Jack Y. B. Lee,
 *  "FLASH-TCP – A New Approach to Accelerate TCP Slow-Start", IEEE Access, 2021.
 *
 * Copyright: Lingfeng Guo and Jack Y. B. Lee
 *            The Chinese University of Hong Kong
 * 
 * home page: http://www.mclab.org
 * Contact  : jacklee@computer.org
 */

/* 
 * Below are information reproduced from the original sources 
 * where this code is based upon. 
 */

/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

/*
 * TCP Westwood+: end-to-end bandwidth estimation for TCP
 *
 *      Angelo Dell'Aera: author of the first version of TCP Westwood+ in Linux 2.4
 *
 * Support at http://c3lab.poliba.it/index.php/Westwood
 * Main references in literature:
 *
 * - Mascolo S, Casetti, M. Gerla et al.
 *   "TCP Westwood: bandwidth estimation for TCP" Proc. ACM Mobicom 2001
 *
 * - A. Grieco, s. Mascolo
 *   "Performance evaluation of New Reno, Vegas, Westwood+ TCP" ACM Computer
 *     Comm. Review, 2004
 *
 * - A. Dell'Aera, L. Grieco, S. Mascolo.
 *   "Linux 2.4 Implementation of Westwood+ TCP with Rate-Halving :
 *    A Performance Evaluation Over the Internet" (ICC 2004), Paris, June 2004
 *
 * Westwood+ employs end-to-end bandwidth measurement to set cwnd and
 * ssthresh after packet loss. The probing phase is as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#include <linux/ktime.h>
#include <linux/time.h>


/*
* FLASH-TCP
*/
	#define BW_NUM	               5  // Size of sliding window to pick the max estimated bandwidth.
	#define INIT_CWND	           10 // Initial CWnd
	#define MIN_ACK_REQUIRED       3  // Minimum number of ACKs required to activate bandwidth estimation.
	#define NEED_AWND              1  // SUPPRESS_AWND flag: 0 means observe AWND, 1 ignores AWND unless it is 0.
	#define FLASH_DEBUG_PRINT	   1  // FLASH_DEBUG_PRINT: Set to 1 to enable debugging messages.

	// Struct for bandwidth estimation
	struct bandwidth {
		u8 flag;					
		/* for westwood*/
		u32 accounted;	
		u32 cumul_ack;
		u32 rtt;
		u32 bk;			

		/* for FLASH-TCP*/	
		u32 initial_seq;	// the initial seq of this TCP connection	
		u32 previous_bk;	// how many data acked since last ACK received
		u32 previous_seq;	// the seq number of the previous ACK
		u32 previous_acked;	// how many data acked by the last ACK
		u32 current_acked;	// how many data acked by this ACK
		u32 previous_interval;	// the interval between the previous ACK and its previous one
		u32 first_acked;	// how many data acked by the first ACK in a measurement cycle
		u32 max_interval_acked;	// how many data acked by the ACK that triggers max interval
		u32 max_interval;	// the max interval ever seen within a measurement cycle

		u32 end_pkt_seq ;
		u32 max_cwnd;
		u32 bw_count;		// we keep track of the total bw samples
		u8  bw_flag;		// to indicate which bw sample to be replaced
		u32 bw_sample[BW_NUM];	// we keep track of three samples, like BBR	
		u32 min_rtt;		// the reason why we keep track of min rtt is, if we found the BDP <= 10, we don't want to do pacing since there is no gain for doing that. unlikely happened though.
		struct timespec64 previous_recv_time;	// timestamp of the previous ACK
		struct timespec64 rtt_win_sx;		// beginning point of a new measurement cycle
	};

	// Struct for IP and Port information
	struct ip_port {
		ktime_t tstamp;
		union {
			struct sockaddr		raw;
			struct sockaddr_in	v4;
			struct sockaddr_in6	v6;
		}	src, dst;
	};
	ktime_t 	begin_ts;
/*
* FLASH-TCP
*/

/*
* for Original Cubic
*/
#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta __read_mostly = 2;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (msec << 3) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
	u64	count;		/* count the number of ack we have received.*/
	u32	bdp;
	u32	min_rtt;
	struct  bandwidth* flow;
};

// FLASH TCP function: get the hash table index for an IPV4 or IPV6 address
int get_index(struct sock* sk, u64* ip,  struct ip_port* copy ){
	const struct inet_sock *inet = inet_sk(sk);

    struct ip_port p;
   
   	switch (sk->sk_family){
		case AF_INET:
			// for ipv4, it is 4 Bytes
			p.dst.v4.sin_family = AF_INET;			
			p.dst.v4.sin_port = inet->inet_dport;		
			p.dst.v4.sin_addr.s_addr = inet->inet_daddr;	

			p.src.v4.sin_family = AF_INET;			
			p.src.v4.sin_port = inet->inet_sport;		
			p.src.v4.sin_addr.s_addr = inet->inet_saddr;	

			*copy = p;
			if (FLASH_DEBUG_PRINT)
				printk(KERN_INFO "IPv4:peer IPs %pISpc %pISpc ip: %llu\n",  &p.src, &p.dst, *ip);
			break;
		case AF_INET6:
	#if IS_ENABLED(CONFIG_IPV6)
			// for ipv6, only the last 64 bits are used.
			memset(&p.src.v6, 0, sizeof(p.src.v6)  );
			memset(&p.dst.v6, 0, sizeof(p.dst.v6)  );
			p.src.v6.sin6_family = AF_INET6;
			p.src.v6.sin6_port = inet->inet_sport;
			p.src.v6.sin6_addr = inet6_sk(sk)->saddr;

			p.dst.v6.sin6_family = AF_INET6;
			p.dst.v6.sin6_port = inet->inet_dport;
			p.dst.v6.sin6_addr = sk->sk_v6_daddr; 

			*copy = p;

			if (FLASH_DEBUG_PRINT)
				printk(KERN_INFO "IPv6:peer IPs %pISpc %pISpc ip: %llu\n",  &p.src, &p.dst, *ip);
			return 0;
	#endif
			return -1;
			break;
		default:
			if (FLASH_DEBUG_PRINT)
				printk(KERN_INFO "Likely IP error!!!!");
			return -1;
	}
	return 0;
}

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 bictcp_clock(void)
{
#if HZ < 1000
	return ktime_to_ms(ktime_get_real());
#else
	return jiffies_to_msecs(jiffies);
#endif
}

/* code for bw estimation */

/*
 * @westwood_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */


// currently no need to touch
static inline u32 westwood_acked_count(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

   if (!ca->flow)
      return 0;

	if (ca->flow->previous_seq != 0)
		ca->flow->cumul_ack = tp->snd_una - ca->flow->previous_seq;
	else
		ca->flow->cumul_ack = tp->mss_cache;

	if (!ca->flow->cumul_ack) {
		ca->flow->accounted += tp->mss_cache;
		ca->flow->cumul_ack = tp->mss_cache;
	}

	if (ca->flow->cumul_ack > tp->mss_cache) {
		if (ca->flow->accounted >= ca->flow->cumul_ack) {
			ca->flow->accounted -= (ca->flow->cumul_ack);
			ca->flow->cumul_ack = tp->mss_cache;
		} else {
			ca->flow->cumul_ack -= ca->flow->accounted;
			ca->flow->accounted = 0;
		}
	}
	return ca->flow->cumul_ack;
}

static inline u32 westwood_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}


/*
* FLASH-TCP bandwidth estimation
*/
static void westwood_update_window(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 period;
	long int diff;
	u64 previous_acked;
	u64 max_bw;
	u64 current_acked;
	u64 first_acked;
	u64 max_interval;
	u64 max_interval_acked;
	u64 previous_interval;
	long int delta = 0;
	u64 better_bw = 0;
	long int duration = 0; 
	long int received = 0;
	struct timespec64 ts;
	int i = 0;
	ts = ktime_to_timespec64(ktime_sub(ktime_get(), begin_ts));

    if (!ca->flow)
      return;

	// Diff is the time gap between current ACK and the previous ACK
	diff = 1000000 * ((long)ts.tv_sec - (long)ca->flow->previous_recv_time.tv_sec) + ((long)ts.tv_nsec - (long)ca->flow->previous_recv_time.tv_nsec)/1000;

	// Delta is the time elapsed since the beginning of current bw measurement
	delta = 1000000 * ((long)ts.tv_sec - (long)ca->flow->rtt_win_sx.tv_sec) + ((long)ts.tv_nsec - (long)ca->flow->rtt_win_sx.tv_nsec)/1000;


	// To get the initial sequence
	if (ca->flow->previous_seq == 0) {
		ca->flow->previous_seq = tcp_sk(sk)->snd_una;
		ca->flow->initial_seq = tcp_sk(sk)->snd_una;
	}

	// Get the number of data acked by current ACK
	ca->flow->current_acked = tcp_sk(sk)->snd_una - ca->flow->previous_seq;
	if (ca->flow->current_acked < tp->mss_cache)
		ca->flow->current_acked = tp->mss_cache;
	// Update the max ACK interval found in current bw measurement cycle
	if (diff >= ca->flow->max_interval && ca->count >= 1){
		ca->flow->max_interval = diff;
		ca->flow->max_interval_acked = ca->flow->current_acked;
		
	}
	printk(KERN_INFO "xxxxxx: flag: %u delta:%ld last:%llu diff:%ld bw:%llu bk: %u %llu) cwnd: %u rtt: %u  pacing: %lu flight: %u recv: %ld dur: %ld end_seq: %u high:%u count:%u\n", 
											ca->flow->bw_flag, delta, previous_interval, diff, better_bw, ca->flow->bk, current_acked, tp->snd_cwnd, 
											ca->min_rtt, sk->sk_pacing_rate, tcp_packets_in_flight(tp), received, duration, ca->flow->end_pkt_seq,tcp_highest_sack_seq(tp), ca->count);

	// The duration of current bw measurement cycle is set to the updated srtt (the same as Westwood)
	period = ca->flow->rtt;
	
	// To make the code clearer
	current_acked = ca->flow->current_acked;
	first_acked = ca->flow->first_acked;
	max_interval = ca->flow->max_interval;
	max_interval_acked = ca->flow->max_interval_acked;
	previous_interval = ca->flow->previous_interval;
	previous_acked = ca->flow->previous_acked;

	// we try to quickly estimate the bandwidth here. It will be executed only once.
	if (ca->count >= MIN_ACK_REQUIRED && tcp_highest_sack_seq(tp) >= ca->flow->end_pkt_seq && 
		ca->flow->end_pkt_seq != 0 && ca->flow->bw_count <= 0 && ca->flow->bw_flag == 0){
		if (tcp_highest_sack_seq(tp) == ca->flow->end_pkt_seq){ 
		// the bw estimation is triggered by 10th ack
			received =  ca->flow->bk - first_acked;
			duration = delta;
        		if (received > 0 && duration > 0)
            			better_bw = (u64)received * 8000 / duration;
        		else
				better_bw = 0;
        		ca->flow->bw_flag = 1;
		}
		else{ 
		// somehow the 10th ack is lost, hence we need to remove the gap 
			received  = ca->flow->bk - first_acked - max_interval_acked;
			duration = delta - max_interval;
			if (received > 0 && duration > 0)
               			better_bw = (u64)received * 8000 / duration;
			else
				better_bw = 0;	
			ca->flow->bw_flag = 2;
		}
		max_bw = better_bw;
		ca->bdp = (u64)ca->min_rtt *  max_bw * 1000 / 8 / tp->mss_cache / 1000000;
		if (ca->bdp > 1000)
			ca->bdp = 1000;
		if (FLASH_DEBUG_PRINT)
			printk(KERN_INFO "BW est in 1st RTT: flag: %u delta:%ld last:%llu diff:%ld bw:%llu bk: %u %llu) cwnd: %u rtt: %u  pacing: %lu flight: %u recv: %ld dur: %ld end_seq: %u\n", 
										ca->flow->bw_flag, delta, previous_interval, diff, better_bw, ca->flow->bk, current_acked, tp->snd_cwnd, 
										ca->min_rtt, sk->sk_pacing_rate, tcp_packets_in_flight(tp), received, duration, ca->flow->end_pkt_seq);

		if (ca->flow->bk < ca->flow->max_cwnd *tp->mss_cache && ca->bdp > tp->snd_cwnd ){
	 		ca->flow->bw_count = 0;
			ca->flow->bw_sample[ca->flow->bw_count%BW_NUM] = better_bw;
			tp->snd_cwnd = ca->bdp;
			sk->sk_pacing_rate =  better_bw * 1000 / 8;
			cmpxchg(&sk->sk_pacing_status,  SK_PACING_NONE,  SK_PACING_NEEDED);
			sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio = 100;
			sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio = 100;
		       	if (tp->snd_wnd < tp->snd_cwnd * tp->mss_cache && tp->snd_wnd != 0 && NEED_AWND)
				tp->snd_wnd = tp->snd_cwnd * tp->mss_cache;
		}
		else	// less likely
			ca->flow->bw_flag = 3;
	}
	if (ca->flow->bw_flag == 1){
		if (ca->flow->bw_count >= 1 || tp->snd_cwnd <= INIT_CWND){
			cmpxchg(&sk->sk_pacing_status,  SK_PACING_NEEDED,  SK_PACING_NONE);
        		sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio = 120;
			sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio = 200;
			ca->flow->bw_flag = 3;
		}
	}
	else if (ca->flow->bw_flag == 2){
		if (ca->flow->bw_count >= 2 || tp->snd_cwnd <= INIT_CWND){
			cmpxchg(&sk->sk_pacing_status,  SK_PACING_NEEDED,  SK_PACING_NONE);
	       		sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio = 120;
			sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio = 200;
			ca->flow->bw_flag = 3;
		}
	}
	else {
		cmpxchg(&sk->sk_pacing_status,  SK_PACING_NEEDED,  SK_PACING_NONE);
		sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio = 120;
		sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio = 200;
	}

	if (ca->flow->rtt && delta > max_t(u32, period, 0)) {
		// Need at least three ACKs to do the calculation.
		if (ca->count > 0 && ca->flow->bk >= MIN_ACK_REQUIRED * tp->mss_cache){
			// ACKed = 0/1 strongly indicates that this is triggered by FIN/FINACK
			// Normally bw triggered by FIN or FIN ACK contain less data
			if (current_acked <= 1 && 0){
			// the last bw sample, we do not care since it is not stateful-tcp anymore
			}
	
			// This is triggered by normal ACK
			else{
				// The first ACKed need to be removed for non-first bw sample 
				// Since now we update bk first and then do the bw calculation
				// By contrast, Westwood will do the bw calculation first then update bk
				received = ca->flow->bk - first_acked - max_interval_acked;
				duration = delta - max_interval;
				
				if (received > 0 && duration > 0)
					better_bw = (u64)received * 8000 / duration;		
				else
					better_bw = 0;	

				if (better_bw != 0){
					ca->flow->bw_count++;
					ca->flow->bw_sample[ca->flow->bw_count%BW_NUM] = better_bw;

					// Round-Robin to keep track of the latest three bw samples.
					// get the max BW sample
					max_bw = ca->flow->bw_sample[0];
					for(i = 1; i < BW_NUM; i++)
						if (max_bw < ca->flow->bw_sample[i])
								max_bw = ca->flow->bw_sample[i];				

		        	ca->bdp = (u64)ca->min_rtt *  max_bw * 1000 / 8 / tp->mss_cache / 1000000;
				}
				if (FLASH_DEBUG_PRINT)
					printk(KERN_INFO "BW est: flag: %u delta:%ld last:%llu diff:%ld bw:%llu bk: %u %llu) cwnd: %u rtt: %u  pacing: %lu flight: %u recv: %ld dur: %ld end_seq: %u\n", 
												ca->flow->bw_flag, delta, previous_interval, diff, better_bw, ca->flow->bk, current_acked, tp->snd_cwnd, 
												ca->min_rtt, sk->sk_pacing_rate, tcp_packets_in_flight(tp), received, duration, ca->flow->end_pkt_seq);
			}
		}
		// Reset the data 
		ca->flow->bk = 0;
		ca->flow->rtt_win_sx = ts;
		ca->flow->max_interval = 0;
		ca->flow->max_interval_acked = 0;
		ca->flow->first_acked = 0;

	}
	// Update parameters
	ca->flow->previous_recv_time = ts;
	ca->flow->previous_seq = tcp_sk(sk)->snd_una;
	ca->flow->previous_acked = ca->flow->current_acked;
	ca->flow->previous_bk = ca->flow->bk;
	ca->flow->previous_interval = diff;
}


static inline void westwood_fast_bw(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!ca->flow)
		return;

	if (ca->flow->previous_seq != 0)	
		ca->flow->bk += tp->snd_una - ca->flow->previous_seq;

	// This is the first ACK in our bw calculation cycle, which needed to be removed for the first bw sample
	if (ca->flow->previous_bk == 0)	
		ca->flow->first_acked = ca->flow->bk;

	westwood_update_window(sk);
}


static void tcp_westwood_ack(struct sock *sk, u32 ack_flags)
{
	struct bictcp *ca = inet_csk_ca(sk);

	if (!ca->flow)
		return;

	if (ack_flags & CA_ACK_SLOWPATH) {
		ca->flow->bk += westwood_acked_count(sk);
		if (ca->flow->previous_bk == 0)
			ca->flow->first_acked = ca->flow->bk;	
		westwood_update_window(sk);
		return;
	}
	westwood_fast_bw(sk);

}

static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock();
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}

/*
* FLASH-TCP. update records
*/

static void bictcp_release(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
   
	u64 ip;
	struct ip_port p;
	int flag;
	flag = get_index(sk, &ip, &p);

	if (!ca->flow || flag == -1)
		return;

	if (FLASH_DEBUG_PRINT)
			printk(KERN_INFO "Released. peer IPs %pISpc %pISpc ACKcount %llu BWcount: %u ,min_rtt: %u bw(%u %u %u) ssth: %u cwnd: %u",  &p.src, &p.dst, ca->count, ca->flow->bw_count, ca->min_rtt, ca->flow->bw_sample[0], ca->flow->bw_sample[1], ca->flow->bw_sample[2], tp->snd_ssthresh, tp->snd_cwnd);
	//		printk(KERN_INFO "IPV4: Release:peer IPs %pISpc %pISpc ACKcount %llu BWcount: %u ,min_rtt: %u bw(%u %u %u) ssth: %u cwnd: %u \n",  
	//				&p->src, &p->dst,  ca->count, ca->flow->bw_count, ca->min_rtt, ca->flow->bw_sample[0], 
	//				ca->flow->bw_sample[1], ca->flow->bw_sample[2], tp->snd_ssthresh, tp->snd_cwnd);
	kfree(ca->flow);
	ca->flow = NULL;
}

/*
* FLASH-TCP. init parameters
*/
static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	u64 ip;
	struct ip_port p;
	int flag;
	flag = get_index(sk, &ip, &p);
	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (hystart)
		bictcp_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;

	ca->count = 0;

	if (flag != -1)
		ca->flow = kmalloc( sizeof(struct bandwidth), GFP_KERNEL);
	else
		ca->flow = NULL;

	if (ca->flow){
		memset(ca->flow,0, sizeof(struct bandwidth));
		ca->flow->previous_recv_time = ktime_to_timespec64(ktime_sub(ktime_get(), begin_ts));
		ca->flow->max_cwnd = INIT_CWND * 2;
		if (FLASH_DEBUG_PRINT)
			printk(KERN_INFO "Memory allocation done, running FLASH :peer IPs %pISpc %pISpc",  &p.src, &p.dst);
	}
	else
		if (FLASH_DEBUG_PRINT)
			printk(KERN_INFO "Memory allocation failed, running Cubic :peer IPs %pISpc %pISpc",  &p.src, &p.dst);
}


/*
* FLASH-TCP. set initial pacing rate 
*/
static void bictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}
/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - ca->epoch_start);
	t += msecs_to_jiffies(ca->delay_min >> 3);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		if (hystart && after(ack, ca->end_seq))
			bictcp_hystart_reset(sk);
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	bictcp_update(ca, tp->snd_cwnd, acked);
	tcp_cong_avoid_ai(tp, ca->cnt, acked);

}

static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

	if (FLASH_DEBUG_PRINT)
		printk(KERN_INFO "Loss event. BDP: %u cwnd:%u", ca->bdp, tp->snd_cwnd);
	// here, we configure the cwnd to max(one bdp, 0.7 cwnd)
	if (ca->bdp > max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U))
		return ca->bdp;
	else
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
	}

}

static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (ca->found & hystart_detect)
		return;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock();

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) {
			ca->last_ack = now;
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4) {
				ca->found |= HYSTART_ACK_TRAIN;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay;

			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found |= HYSTART_DELAY;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}
}

static void bictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	if (ca->flow){
		if (tcp_packets_in_flight(tp) >= 5 && ca->flow->end_pkt_seq == 0){
			ca->flow->end_pkt_seq = tp->snd_nxt;
			ca->flow->rtt_win_sx = ktime_to_timespec64(ktime_sub(ktime_get(), begin_ts));
			printk(KERN_INFO "Beginning sequence: bk:%u cwnd:%u minrtt:%u pacing:%u flight:%u end_seq:%u", ca->flow->bk, 
				tp->snd_cwnd, ca->min_rtt, sk->sk_pacing_rate, tcp_packets_in_flight(tp), ca->flow->end_pkt_seq);
		}
		// We limit the max cwnd to 2 bdp
		if (ca->flow->max_cwnd < 2 * ca->bdp)
			ca->flow->max_cwnd = 2 * ca->bdp;
		// we set the CWnd limit here
		if (tp->snd_cwnd > ca->flow->max_cwnd)
			tp->snd_cwnd = ca->flow->max_cwnd;

		// Ignore awnd unless zero
		if (tp->snd_wnd < tp->snd_cwnd * tp->mss_cache && tp->snd_wnd != 0 && NEED_AWND)
			tp->snd_wnd = tp->snd_cwnd * tp->mss_cache;

		ca->flow->rtt = sample->rtt_us;
		if (ca->min_rtt == 0 || ca->min_rtt > ca->flow->rtt)
			ca->min_rtt = ca->flow->rtt;
	}
	ca->count ++;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = (sample->rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (hystart && tcp_in_slow_start(tp) &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);

}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= bictcp_init,
	.release	= bictcp_release,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.cwnd_event	= bictcp_cwnd_event,
	.pkts_acked     = bictcp_acked,
	.in_ack_event	= tcp_westwood_ack,
	.owner		= THIS_MODULE,
	.name		= "flash_release3",
};

static int __init cubictcp_register(void)
{
        int ret = -ENOMEM;

	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
	
	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */
	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	// record the begin timestamp when the module is registered
	begin_ts = ktime_get();

	return tcp_register_congestion_control(&cubictcp);

	return ret;
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FLASH");
MODULE_VERSION("2.3");
