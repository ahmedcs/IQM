/*
 * IQM - Incast-aware Queue management in OpenvSwitch datapath Module.
 *
 *  Author: Ahmed Mohamed Abdelmoniem Sayed, <ahmedcs982@gmail.com, github:ahmedcs>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of CRAPL LICENCE avaliable at
 *    http://matt.might.net/articles/crapl/.
 *    http://matt.might.net/articles/crapl/CRAPL-LICENSE.txt
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the CRAPL LICENSE for more details.
 *
 * Please READ carefully the attached README and LICENCE file with this software
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <net/pkt_sched.h>
#include <linux/openvswitch.h>
#include "vport.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"
#include "datapath.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define DEV_MAX 1000

static bool iqm_detected = false;
module_param(iqm_detected, bool, 0644);
MODULE_PARM_DESC(iqm_detected, " iqm_detected enables IQM incast detection mechanism");

static int M = 16;
module_param(M, int, 0644);
MODULE_PARM_DESC(M, " M determines max number of intervals before turning off incast");

static long int interval = 200L;
module_param(interval, long, 0644);
MODULE_PARM_DESC(interval, " interval determines the timer interval in microseconds");

static spinlock_t globalLock;
static struct hrtimer my_hrtimer;
static ktime_t ktime;

static short devcount=0;
static bool timerrun=false;
static short count=0;
static short devindex[DEV_MAX];
static int wnd[DEV_MAX];
static int qlimit[DEV_MAX];
static short conncount[DEV_MAX];
static unsigned short MSS[DEV_MAX];
static short syncount[DEV_MAX];
static bool incast[DEV_MAX];
static long int incastinterval[DEV_MAX];
static bool fail=false;
static struct timespec currincast_tm[DEV_MAX];
static struct timespec curr_tm;

bool iqm_detect(void)
{
    return iqm_detected;
}

enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
    //timerrun=false;
    struct net_device * dev;
    int i=0;
    getnstimeofday(&curr_tm);
    while (i<devcount)
    {
        //if(conncount[i]>0)
        //{
            dev = dev_get_by_index(&init_net, devindex[i]);
            int backlog=dev->qdisc->qstats.backlog;
	    if(backlog < (qlimit[i]>>3) && (incastinterval[i]-jiffies)*1000>=7*interval)
		incast[i]=false;
	    int amount=syncount[i] * MIN(wnd[i], 10 * MSS[i]) + backlog;
	    if(!incast[i] &&  amount > qlimit[i] && backlog > 0 )
	    {
		printk(KERN_INFO "Openvswitch: TIME: %.2lu:%.2lu:%.2lu:%.6lu Incast happend, syncount: %d, window: %d, backlog: %d, amount: %d, qlimit:%d \r\n",(curr_tm.tv_sec / 3600) % (24), (curr_tm.tv_sec / 60) % (60), curr_tm.tv_sec % 60,    curr_tm.tv_nsec / 1000, syncount[i],  MIN(wnd[i],10*MSS[i]), backlog, amount, qlimit[i]);		
		incast[i] = true;
		syncount[i]=0;
		incastinterval[i]=jiffies;
		//count=0;
		
	    }	    
	    if(count==M)
		    syncount[i]=0;
        //}
        i++;

    }
    if(count == M)
        count=0; 
    else
        count++;

    if(iqm_detected)
    {
		timerrun=true;
        ktime_t ktnow = hrtimer_cb_get_time(&my_hrtimer);
        int overrun = hrtimer_forward(&my_hrtimer, ktnow, ktime);
        return HRTIMER_RESTART;
    }
//stop:
    timerrun=false;
    return HRTIMER_NORESTART;
}

void process_packet(struct sk_buff *skb, struct vport *inp , struct vport *outp)
{
    if(!iqm_detected)
		return;
    const struct net_device *in=netdev_vport_priv(inp)->dev;
    const struct net_device *out=netdev_vport_priv(outp)->dev;
    int k=0,i=-1,j=-1;
    if (skb && in && out && !fail)
    {

        struct iphdr * ip_header = (struct iphdr *)skb_network_header(skb);
        if (ip_header && ip_header->protocol == IPPROTO_TCP)
        {

            struct tcphdr * tcp_header = (void *)(skb_network_header(skb) + ip_header->ihl * 4);
		k=0;
	    while(k < devcount)
	    {
			if(devindex[k] == in->ifindex)
			     i=k;
			if(devindex[k] == out->ifindex)
			     j=k;
			k++;
	     }
	     if(i==-1 || j==-1)
	     {
		   if(i==-1)
		   {
		        add_dev(in);
			i=0;
		   }
		   if(j==-1)
		   {
		        add_dev(out);
			j=0;
		   }
	    }
	    if(i==-1)
		return;
	    if(!timerrun)
     	    {
            	if (hrtimer_active(&my_hrtimer) != 0)
                  hrtimer_cancel(&my_hrtimer);
            	ktime = ktime_set(0 , interval * ( (unsigned long) 1E3L) );
            	hrtimer_start(&my_hrtimer, ktime, HRTIMER_MODE_REL);
            	timerrun=true;
      	    }
	    if(!incast[i] && tcp_header->syn) 
	    	syncount[i]++;
	    else if(!incast[i] && tcp_header->fin)
	    	syncount[i]=MAX(0,syncount[i]-1);
            if(tcp_header->ack && MSS[i] && (incast[i] || in->qdisc->qstats.backlog>=qlimit[i]-MSS[i]))
            {
                    __be16 old_win = tcp_header->window;
                    __be16 new_win = htons(MSS[i]);
                    tcp_header->window = new_win;
                    csum_replace2(&tcp_header->check, old_win, new_win);
            }
        }
    }
    return;
}

void add_dev(const struct net_device * dev)
{
    if(dev==NULL || devcount+1>DEV_MAX)
    {
        fail=true;
        timerrun=false;
        printk(KERN_INFO "OpenVswitch : Fatal Error Exceed Allowed number of Devices : %d \n", devcount);
        return;
    }
    if(dev->qdisc->limit <=0 || psched_mtu(dev) <=0)
        return;
    devindex[devcount] = dev->ifindex;
    MSS[devcount] = (psched_mtu(dev) - 54);
    qlimit[devcount] = dev->qdisc->limit;
    wnd[devcount] = qlimit[devcount] >> 3;
    conncount[devcount] = 0;
    syncount[devcount]=0;
    incast[devcount] = false;
    incastinterval[devcount]=0;

    printk(KERN_INFO "OpenVswitch ADD: [%i:%s] initials : %d %d %d %d %d\n", devindex[devcount], (const char*)dev->name ,  qlimit[devcount], dev->tx_queue_len, psched_mtu(dev), wnd[devcount], MSS[devcount] );
    devcount++;
    printk(KERN_INFO "OpenVswitch ADD: total number of detected devices : %d \n", devcount);

}

/*void update_dev(const struct net_device * dev, int i)
{
    if(qlimit[i] == dev->qdisc->limit && MSS[i] == (psched_mtu(dev) - 54))
        return;

    MSS[i] = (psched_mtu(dev) - 54);
    qlimit[i] = dev->qdisc->limit;

    printk(KERN_INFO "OpenVswitch update: [%i:%s] initials : %d %d %d %d %d\n", devindex[i], (const char*)dev->name ,  qlimit[i], dev->tx_queue_len, psched_mtu(dev), wnd[i], MSS[i] );
    return;

}*/

void del_dev(const struct net_device * dev)
{
    if(dev==NULL || devcount<=0)
        return;
    int i=0;
    while(i<devcount && devindex[i]!=dev->ifindex)
    {
            i++;
    }
    if(i<devcount)
    {
        printk(KERN_INFO "OpenVswitch DEL: [%d:%s] \n", devindex[i], (const char*)dev->name);
        int j=i;
        while(j<devcount && devindex[j+1]!=-1)
        {
            devindex[j] = devindex[j+1];
            MSS[j] = MSS[j+1];
            wnd[j] = wnd[j+1];
            qlimit[j] = qlimit[j+1];
            conncount[j] = conncount[j+1];
    	    syncount[j]=syncount[j+1];
	        incast[j] = incast[j+1];
            incastinterval[j]= incastinterval[j+1];
            j++;
        }

        devcount--;
        printk(KERN_INFO "OpenVswitch DEL: total number of detected devices : %d \n", devcount);
    }
}


void init_iqm(void)
{

    hrtimer_init(&my_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    my_hrtimer.function = &timer_callback;
    timerrun=false;

    devcount=0;
    fail=false;

    int i=0;
    while( i < DEV_MAX)
    {
        devindex[i]=-1;
        conncount[i]=0;
        MSS[i]=0;
        wnd[i]=0;
        qlimit[i]=0;
        syncount[devcount]=0;
	    incast[i] = false;
        incastinterval[i]=0;
        i++;

    }
    if(interval<0)
        interval = 1000L;
    if(M<0)
        M=8;
    printk(KERN_INFO "OpenVswitch Init IQM incast detector: interval : %ld , M : %d, iqm_detected: %d \n", interval, M, iqm_detected);

    return;
}

void cleanup_iqm(void)
{
    int ret_cancel = 0;
    while( hrtimer_callback_running(&my_hrtimer) )
    {
        ret_cancel++;
    }
    if (ret_cancel != 0)
    {
        printk(KERN_INFO " OpenVswitch: testjiffy Waited for hrtimer callback to finish (%d)\n", ret_cancel);
    }
    if (hrtimer_active(&my_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&my_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy active hrtimer cancelled: %d \n", ret_cancel);
    }
    if (hrtimer_is_queued(&my_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&my_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy queued hrtimer cancelled: %d \n", ret_cancel);
    }
    printk(KERN_INFO "OpenVswitch: Stop Incast detector IQM\n");


}

