
#ifndef NS_IQM_H
#define NS_IQM_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "queue.h"
#include "packet.h"
#include "tcp.h"
#include "ip.h"
#include "flags.h"


#define TRACE  1                       // when 0, we don't race or write
                                       // var to disk

class IQM;

class IQMTimer : public TimerHandler
{
public:
	IQMTimer(IQM *a, void (IQM::*call_back)() )
		: a_(a), call_back_(call_back) {};
protected:
	virtual void expire (Event *e);
	IQM *a_;
	void (IQM::*call_back_)();
};


class IQM : public Queue {
	friend class IQMTimer;
public:
	IQM();
  ~IQM() {
		delete q_;
	}
	void Tq_timeout ();  // timeout every propagation delay
	void Te_timeout ();  // timeout every avg. rtt
  void Ts_timeout ();  // timeout every 1/4 RTT for syn rate check
	void everyRTT();     // timeout every highest rtt seen by rtr or some
	                     // preset rtt value
	void setupTimers();  // setup timers for IQM queue only
	void setEffectiveRtt(double rtt) ;

	void setBW(double bw);
	void setChannel(Tcl_Channel queue_trace_file);
	double totalDrops() { return total_drops_; }
  
  /******************** DropTail *****************************/
  PacketQueue *q_;	/* underlying FIFO queue */
	int drop_front_;	/* drop-from-front (rather than from tail) */
	int summarystats;
	int qib_;       	/* bool: queue measured in bytes? */
	int mean_pktsize_;	/* configured mean packet size in bytes */
 
  // Overloaded functions
	void enque(Packet* pkt);
	Packet* deque();
	virtual void drop(Packet* p);
	void print_summarystats();
 
	/*****************************Ahmed*************************/
	int incastonly;
	IQM *otherpq_;
	double queuefactor_;
	double currentfactor;
	double flowupdateinterval_;
	double incasttime;
	int maxnum;
	int flownum;
	int otherflownum;
	int *flow;
	double *lastrecv;
	double phi_bytes;
	double currentwnd;
	double oldavg;
	double oldwnd;
	bool overflow;
	double wndincr;
	double sswndincr;
	bool slowstart;
	int avgpktsize;
	int maxpktsize;
	int qlimb_;
	long totalenque, totalinc, totaldec;
	bool limitexceed;
	double micewnd;
	double elephwnd;
	
	int divisor;
	int syncount;
	bool incast;
	virtual int getflownum() const { return (flownum); }
	virtual double getfraction(int num) const {return totalenque>0?double(flow[num])/double(totalenque):0;}
	virtual double getTEfraction(int num) const {return num_cc_packets_in_Te_>0?double(flow[num])/double(num_cc_packets_in_Te_):0;}
	bool ismice(int num);
	int getmicenum();
	int command(int argc, const char*const* argv);
	/*****************************Ahmed*************************/

protected:

	// Utility Functions
	double max(double d1, double d2) { return (d1 > d2) ? d1 : d2; }
	double min(double d1, double d2) { return (d1 < d2) ? d1 : d2; }
    int max(int i1, int i2) { return (i1 > i2) ? i1 : i2; }
	int min(int i1, int i2) { return (i1 < i2) ? i1 : i2; }
	double abs(double d) { return (d < 0) ? -d : d; }

	virtual void trace_var(char * var_name, double var);

	// Estimation & Control Helpers
	void init_vars();

	// called in enque, but packet may be dropped; used for
	// updating the estimation helping vars such as
	// counting the offered_load_, sum_rtt_by_cwnd_
	virtual void do_on_packet_arrival(Packet* pkt);

	// called in deque, before packet leaves
	// used for writing the feedback in the packet
	virtual void do_before_packet_departure(Packet* p);

	virtual double qavgupdate(int nqueued, double ave, double q_w);
	// ---- Variables --------
	IQMTimer*        queue_timer_;
	IQMTimer*        estimation_control_timer_;
	IQMTimer*        syn_rate_timer_;
	IQMTimer*        rtt_timer_;
	double           link_capacity_bps_;

	static const double	ALPHA_;
	static const double	BETA_;
	static const double	queue_wieght_;
	static const double IQM_MAX_INTERVAL;
	static const double	IQM_MIN_INTERVAL;


	double          Te_;       // control interval
	double          Tq_;
    	double          Ts_;
	double          Tr_;
	double          effective_rtt_; // pre-set rtt value
	double          queue_bytes_;   // our estimate of the fluid model queue
	double 			queue_avg_;
	double 			old_queue_avg_;
	double          input_traffic_bytes_;       // input traffic in Te
	double          output_traffic_bytes_;       // output traffic in Te
	double          running_min_queue_bytes_;
	unsigned int    num_cc_packets_in_Te_;

	double		total_thruput_;
	int		min_queue_ci_;
	int		max_queue_ci_;
	// drops
	int 		drops_;
	int 		bdrops_;
	double		total_drops_ ;

	// ----- For Tracing Vars --------------//
	Tcl_Channel 	queue_trace_file_;

};


#endif //NS_IQM_H
