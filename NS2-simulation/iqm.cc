#include "iqm.h"
#include "random.h"
#include "flags.h"
#include "tcp-full.h"

#define INF 999999999

const double IQM::queue_wieght_=0.75;

static class IQMClass: public TclClass {
public:
	IQMClass() :
		TclClass("Queue/IQM") {
	}
	TclObject* create(int, const char* const *) {
		return (new IQM);
	}
} class_IQM;

IQM::IQM() :
	queue_timer_(NULL), estimation_control_timer_(NULL), syn_rate_timer_(NULL), rtt_timer_(NULL),
			effective_rtt_(0.0) {
    q_ = new PacketQueue;
	pq_ = q_;
	bind_bool("drop_front_", &drop_front_);
	bind_bool("summarystats_", &summarystats);
	bind_bool("queue_in_bytes_", &qib_);  // boolean: q in bytes?
	bind("mean_pktsize_", &mean_pktsize_);
	init_vars();
	setupTimers();

	//double now = Scheduler::instance().clock();
    //printf("An instance of IQM has been created at time: %f\n", now);
}

void IQM::setupTimers() {
	//estimation_control_timer_ = new RWNDSYNTimer(this, &IQM::Te_timeout);
	queue_timer_ = new IQMTimer(this, &IQM::Tq_timeout);
  syn_rate_timer_ = new IQMTimer(this, &IQM::Ts_timeout);

	// Scheduling timers randomly so routers are not synchronized
	double T;

	T= Random::normal(Tq_, 0.2 * Tq_);
	queue_timer_->sched(T);

	//T = Random::normal(0.001, 0.2 * 0.001);
	//estimation_control_timer_->sched(T);

	T = Random::normal(Ts_, 0.2 * Ts_);
	syn_rate_timer_->sched(T);
}

void IQM::setBW(double bw) {
	if (bw > 0)
		link_capacity_bps_ = bw;
}

void IQM::setChannel(Tcl_Channel queue_trace_file) {
	queue_trace_file_ = queue_trace_file;
}

Packet* IQM::deque() {
	double inst_queue = byteLength();
	/* L 32 */
	if (inst_queue < running_min_queue_bytes_)
		running_min_queue_bytes_ = inst_queue;

	//Packet* p = DropTail::deque();
 if (summarystats && &Scheduler::instance() != NULL) {
                Queue::updateStats(qib_?q_->byteLength():q_->length());
        }
	Packet* p = q_->deque();
 
	do_before_packet_departure(p);

	return (p);
}

void IQM::enque(Packet* p) {
	do_on_packet_arrival(p);
	//DropTail::enque(p);
 
  if (summarystats) {
                Queue::updateStats(qib_?q_->byteLength():q_->length());
	}

	int qlimBytes = qlim_ * mean_pktsize_;
	if ((!qib_ && (q_->length() + 1) >= qlim_) ||
  	(qib_ && (q_->byteLength() + hdr_cmn::access(p)->size()) >= qlimBytes)){
		// if the queue would overflow if we added this packet...
		if (drop_front_) { /* remove from head of queue */
			q_->enque(p);
			Packet *pp = q_->deque();
			drop(pp);
		} else {
			drop(p);
		}
	} else {
		q_->enque(p);
	}

}

/*****************************************Ahmed*****************************************/
void IQM::do_on_packet_arrival(Packet* pkt) {
	hdr_tcp *tcph = NULL;
	double inst_queue = byteLength();
        double now = Scheduler::instance().clock();
	//double pkt_size = double(hdr_cmn::access(pkt)->size());
	totalenque++;
	qlimb_ = qlim_ * mean_pktsize_;
	hdr_cmn *cmnh = hdr_cmn::access(pkt);
	input_traffic_bytes_ += double(cmnh->size());
	maxpktsize = max(maxpktsize, cmnh->size());
	/*if(cmnh->ptype() == PT_UDP)
		syncount++;*/

	/************************************************Ahmed******************************************/
	//queue_avg_ = qavgupdate(this->byteLength(), queue_avg_, queue_wieght_);
	hdr_ip* iph = hdr_ip::access(pkt);
	if (cmnh->ptype() == PT_TCP)
		tcph = hdr_tcp::access(pkt);
	int num = iph->flowid();
	if (num < maxnum && lastrecv[num] >=0) 
	{
		lastrecv[num] = now;
		flow[num]++;
	}
	 if (tcph!=NULL && (tcph->flags() & TH_SYN))
	 {
			flow[num]++;
			lastrecv[num] = now;
			flownum++;
			syncount++;
			printf("SYN of flow %d arrived at time %f\n", num, now);
	 }
	else if (tcph!=NULL && (tcph->flags() & TH_FIN))
	 {
			flow[num]=0;
			lastrecv[num] = -1;
			flownum = max(0, flownum-1);
			syncount = max(0, syncount-1);
			printf("FIN of flow %d arrived at time %f\n", num, now);
	 }
	if (incast && ((queue_avg_ < qlimb_*queuefactor_  && now - incasttime >= 8*Ts_) || now - incasttime >= 16*Ts_))
	{
		incast=false;
		incasttime=-1;
		printf("incast stopped at time %f\n", now);
	}
	/************************************************End Ahmed*********************************************/
}

void IQM::do_before_packet_departure(Packet* p) {
	if (!p)
		return;

	hdr_cmn *cmnh = hdr_cmn::access(p);
	/* L 1 */
	output_traffic_bytes_ += double(cmnh->size());
	++num_cc_packets_in_Te_;
	    if(otherpq_ != NULL)
	    {
		if ( otherpq_->incast && cmnh->ptype() == PT_ACK)//  && otherpq_->flownum>0) 
		{
		    hdr_tcp *tcph = hdr_tcp::access(p); // TCP header
		    double incomewnd = tcph->advwin();
		    tcph->advwin() = maxpktsize;           
		}
	    }
	    else
	    {
	    	printf("Serious Error otherpq is not set, please fix this");
	        exit(1);
	    }
	return;

}

/*****************************************Ahmed*****************************************/
/*
 * Compute the average queue size.
 * Nqueued can be bytes or packets.
 */
double IQM::qavgupdate(int nqueued, double ave, double q_w) {
	double new_ave;

	new_ave = ave * (1.0 - q_w) + q_w * nqueued;

	return new_ave;
}

void IQM::Tq_timeout() {
	double inst_queue = byteLength();

	queue_bytes_ = running_min_queue_bytes_;

	oldavg = queue_avg_;

	queue_avg_ = qavgupdate(inst_queue, queue_avg_, queue_wieght_);

	running_min_queue_bytes_ = inst_queue;
	
	queue_timer_->resched(Tq_);
	if (TRACE && (queue_trace_file_ != 0)) {
		trace_var("Tq_", Tq_);
		trace_var("queue_bytes_", queue_bytes_);
	}
}

void IQM::Ts_timeout() {
        double now = Scheduler::instance().clock();
	double inst_queue = byteLength();	
	//oldavg = queue_avg_;
	//queue_avg_ = qavgupdate(inst_queue, queue_avg_, queue_wieght_);
	running_min_queue_bytes_ = inst_queue;
	qlimb_ = qlim_ * mean_pktsize_;
	
	if(!incast)
	{
		if(incastonly && syncount>0 && syncount * 10 * maxpktsize + queue_avg_  >= qlimb_)
		//if(incastonly && syncount>0 && syncount * maxpktsize + queue_avg_  >= qlimb_)
		{
			incast=true;
			incasttime=now;
		 	printf("%d number of syns caused incast at time %f %d %f\n", syncount,  now, maxpktsize, queue_avg_);
			syncount=0;
		}
		else if(!incastonly && syncount * maxpktsize + inst_queue  >= qlimb_)
		{
			incast=true;
			incasttime=now;
			syncount=0;
		 	printf("buffer overflow at time %f\n", now);
		}
	}
	if (flownum > 0) {
		//int seen = flownum;
		for (int i = 0; i < maxnum; i++)// && seen); i++)
		{	
			if (lastrecv[i] != -1 &&  now - lastrecv[i] >= 50*Ts_) 
			{	//totalenque -= flow[i];
				flow[i] = 0;
				lastrecv[i] = -1;
				flownum=max(0, flownum-1);
				syncount=max(0, syncount-1);
				//seen--;
				printf("flow %d stopped at time %f\n", i,now);
			}
	
		}
	}	
	syncount=0;

	// measure drops, if any
	trace_var("d", drops_);
	drops_ = 0;
	bdrops_ = 0;

	// sample the current queue size
	trace_var("q", length());

	syn_rate_timer_->resched(Ts_);
}

void IQM::drop(Packet* p) {
	drops_++;
	total_drops_++;
	Connector::drop(p);
}

void IQM::setEffectiveRtt(double rtt) {
	effective_rtt_ = rtt;

	rtt_timer_->resched(effective_rtt_);
}

// Estimation & Control Helpers

void IQM::init_vars() {
	qlimb_ = qlim_ * mean_pktsize_;
	link_capacity_bps_ = 0.0;
	//Tq_ = INITIAL_Te_VALUE;
	Tr_ = 0.1;

	queue_bytes_ = 0.0; // our estimate of the fluid model queue
	queue_avg_ = 0.0;
	old_queue_avg_ = 0.0;

	input_traffic_bytes_ = 0.0;
	output_traffic_bytes_ = 0.0;
	running_min_queue_bytes_ = 0;
	num_cc_packets_in_Te_ = totalinc = totaldec = 0;

	queue_trace_file_ = 0;

	min_queue_ci_ = max_queue_ci_ = length();

	// measuring drops
	drops_ = 0;
	total_drops_ = 0;
	bdrops_ = 0;

	// utilisation;
	total_thruput_ = 0.0;
	/***********************************Ahmed*****************************/
	bind("otherpq_", (TclObject**) &otherpq_);
	bind("flowupdateinterval_", &flowupdateinterval_);
	bind("queuefactor_", &queuefactor_);
	bind("maxnum_", &maxnum);
	bind("incastonly_", &incastonly);
	Te_  = flowupdateinterval_;
	incasttime=-1;
	flownum = 0;
	totalenque = 0;
	currentwnd = oldwnd = INF;
	overflow = false;
	avgpktsize  = maxpktsize = sswndincr = mean_pktsize_;
	wndincr = 0;
	divisor = 100;
	syncount=0;
	Tq_ = Te_ / divisor;
        Ts_ = flowupdateinterval_; //0.0005;
       incast = false;
	slowstart = true;
	limitexceed = false;
	flow = new int[maxnum];
	lastrecv = new double[maxnum];
	for (int i = 0; i < maxnum; i++) {
		flow[i] = 0;
		lastrecv[i] = -1;
	}
	currentfactor = queuefactor_;
	/**********************************************************************/
}

void IQMTimer::expire(Event *) {
	(*a_.*call_back_)();
}

void IQM::trace_var(char * var_name, double var) {
	char wrk[500];
	double now = Scheduler::instance().clock();

	if (queue_trace_file_) {
		int n;
		sprintf(wrk, "%s %g %g", var_name, now, var);
		n = strlen(wrk);
		wrk[n] = '\n';
		wrk[n + 1] = 0;
		(void) Tcl_Write(queue_trace_file_, wrk, n + 1);
	}
	return;
}

int IQM::command(int argc, const char* const * argv) {
	Tcl& tcl = Tcl::instance();

	if (argc == 2) {
		if (strcmp(argv[1], "queue-read-drops") == 0) {
			if (this) {
				tcl.resultf("%g", totalDrops());
				return (TCL_OK);
			} else {
				tcl.add_errorf("RWNDSYNQ queue is not set\n");
				return TCL_ERROR;
			}
		}

	}

	if (argc == 3) {

		if (strcmp(argv[1], "set-link-capacity") == 0) {
			double link_capacity_bitps = strtod(argv[2], 0);
			if (link_capacity_bitps < 0.0) {
				printf("Error: BW < 0");
				exit(1);
			}
			setBW(link_capacity_bitps / 8.0);
			return TCL_OK;
		} else if (strcmp(argv[1], "drop-target") == 0) {
			drop_ = (NsObject*) TclObject::lookup(argv[2]);
			if (drop_ == 0) {
				tcl.resultf("no object %s", argv[2]);
				return (TCL_ERROR);
			}
			setDropTarget(drop_);
			return (TCL_OK);
		}

		else if (strcmp(argv[1], "attach") == 0) {
			int mode;
			const char* id = argv[2];
			Tcl_Channel queue_trace_file = Tcl_GetChannel(tcl.interp(),
					(char*) id, &mode);
			if (queue_trace_file == 0) {
				tcl.resultf(
						"queue.cc: trace-drops: can't attach %s for writing",
						id);          
				return (TCL_ERROR);
			}
			setChannel(queue_trace_file);
			return (TCL_OK);
		}

		else if (strcmp(argv[1], "queue-sample-everyrtt") == 0) {
			double e_rtt = strtod(argv[2], 0);
			setEffectiveRtt(e_rtt);
			return (TCL_OK);
		}
    else if (!strcmp(argv[1], "packetqueue-attach")) {
			delete q_;
			if (!(q_ = (PacketQueue*) TclObject::lookup(argv[2])))
				return (TCL_ERROR);
			else {
				pq_ = q_;
				return (TCL_OK);
			}
		}
	}
	return (Queue::command(argc, argv));
}
