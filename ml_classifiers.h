#include <boost/python.hpp>

#include <map>
#include <mutex>
#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <sys/time.h>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/sum.hpp>
#include <boost/accumulators/statistics/min.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/count.hpp>
#include <boost/accumulators/statistics/variance.hpp>

#include "protocols/packet.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"

/* For convenience. */
namespace bp = boost::python;

using namespace snort;
using namespace boost::accumulators;

typedef accumulator_set< int64_t, features<tag::count, tag::sum, tag::min, tag::max, tag::mean, tag::variance > > intAcc;
typedef accumulator_set< double, features<tag::count, tag::sum, tag::min, tag::max, tag::mean, tag::variance > > doubleAcc;

class Connection;

/* Mutex. */
std::mutex ml_mutex;

/* Selected Machine Learning Technique. */
std::string ml_technique;

/* Map of current active connections.*/
std::map<std::string, Connection> connections;
std::map<std::string, Connection>::iterator connections_it;

/*
    Struct of timeouted connections.
    Contains their id and features.
*/

struct TimeoutedConnections {
    std::vector<std::string> id;
    std::vector<Connection> connections;
    std::vector<std::vector<double>> features;
};

TimeoutedConnections t_connections;

/* Auxiliary functions prototypes. */
int64_t get_time_in_microseconds();
int64_t get_time_in_microseconds(time_t tvsec, suseconds_t tvusec);

std::vector<std::string> get_id_candidates(Packet* p);

void classify_connections();
void check_connections(Packet* p);
void verify_timeouts();

/* This class' features are based on the CICFlowMeter's features. */
class Connection {
    public:
        /*
            Basic constructor:
            Initializes most of this class' parameters.
        */
            Connection (Packet* p, std::string id) {
            std::cout << "[+] " << id << std::endl;

            /* Initializes the flags_counter and other parameters. */
            init_flags();
            init_parameters();

            update_flow_bulk(p);
            update_subflows(p);

            /* Updates the flags_counter based on the packet's flags (TCP-only). */
            if (p->is_tcp()) {
                update_flags_counter(p);
            }

            flow_id = id;
            protocol = (uint8_t)p->ip_proto_next;

            /* The packet's timestamp in microseconds. */
            //uint32_t packet_timestamp = p->pkth->ts.tv_usec;
            int64_t packet_timestamp = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);
            
            flow_first_seen = flow_last_seen =
                start_active_time = end_active_time = packet_timestamp;

            flow_length((double)p->dsize);

            p->flow->client_ip.ntop(client_ip);
            client_port = p->flow->client_port;

            p->flow->server_ip.ntop(server_ip);
            server_port = p->flow->server_port;

            /* Instead of comparing client_ip w/ packet_source,
               I'll use "p->is_from_client()".
             
                SfIpString packet_source;
                *(p->ptrs.ip_api.get_src())->ntop(packet_source);
            */
            
            /* Checks whether this packet is coming from the client or the server. */
            if (p->is_from_client()) {
                /* Coming from client (forward direction). */
                min_seg_size_forward = p->pkth->pktlen - p->dsize;

                if (p->is_tcp()) {
                    init_win_bytes_forward = p->ptrs.tcph->win();

                    if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
                        forward_PSH += 1;
                    }

                    if (p->ptrs.tcph->are_flags_set(TH_URG)) {
                        forward_URG += 1;
                    }
                }

                /*
                    Note: In CICFlowMeter's code, the authors
                    update the flow_length one more time.
                    (Does that makes any sense?)
                    flow_length((double)p->dsize);
                */
                forward_pkt((double)p->dsize);
                forward_bytes += p->dsize;
                forward_hbytes += p->pkth->pktlen - p->dsize;

                forward_last_seen = packet_timestamp;
                forward_count += 1;

            } else {
                /* Coming from server (backward direction). */
                if (p->is_tcp()) {
                    init_win_bytes_backward = p->ptrs.tcph->win();

                    if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
                        backward_PSH += 1;
                    }

                    if (p->ptrs.tcph->are_flags_set(TH_URG)) {
                        backward_URG += 1;
                    }
                }

                /*
                    Note: In CICFlowMeter's code, the authors
                    update the flow_length one more time.
                    (Does that makes any sense?)
                    flow_length((double)p->dsize);
                */
                backward_pkt((double)p->dsize);
                backward_bytes += p->dsize;
                backward_hbytes += p->pkth->pktlen - p->dsize;

                backward_last_seen = packet_timestamp;
                backward_count += 1;
            }
        }

        /* Method used to update a connection based on the packet's information. */
        void add_packet(Packet* p) {
            //uint32_t packet_timestamp = p->pkth->ts.tv_usec;
            int64_t packet_timestamp = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);
            
            /*
            For some reason, the CICFlowMeter's authors kept these
            three lines commented for a long time.
            */
            update_flow_bulk(p);
            update_subflows(p);
            
            if (p->is_tcp()) {
                update_flags_counter(p);
            }
            
            
            flow_length((double)p->dsize);

            /*
                SfIpString packet_source;
                *(p->ptrs.ip_api.get_src())->ntop(packet_source);
            */

            if (p->is_from_client()) {
                if (p->dsize >= 1.0f) {
                    act_data_pkt_forward += 1;
                }

                if (p->is_tcp()) {
                    if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
                        backward_PSH += 1;
                    }

                    if (p->ptrs.tcph->are_flags_set(TH_URG)) {
                        backward_URG += 1;
                    }
                }

                forward_pkt((double)p->dsize);
                forward_bytes += p->dsize;
                forward_hbytes += p->pkth->pktlen - p->dsize;

                forward_count += 1;

                if (forward_count > 1) {
                    forward_iat(packet_timestamp - forward_last_seen);
                }
                
                forward_last_seen = packet_timestamp;
                min_seg_size_forward = std::min((p->pkth->pktlen - p->dsize), min_seg_size_forward);
        
            } else {
                if (p->is_tcp()) {
                    init_win_bytes_backward = p->ptrs.tcph->win();

                    if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
                        backward_PSH += 1;
                    }

                    if (p->ptrs.tcph->are_flags_set(TH_URG)) {
                        backward_URG += 1;
                    }
                }

                backward_pkt((double)p->dsize);
                backward_bytes += p->dsize;
                backward_hbytes += p->pkth->pktlen - p->dsize;

                backward_count += 1;

                if (backward_count > 1) {
                    backward_iat(packet_timestamp - backward_last_seen);
                }
                
                backward_last_seen = packet_timestamp;
            }

            flow_iat(packet_timestamp - flow_last_seen);
            flow_last_seen = packet_timestamp;
        }

        /* Method used to initialize the flags counter. */
        void init_flags() {
            flags_counter["FIN"] = 0;
            flags_counter["SYN"] = 0;
            flags_counter["RST"] = 0;
            flags_counter["PSH"] = 0;
            flags_counter["ACK"] = 0;
            flags_counter["URG"] = 0;
            flags_counter["CWR"] = 0;
            flags_counter["ECE"] = 0;
        }

        /* Method used to initialize most of this class' variables/parameters. */
        void init_parameters() {
            forward_count = 0;
            backward_count = 0;

            flow_first_seen = 0;
            flow_last_seen = 0;

            forward_last_seen = 0;
            backward_last_seen = 0;

            forward_PSH = 0;
            forward_URG = 0;
            backward_PSH = 0;
            backward_URG = 0;

            forward_bytes = 0;
            forward_hbytes = 0;
            backward_bytes = 0;
            backward_hbytes = 0;

            start_active_time = 0;
            end_active_time = 0;

            act_data_pkt_forward = 0;
            min_seg_size_forward = 0;

            init_win_bytes_forward = 0;
            init_win_bytes_backward = 0;
       }

        /* Method used to update the flags_counter (TCP-only). */
        void update_flags_counter(Packet* p) {
            const tcp::TCPHdr* tcpHeader = p->ptrs.tcph;

            if (tcpHeader->are_flags_set(TH_FIN)) {
                flags_counter["FIN"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_SYN)) {
                flags_counter["SYN"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_RST)) {
                flags_counter["RST"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_PUSH)) {
                flags_counter["PSH"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_ACK)) {
                flags_counter["ACK"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_URG)) {
                flags_counter["URG"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_CWR)) {
                flags_counter["CWR"] += 1;
            }
            if (tcpHeader->are_flags_set(TH_ECE)) {
                flags_counter["ECE"] += 1;
            }
        }

        /* Method used to update the bulk flow in the forward direction. */
        void update_forward_bulk(Packet* p, int64_t op_bulk_last_timestamp) {
            uint32_t size = p->dsize;
            //uint32_t packet_timestamp = p->pkth->ts.tv_usec;
            int64_t packet_timestamp = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);
            
            if (op_bulk_last_timestamp > f_bulk_start_helper) f_bulk_start_helper = 0;
            if (size <= 0) return;

            if (f_bulk_start_helper == 0) {
                f_bulk_size_helper = size;
                f_bulk_packet_count_helper = 1;
                f_bulk_start_helper = packet_timestamp;
                f_bulk_last_timestamp = packet_timestamp;
            } else {
                if (((packet_timestamp - f_bulk_last_timestamp) / (double)1000000) > 1) {
                    f_bulk_size_helper = size;
                    f_bulk_packet_count_helper = 1;
                    f_bulk_start_helper = packet_timestamp;
                    f_bulk_last_timestamp = packet_timestamp;
                } else {
                    f_bulk_size_helper += size;
                    f_bulk_packet_count_helper += 1;

                    if (f_bulk_packet_count_helper == 4) {
                        f_bulk_state_count += 1;
                        f_bulk_packet_count += f_bulk_packet_count_helper;
                        f_bulk_total_size += f_bulk_size_helper;
                        f_bulk_duration += packet_timestamp - f_bulk_start_helper;
                    } else if (f_bulk_packet_count_helper > 4) {
                        f_bulk_packet_count += 1;
                        f_bulk_total_size += size;
                        f_bulk_duration += packet_timestamp - f_bulk_last_timestamp;
                    }

                    f_bulk_last_timestamp = packet_timestamp;
                }
            }
        }

        /* Method used to update the bulk flow in the backward direction. */
        void update_backward_bulk(Packet* p, uint32_t op_bulk_last_timestamp) {
            uint32_t size = p->dsize;
            //uint32_t packet_timestamp = p->pkth->ts.tv_usec;
            int64_t packet_timestamp = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);
            
            if (op_bulk_last_timestamp > b_bulk_start_helper) b_bulk_start_helper = 0;
            if (size <= 0) return;

            if (b_bulk_start_helper == 0) {
                b_bulk_size_helper = size;
                b_bulk_packet_count_helper = 1;
                b_bulk_start_helper = packet_timestamp;
                b_bulk_last_timestamp = packet_timestamp;
            }
            else {
                if (((packet_timestamp - b_bulk_last_timestamp) / (double)1000000) > 1) {
                    b_bulk_size_helper = size;
                    b_bulk_packet_count_helper = 1;
                    b_bulk_start_helper = packet_timestamp;
                    b_bulk_last_timestamp = packet_timestamp;
                }
                else {
                    b_bulk_size_helper += size;
                    b_bulk_packet_count_helper += 1;

                    if (b_bulk_packet_count_helper == 4) {
                        b_bulk_state_count += 1;
                        b_bulk_packet_count += b_bulk_packet_count_helper;
                        b_bulk_total_size += b_bulk_size_helper;
                        b_bulk_duration += packet_timestamp - b_bulk_start_helper;
                    }
                    else if (b_bulk_packet_count_helper > 4) {
                        b_bulk_packet_count += 1;
                        b_bulk_total_size += size;
                        b_bulk_duration += packet_timestamp - b_bulk_last_timestamp;
                    }

                    b_bulk_last_timestamp = packet_timestamp;
                }
            }
        }

        /* Method used to update the bulk flow. */
        void update_flow_bulk(Packet* p) {
            /*
                SfIpString packet_source;
                *(p->ptrs.ip_api.get_src())->ntop(packet_source);
            */
            if (p->is_from_client()) {
                update_forward_bulk(p, b_bulk_last_timestamp);
            } else {
                update_backward_bulk(p, f_bulk_last_timestamp);
            }
        }

        /* Method used to update both active and idle time of the flow. */
        void update_active_idle_time(int64_t current_time, int64_t threshold) {
            if ((current_time - end_active_time) > threshold) {
                if ((end_active_time - start_active_time) > 0) {
                    flow_active(end_active_time - start_active_time);
                }

                flow_idle(current_time - end_active_time);
                start_active_time = current_time;
                end_active_time = current_time;
            } else {
                end_active_time = current_time;
            }
        }

        /* Method used to update subflows. */
        void update_subflows(Packet* p) {
            //uint32_t packet_timestamp = p->pkth->ts.tv_usec;
            int64_t packet_timestamp = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);
            
            if (sf_last_packet_timestamp == -1) {
                sf_last_packet_timestamp = packet_timestamp;
                sf_ac_helper = packet_timestamp;
            }

            if (((packet_timestamp - sf_last_packet_timestamp) / (double)1000000) > 1) {
                sf_count += 1;
                int64_t last_sf_duration = packet_timestamp - sf_ac_helper;
                update_active_idle_time(packet_timestamp - sf_last_packet_timestamp, 5000000);
                sf_ac_helper = packet_timestamp;
            }

            sf_last_packet_timestamp = packet_timestamp;
        }

        /* Features "getters". */
        std::string get_flowid() {
            return flow_id;
        }
        
        int64_t get_flowfirstseen() {
            return flow_first_seen;
        }

        int64_t get_flowlastseen() {
            return flow_last_seen;
        }

        double get_flowbytespersec() {
            int64_t duration = flow_last_seen - flow_first_seen;

            if (duration > 0) {
                return ((double)(forward_bytes + backward_bytes)) / ((double)duration/1000000);
            } else {
                return 0;
            }
        }

        double get_flowpktspersec() {
            int64_t duration = flow_last_seen - flow_first_seen;
            uint32_t packet_count = forward_count + backward_count;

            if (duration > 0) {
                return ((double)packet_count) / ((double)duration/1000000);
            } else {
                return 0;
            }
        }

        double get_fpktspersec() {
            int64_t duration = flow_last_seen - flow_first_seen;

            if (duration > 0) {
                return ((double)forward_count) / ((double)duration/1000000);
            } else {
                return 0;
            }
        }

        double get_bpktspersec() {
            int64_t duration = flow_last_seen - flow_first_seen;

            if (duration > 0) {
                return ((double)backward_count) / ((double)duration/1000000);
            }
            else {
                return 0;
            }
        }

        double get_downupratio() {
            if (forward_count > 0) {
                return ((double)backward_count / (double)forward_count);
            } else {
                return 0;
            }
        }

        double get_avgpktsize() {
            uint32_t packet_count = forward_count + backward_count;
            if (packet_count > 0) {
                return (sum(flow_length) / (double)packet_count);
            } else {
                return 0;
            }
        }

        double get_favgsegmentsize() {
            if (forward_count > 0) {
                return (sum(forward_pkt) / (double)forward_count);
            } else {
                return 0;
            }
        }

        double get_bavgsegmentsize() {
            if (backward_count > 0) {
                return (sum(backward_pkt) / (double)backward_count);
            } else {
                return 0;
            }
        }

        double get_fsubflowbytes() {
            if (sf_count > 0) {
                return ((double)forward_bytes / (double)sf_count);
            } else {
                return 0;
            }
        }

        double get_fsubflowpkts() {
            if (sf_count > 0) {
                return ((double)forward_count / (double)sf_count);
            } else {
                return 0;
            }
        }

        double get_bsubflowbytes() {
            if (sf_count > 0) {
                return ((double)backward_bytes / (double)sf_count);
            } else {
                return 0;
            }
        }

        double get_bsubflowpkts() {
            if (sf_count > 0) {
                return ((double)backward_count / (double)sf_count);
            } else {
                return 0;
            }
        }

        uint32_t get_fbulkstatecount() {
            return f_bulk_state_count;
        }

        uint32_t get_fbulktotalsize() {
            return f_bulk_total_size;
        }

        uint32_t get_fbulkpktcount() {
            return f_bulk_packet_count;
        }

        int64_t get_fbulkduration() {
            return f_bulk_duration;
        }

        double get_fbulkduration_seconds() {
            return f_bulk_duration / (double)1000000;
        }
        
        uint32_t get_favgbytesperbulk() {
            if (get_fbulkstatecount() != 0) {
                return (get_fbulktotalsize() / get_fbulkstatecount());
            } else {
                return 0;
            }
        }

        uint32_t get_favgpktsperbulk() {
            if (get_fbulkstatecount() != 0) {
                return (get_fbulkpktcount() / get_fbulkstatecount());
            } else {
                return 0;
            }
        }

        uint32_t get_favgbulkrate() {
            if (get_fbulkduration() != 0) {
                return (uint32_t)(get_fbulktotalsize() / get_fbulkduration_seconds());
            } else {
                return 0;
            }
        }

        uint32_t get_bbulkstatecount() {
            return b_bulk_state_count;
        }

        uint32_t get_bbulktotalsize() {
            return b_bulk_total_size;
        }

        uint32_t get_bbulkpktcount() {
            return b_bulk_packet_count;
        }

        int64_t get_bbulkduration() {
            return b_bulk_duration;
        }

        double get_bbulkduration_seconds() {
            return b_bulk_duration / (double)1000000;
        }
        
        uint32_t get_bavgbytesperbulk() {
            if (get_bbulkstatecount() != 0) {
                return (get_bbulktotalsize() / get_bbulkstatecount());
            } else {
                return 0;
            }
        }

        uint32_t get_bavgpktsperbulk() {
            if (get_bbulkstatecount() != 0) {
                return (get_bbulkpktcount() / get_bbulkstatecount());
            } else {
                return 0;
            }
        }

        uint32_t get_bavgbulkrate() {
            if (get_bbulkduration() != 0) {
                return (uint32_t)(get_bbulktotalsize() / get_bbulkduration_seconds());
            } else {
                return 0;
            }
        }

        /* Method used to print the feature vector. */
        void print_feature_vector(std::vector<double> feature_vector) {
            std::cout << "[";
            for (int i = 0; i < feature_vector.size(); i++) {
                std::cout << "(" << (i + 1) << "): " << feature_vector[i];

                if (i < (feature_vector.size() - 1)) {
                    std::cout << " ";
                }
            }
            std::cout << "]" << std::endl;
        }

        /* Method used to get the feature vector. */
        std::vector<double> get_feature_vector() {
            std::vector<double> feature_vector;

            /*
                MachineLearningCVE - Features
                Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,
                Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,
                Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,Flow Bytes/s, Flow Packets/s,
                Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,
                Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags,
                Fwd Header Length, Bwd Header Length,Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean,
                Packet Length Std, Packet Length Variance,FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count,
                URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size,
                Fwd Header Length,Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,
                Bwd Avg Bulk Rate,Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,Init_Win_bytes_forward,
                Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,Active Mean, Active Std, Active Max, Active Min,Idle Mean,
                Idle Std, Idle Max, Idle Min, Label
            */

            int64_t duration = flow_last_seen - flow_first_seen;

            feature_vector.push_back(server_port);                      /* 1  */

            feature_vector.push_back(duration);                         /* 2  */

            feature_vector.push_back(count(forward_pkt));               /* 3  */
            feature_vector.push_back(count(backward_pkt));              /* 4  */
            feature_vector.push_back(sum(forward_pkt));                 /* 5  */
            feature_vector.push_back(sum(backward_pkt));                /* 6  */

            /* Forward Packet Length. */
            if (count(forward_pkt) > 0) {
                feature_vector.push_back((max)(forward_pkt));           /* 7  */
                feature_vector.push_back((min)(forward_pkt));           /* 8  */
                feature_vector.push_back(mean(forward_pkt));            /* 9  */
                feature_vector.push_back(sqrt(variance(forward_pkt)));  /* 10 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            /* Backward Packet Length. */
            if (count(backward_pkt) > 0) {
                feature_vector.push_back((max)(backward_pkt));          /* 11 */
                feature_vector.push_back((min)(backward_pkt));          /* 12 */
                feature_vector.push_back(mean(backward_pkt));           /* 13 */
                feature_vector.push_back(sqrt(variance(backward_pkt))); /* 14 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            feature_vector.push_back(get_flowbytespersec());            /* 15 */
            feature_vector.push_back(get_flowpktspersec());             /* 16 */
            
            /* Flow IAT. */
            if (count(flow_iat) > 0) {
                feature_vector.push_back(mean(flow_iat));               /* 17 */
                feature_vector.push_back(sqrt(variance(flow_iat)));     /* 18 */
                feature_vector.push_back((max)(flow_iat));              /* 19 */
                feature_vector.push_back((min)(flow_iat));              /* 20 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            /* Forward IAT. */
            if (forward_count > 1) {
                feature_vector.push_back(sum(forward_iat));             /* 21 */
                feature_vector.push_back(mean(forward_iat));            /* 22 */
                feature_vector.push_back(sqrt(variance(forward_iat)));  /* 23 */
                feature_vector.push_back((max)(forward_iat));           /* 24 */
                feature_vector.push_back((min)(forward_iat));           /* 25 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            /* Backward IAT. */
            if (backward_count > 1) {
                feature_vector.push_back(sum(backward_iat));            /* 26 */
                feature_vector.push_back(mean(backward_iat));           /* 27 */
                feature_vector.push_back(sqrt(variance(backward_iat))); /* 28 */
                feature_vector.push_back((max)(backward_iat));          /* 29 */
                feature_vector.push_back((min)(backward_iat));          /* 30 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            feature_vector.push_back(forward_PSH);                      /* 31 */
            feature_vector.push_back(backward_PSH);                     /* 32 */
            feature_vector.push_back(forward_URG);                      /* 33 */
            feature_vector.push_back(backward_PSH);                     /* 34 */

            feature_vector.push_back(forward_hbytes);                   /* 35 */
            feature_vector.push_back(backward_hbytes);                  /* 36 */
            feature_vector.push_back(get_fpktspersec());                /* 37 */
            feature_vector.push_back(get_bpktspersec());                /* 38 */

            /* Flow Length. */
            if (count(flow_length) > 0) {
                feature_vector.push_back((min)(flow_length));           /* 39 */
                feature_vector.push_back((max)(flow_length));           /* 40 */
                feature_vector.push_back(mean(flow_length));            /* 41 */
                feature_vector.push_back(sqrt(variance(flow_length)));  /* 42 */
                feature_vector.push_back(variance(flow_length));        /* 43 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            feature_vector.push_back(flags_counter["FIN"]);             /* 44 */
            feature_vector.push_back(flags_counter["SYN"]);             /* 45 */
            feature_vector.push_back(flags_counter["RST"]);             /* 46 */
            feature_vector.push_back(flags_counter["PSH"]);             /* 47 */
            feature_vector.push_back(flags_counter["ACK"]);             /* 48 */
            feature_vector.push_back(flags_counter["URG"]);             /* 49 */
            feature_vector.push_back(flags_counter["CWR"]);             /* 50 */
            feature_vector.push_back(flags_counter["ECE"]);             /* 51 */

            feature_vector.push_back(get_downupratio());                /* 52 */
            feature_vector.push_back(get_avgpktsize());                 /* 53 */
            feature_vector.push_back(get_favgsegmentsize());            /* 54 */
            feature_vector.push_back(get_bavgsegmentsize());            /* 55 */

            feature_vector.push_back(forward_hbytes);                   /* 56
                                                                           This feature is duplicated (35). 
                                                                           I'm keeping it because the CICIDS2017's authors kept it in the CSV
                                                                           files used to train the machine learning techniques.
                                                                        */
            
            feature_vector.push_back(get_favgbytesperbulk());           /* 57 */
            feature_vector.push_back(get_favgpktsperbulk());            /* 58 */
            feature_vector.push_back(get_favgbulkrate());               /* 59 */
            feature_vector.push_back(get_bavgbytesperbulk());           /* 60 */
            feature_vector.push_back(get_bavgpktsperbulk());            /* 61 */
            feature_vector.push_back(get_bavgbulkrate());               /* 62 */

            feature_vector.push_back(get_fsubflowpkts());               /* 63 */
            feature_vector.push_back(get_fsubflowbytes());              /* 64 */
            feature_vector.push_back(get_bsubflowpkts());               /* 65 */
            feature_vector.push_back(get_bsubflowbytes());              /* 66 */

            feature_vector.push_back(init_win_bytes_forward);           /* 67 */
            feature_vector.push_back(init_win_bytes_backward);          /* 68 */
            feature_vector.push_back(act_data_pkt_forward);             /* 69 */
            feature_vector.push_back(min_seg_size_forward);             /* 70 */

            /* Flow Active. */
            if (count(flow_active) > 0) {
                feature_vector.push_back(mean(flow_active));            /* 71 */
                feature_vector.push_back(sqrt(variance(flow_active)));  /* 72 */
                feature_vector.push_back((max)(flow_active));           /* 73 */
                feature_vector.push_back((min)(flow_active));           /* 74 */
            } else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            /* Flow Idle. */
            if (count(flow_idle) > 0) {
                feature_vector.push_back(mean(flow_idle));              /* 75 */
                feature_vector.push_back(sqrt(variance(flow_idle)));    /* 76 */
                feature_vector.push_back((max)(flow_idle));             /* 77 */
                feature_vector.push_back((min)(flow_idle));             /* 78 */
            }
            else {
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
                feature_vector.push_back(0);
            }

            return feature_vector;
        }

    /* 
        These are meant to be private.
        They're currently public for debugging purpose.
    */
    private:
        /* Flow ID*/
        std::string flow_id;

        /* Client/Server IP Addresses */
        SfIpString client_ip;
        SfIpString server_ip;

        /* Client/Server Ports */
        uint16_t client_port;
        uint16_t server_port;

        /* Connection Protocol */
        uint8_t protocol;

        /* Count of packets sent in the forward/backward direction of the flow */
        uint32_t forward_count;
        uint32_t backward_count;

        /* First and last time this flow was seen */
        int64_t flow_first_seen;
        int64_t flow_last_seen;

        /* Last time the forward/backward direction of the flow was seen */
        int64_t forward_last_seen;
        int64_t backward_last_seen;

        /* Start/end of this flow active time */
        int64_t start_active_time;
        int64_t end_active_time;

        /* Flags counter (TCP) */
        std::map<std::string, uint32_t> flags_counter;

        /* PSH/URG flags counters for the forward/backward direction of the flow */
        uint32_t forward_PSH;
        uint32_t forward_URG;
        uint32_t backward_PSH;
        uint32_t backward_URG;

        /* Bytes and header bytes counters for the forward/backward direction of the flow */
        uint32_t forward_bytes;
        uint32_t forward_hbytes;
        uint32_t backward_bytes;
        uint32_t backward_hbytes;

        /* Count of packets with at least 1 byte of TCP data payload in the forward direction */
        uint32_t act_data_pkt_forward;

        /* Minimum segment size observed in the forward direction */
        uint32_t min_seg_size_forward;

        /* Total number of bytes sent in initial window in the forward direction */
        uint32_t init_win_bytes_forward;

        /* Total number of bytes sent in initial window in the backward direction */
        uint32_t init_win_bytes_backward;

        /*
            Accumulator sets for flow's statistics:
            - inter-arrival time of packets;
            - time a flow was idle before becoming active;
            - time a flow was active before becoming idle;
            - total bytes of payload (flow and forward/backward direction of the flow).
        */
        intAcc flow_iat;
        intAcc forward_iat;
        intAcc backward_iat;

        intAcc flow_idle;
        intAcc flow_active;

        doubleAcc flow_length;
        doubleAcc forward_pkt;
        doubleAcc backward_pkt;

    /*
        Bulk related variables/parameters.
    */
        /* Subflows */
        uint32_t sf_count = 0;
        int64_t sf_ac_helper = -1;              /* This is initialized as -1, so it has to be int32_t. */
        int64_t sf_last_packet_timestamp = -1;  /* This is initialized as -1, so it has to be int32_t. */

        /* Forward bulk flow. */
        int64_t f_bulk_duration = 0;
        uint32_t f_bulk_total_size = 0;

        uint32_t f_bulk_state_count = 0;
        uint32_t f_bulk_packet_count = 0;

        uint32_t f_bulk_size_helper = 0;
        int64_t f_bulk_start_helper = 0;
        uint32_t f_bulk_packet_count_helper = 0;

        int64_t f_bulk_last_timestamp = 0;

        /* Backward bulk flow. */
        int64_t b_bulk_duration = 0;
        uint32_t b_bulk_total_size = 0;

        uint32_t b_bulk_state_count = 0;
        uint32_t b_bulk_packet_count = 0;

        uint32_t b_bulk_size_helper = 0;
        int64_t b_bulk_start_helper = 0;
        uint32_t b_bulk_packet_count_helper = 0;

        int64_t b_bulk_last_timestamp = 0;
};

/*
    Auxiliary function used to retrieve the current time in microseconds.
*/
int64_t get_time_in_microseconds() {
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);
    return timestamp.tv_sec * (int)1e6 + timestamp.tv_usec;
}

int64_t get_time_in_microseconds(time_t tvsec, suseconds_t tvusec) {
    return tvsec * (int)1e6 + tvusec;
}

/* 
    Auxiliary function used to retrieve possible strings for the flow id:
        - id_candidates[0]: flow_id;
        - id_candidates[1]: reversed flow_id.
*/
std::vector<std::string> get_id_candidates(Packet* p) {
    std::vector<std::string> id_candidates;

    std::ostringstream iss, reversed_iss;

    if (p->is_tcp()) {
        iss << "TCP"; reversed_iss << "TCP";
    } else if (p->is_udp()) {
        iss << "UDP"; reversed_iss << "UDP";
    } else if (p->is_icmp()) {
        iss << "ICMP"; reversed_iss << "ICMP";
    }

    SfIpString client_ip, server_ip;
    p->flow->client_ip.ntop(client_ip);
    p->flow->server_ip.ntop(server_ip);

    iss << "-" << client_ip << ":" << p->flow->client_port << "-" << server_ip << ":" << p->flow->server_port;
    reversed_iss << "-" << server_ip << ":" << p->flow->server_port << "-" << client_ip << ":" << p->flow->client_port;

    if (p->is_icmp()) {
        iss << "-" << p->ptrs.icmph->s_icmp_id;
        reversed_iss << "-" << p->ptrs.icmph->s_icmp_id;
    }

    id_candidates.push_back(iss.str());
    id_candidates.push_back(reversed_iss.str());

    return id_candidates;
}

/*
    Auxiliary function used to classify the timeouted connections.
*/
void classify_connections() {
    /* Creates a file containing the feature vector of each timeouted connection. */
    std::ofstream outputFile;
    outputFile.open("/home/lnutimura/Desktop/ml_classifiers/tmp/timeouted_connections.txt", std::ios_base::trunc);
    
    for (int i = 0; i < t_connections.id.size(); i++) {
        outputFile << std::fixed << std::setprecision(9);
        
        for (int j = 0; j < 78; j++) {
            outputFile << t_connections.features[i][j];
            
            if (j == 77)
                outputFile << std::scientific << "\n";
            else
                outputFile << " ";
        }
    }
    outputFile.close();
    
    /* Executes the script that classifies every single feature vector in the timeouted_connections.txt file. */
    std::string py_cmd = "python3 /home/lnutimura/Desktop/ml_classifiers/ml_classifiers.py " + ml_technique;
    system(py_cmd.c_str());
    
    /* Reads the predictions of every single connection timeouted previously. */
    std::ifstream inputFile ("/home/lnutimura/Desktop/ml_classifiers/tmp/timeouted_connections_results.txt");
    
    if (inputFile.is_open()) {
        std::string line;
        uint32_t index = 0;
        
        while (std::getline(inputFile, line)) {
            float predictedValue;
            
            std::cout << "[-] " << t_connections.id[index] << std::endl;
            t_connections.connections[index].print_feature_vector(t_connections.features[index]);
            std::cout << "\tResult: ";
            
            std::istringstream iss (line);
            iss >> predictedValue;
            
            if (predictedValue == 0.0f) {
                std::cout << "Normal (" << predictedValue << ")" << std::endl;
            } else {
                std::cout << "Attack (" << predictedValue << ")" << std::endl;
            }
            
            index++;
        }
        
        inputFile.close();
    }
    
    t_connections.id.clear();
    t_connections.connections.clear();
    t_connections.features.clear();
}

/*
    Auxiliary function used to check currently active connections 
    and handle timeouted connections.
*/
void check_connections(Packet* p) {
    ml_mutex.lock();
    std::map<std::string, Connection> active_connections = connections;
    ml_mutex.unlock();

    for (auto it = active_connections.begin(); it != active_connections.end(); it++) {
        int64_t time_difference;

        /* 
            If this function is called with a null argument (p == nullptr), it means
            that the caller is a thread checking for timeouts in the map of currently active connections.
            In this case, we must compare the current time (time(nullptr)) with the last time the target flow was seen.
            In the scenario where we're reading a .pcap, this function will always be called with an argument (the current packet being processed),
            hence we just need to compare the packet's time with the last time the target flow was seen.
        */
        if (p == nullptr) {
            //time_difference = time(nullptr) - it->second.flow_last_seen;
            //time_difference = time(nullptr) - it->second.get_flowlastseen();
            time_difference = get_time_in_microseconds() - it->second.get_flowlastseen();
        } else {
            //time_difference = p->pkth->ts.tv_sec - it->second.flow_last_seen;
            //time_difference = p->pkth->ts.tv_usec - it->second.get_flowlastseen();
            time_difference = get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec) - it->second.get_flowlastseen();
        }

        /* Assuming a default timeout value of 120 sec. */
        if (time_difference > 120000000) {
            ml_mutex.lock();
            
            /* Iterator pointing to the soon-to-be timeouted connection. */
            std::map<std::string, Connection>::iterator t_it = connections.find(it->first);


            if (t_it != connections.end()) {
                /* Retrieves all the flow's information and puts them in a vector. */
                std::vector<double> feature_vector = t_it->second.get_feature_vector();
                
                /* 
                    Transfer the timeouted connection to a struct responsible for 
                    holding it's informations.
                */
                t_connections.id.push_back(t_it->second.get_flowid());
                t_connections.features.push_back(feature_vector);
                t_connections.connections.push_back(t_it->second);
                
                connections.erase(t_it);
            }
            ml_mutex.unlock();
        }
    }
    
    /*
        If there are timeouted connections inside the t_connections struct,
        we have to classify them.
    */
    if (t_connections.id.size() > 0) {
        classify_connections();
    }
}

/*
    Thread's run function.
    Runs every 20 sec.
*/
void verify_timeouts() {
    while (true) {
        std::cout << "[+] verify_timeouts (" << connections.size() << ")" << std::endl;

        check_connections(nullptr);
        std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    }
}
