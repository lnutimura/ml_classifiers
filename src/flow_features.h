//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------
// Bidirectional flow statistics matching CICFlowMeter BasicFlow. Packet
// fields are plain values so the math can be tested without Snort.

#ifndef ML_CLASSIFIERS_FLOW_FEATURES_H
#define ML_CLASSIFIERS_FLOW_FEATURES_H

#include <array>
#include <cstdint>

#include "feature_columns.h"

namespace mlc
{

// Same bit positions as the TCP header and Snort's TH_* flags.
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;
constexpr uint8_t TCP_ECE = 0x40;
constexpr uint8_t TCP_CWR = 0x80;

class FlowFeatures
{
public:
    explicit FlowFeatures(uint16_t destination_port);

    void add(int64_t timestamp_usec, bool from_client, uint32_t payload_len,
        uint32_t header_len, uint8_t tcp_flags, uint16_t tcp_window);

    std::array<double, FEATURE_COUNT> vector() const;

    int64_t last_seen() const
    { return flow_last_seen; }

    uint32_t packet_count() const
    { return forward_count + backward_count; }

private:
    struct RunningStats
    {
        void add(double value);
        uint64_t count() const
        { return n; }
        double total() const
        { return sum; }
        double minimum() const;
        double maximum() const;
        double mean() const;
        double variance() const;
        double stddev() const;

        uint64_t n = 0;
        double sum = 0;
        double average = 0;
        double m2 = 0;
        double min_v = 0;
        double max_v = 0;
    };

    struct BulkState
    {
        int64_t duration = 0;
        int64_t total_size = 0;
        int64_t state_count = 0;
        int64_t packet_count = 0;
        int64_t size_helper = 0;
        int64_t start = 0;
        int64_t count_helper = 0;
        int64_t last = 0;
    };

    void update_bulk(BulkState& bulk, int64_t timestamp, uint32_t payload, int64_t other_last);
    void update_subflows(int64_t timestamp);
    void update_active_idle(int64_t current, int64_t threshold);
    void update_flag_counts(uint8_t tcp_flags);

    static double per_second(double numerator, int64_t duration_usec);
    static double bulk_average(int64_t total, int64_t count);
    static double bulk_rate(int64_t total_size, int64_t duration_usec);

    uint16_t destination_port;

    uint32_t forward_count = 0;
    uint32_t backward_count = 0;
    uint64_t forward_bytes = 0;
    uint64_t backward_bytes = 0;
    uint64_t forward_header = 0;
    uint64_t backward_header = 0;

    int64_t flow_first_seen = 0;
    int64_t flow_last_seen = 0;
    int64_t forward_last_seen = 0;
    int64_t backward_last_seen = 0;
    int64_t start_active = 0;
    int64_t end_active = 0;

    uint32_t forward_psh = 0;
    uint32_t backward_psh = 0;
    uint32_t forward_urg = 0;
    uint32_t backward_urg = 0;
    uint32_t flag_counts[8] = {};

    uint32_t act_data_forward = 0;
    uint32_t min_seg_forward = 0;
    uint32_t init_win_forward = 0;
    uint32_t init_win_backward = 0;

    RunningStats flow_iat;
    RunningStats forward_iat;
    RunningStats backward_iat;
    RunningStats flow_active;
    RunningStats flow_idle;
    RunningStats flow_length;
    RunningStats forward_pkts;
    RunningStats backward_pkts;

    int64_t sf_last = -1;
    int sf_count = 0;

    BulkState forward_bulk;
    BulkState backward_bulk;
};

} // namespace mlc

#endif
