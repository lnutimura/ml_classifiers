//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------

#include "flow_features.h"

#include <cmath>

namespace mlc
{
namespace
{
constexpr int64_t ACTIVITY_TIMEOUT_USEC = 5000000;
constexpr double GAP_SECONDS = 1.0;

enum FlagIndex
{
    FLAG_FIN = 0,
    FLAG_SYN,
    FLAG_RST,
    FLAG_PSH,
    FLAG_ACK,
    FLAG_URG,
    FLAG_CWR,
    FLAG_ECE
};

double seconds_between(int64_t delta_usec)
{
    return static_cast<double>(delta_usec) / 1000000.0;
}

} // namespace

void FlowFeatures::RunningStats::add(double value)
{
    if (n == 0)
    {
        min_v = value;
        max_v = value;
    }
    else
    {
        if (value < min_v)
            min_v = value;
        if (value > max_v)
            max_v = value;
    }

    ++n;
    sum += value;

    // Welford's algorithm. variance() divides by n - 1, matching Apache
    // Commons Math SummaryStatistics (the library CICFlowMeter uses).
    const double delta = value - average;
    average += delta / static_cast<double>(n);
    m2 += delta * (value - average);
}

double FlowFeatures::RunningStats::minimum() const
{
    return n ? min_v : 0;
}

double FlowFeatures::RunningStats::maximum() const
{
    return n ? max_v : 0;
}

double FlowFeatures::RunningStats::mean() const
{
    return n ? average : 0;
}

double FlowFeatures::RunningStats::variance() const
{
    // One sample has an undefined sample variance. Commons Math returns NaN,
    // which the training pipeline discarded. Keep the runtime vector finite.
    if (n < 2)
        return 0;
    return m2 / static_cast<double>(n - 1);
}

double FlowFeatures::RunningStats::stddev() const
{
    return std::sqrt(variance());
}

FlowFeatures::FlowFeatures(uint16_t port) : destination_port(port) { }

double FlowFeatures::per_second(double numerator, int64_t duration_usec)
{
    if (duration_usec <= 0)
        return 0;
    return numerator / seconds_between(duration_usec);
}

double FlowFeatures::bulk_average(int64_t total, int64_t count)
{
    if (count == 0)
        return 0;
    return static_cast<double>(total / count);
}

double FlowFeatures::bulk_rate(int64_t total_size, int64_t duration_usec)
{
    if (duration_usec == 0)
        return 0;
    const double rate = static_cast<double>(total_size) / seconds_between(duration_usec);
    return static_cast<double>(static_cast<int64_t>(rate));
}

void FlowFeatures::update_bulk(BulkState& bulk, int64_t timestamp, uint32_t payload, int64_t other_last)
{
    if (other_last > bulk.start)
        bulk.start = 0;
    if (payload == 0)
        return;

    if (bulk.start == 0)
    {
        bulk.start = timestamp;
        bulk.count_helper = 1;
        bulk.size_helper = payload;
        bulk.last = timestamp;
        return;
    }

    if (seconds_between(timestamp - bulk.last) > GAP_SECONDS)
    {
        bulk.start = timestamp;
        bulk.last = timestamp;
        bulk.count_helper = 1;
        bulk.size_helper = payload;
        return;
    }

    bulk.count_helper += 1;
    bulk.size_helper += payload;

    if (bulk.count_helper == 4)
    {
        bulk.state_count += 1;
        bulk.packet_count += bulk.count_helper;
        bulk.total_size += bulk.size_helper;
        bulk.duration += timestamp - bulk.start;
    }
    else if (bulk.count_helper > 4)
    {
        bulk.packet_count += 1;
        bulk.total_size += payload;
        bulk.duration += timestamp - bulk.last;
    }

    bulk.last = timestamp;
}

void FlowFeatures::update_active_idle(int64_t current, int64_t threshold)
{
    if ((current - end_active) > threshold)
    {
        if ((end_active - start_active) > 0)
            flow_active.add(static_cast<double>(end_active - start_active));
        flow_idle.add(static_cast<double>(current - end_active));
        start_active = current;
        end_active = current;
    }
    else
    {
        end_active = current;
    }
}

void FlowFeatures::update_subflows(int64_t timestamp)
{
    if (sf_last < 0)
    {
        sf_last = timestamp;
    }

    if (seconds_between(timestamp - sf_last) > GAP_SECONDS)
    {
        sf_count += 1;
        update_active_idle(timestamp, ACTIVITY_TIMEOUT_USEC);
    }

    sf_last = timestamp;
}

void FlowFeatures::update_flag_counts(uint8_t tcp_flags)
{
    if (tcp_flags & TCP_FIN)
        flag_counts[FLAG_FIN] += 1;
    if (tcp_flags & TCP_SYN)
        flag_counts[FLAG_SYN] += 1;
    if (tcp_flags & TCP_RST)
        flag_counts[FLAG_RST] += 1;
    if (tcp_flags & TCP_PSH)
        flag_counts[FLAG_PSH] += 1;
    if (tcp_flags & TCP_ACK)
        flag_counts[FLAG_ACK] += 1;
    if (tcp_flags & TCP_URG)
        flag_counts[FLAG_URG] += 1;
    if (tcp_flags & TCP_CWR)
        flag_counts[FLAG_CWR] += 1;
    if (tcp_flags & TCP_ECE)
        flag_counts[FLAG_ECE] += 1;
}

void FlowFeatures::add(int64_t timestamp_usec, bool from_client, uint32_t payload_len,
    uint32_t header_len, uint8_t tcp_flags, uint16_t tcp_window)
{
    const bool first = packet_count() == 0;

    if (from_client)
        update_bulk(forward_bulk, timestamp_usec, payload_len, backward_bulk.last);
    else
        update_bulk(backward_bulk, timestamp_usec, payload_len, forward_bulk.last);

    update_subflows(timestamp_usec);
    update_flag_counts(tcp_flags);

    if (first)
    {
        flow_first_seen = timestamp_usec;
        flow_last_seen = timestamp_usec;
        start_active = timestamp_usec;
        end_active = timestamp_usec;
        // CICFlowMeter::firstPacket adds the first payload to the flow-length
        // statistics here and again in the direction branch below.
        flow_length.add(static_cast<double>(payload_len));
    }
    else
    {
        flow_length.add(static_cast<double>(payload_len));
        flow_iat.add(static_cast<double>(timestamp_usec - flow_last_seen));
        flow_last_seen = timestamp_usec;
    }

    if (from_client)
    {
        if (first)
        {
            min_seg_forward = header_len;
            init_win_forward = tcp_window;
            flow_length.add(static_cast<double>(payload_len));
            forward_header = header_len;
            if (tcp_flags & TCP_PSH)
                forward_psh += 1;
            if (tcp_flags & TCP_URG)
                forward_urg += 1;
        }
        else
        {
            if (payload_len >= 1)
                act_data_forward += 1;
            forward_header += header_len;
            if (header_len < min_seg_forward)
                min_seg_forward = header_len;
        }

        forward_bytes += payload_len;
        forward_pkts.add(static_cast<double>(payload_len));
        forward_count += 1;
        if (!first && forward_count > 1)
            forward_iat.add(static_cast<double>(timestamp_usec - forward_last_seen));
        forward_last_seen = timestamp_usec;
    }
    else
    {
        if (first)
        {
            flow_length.add(static_cast<double>(payload_len));
            backward_header = header_len;
            if (tcp_flags & TCP_PSH)
                backward_psh += 1;
            if (tcp_flags & TCP_URG)
                backward_urg += 1;
        }
        else
        {
            backward_header += header_len;
        }

        // CICFlowMeter overwrites the backward initial window on every
        // backward packet, including the first one.
        init_win_backward = tcp_window;
        backward_bytes += payload_len;
        backward_pkts.add(static_cast<double>(payload_len));
        backward_count += 1;
        if (!first && backward_count > 1)
            backward_iat.add(static_cast<double>(timestamp_usec - backward_last_seen));
        backward_last_seen = timestamp_usec;
    }
}

std::array<double, FEATURE_COUNT> FlowFeatures::vector() const
{
    std::array<double, FEATURE_COUNT> out{};
    const int64_t duration = flow_last_seen - flow_first_seen;
    const uint32_t packets = packet_count();

    out[DESTINATION_PORT] = destination_port;
    out[FLOW_DURATION] = static_cast<double>(duration);
    out[TOTAL_FWD_PACKETS] = forward_count;
    out[TOTAL_BWD_PACKETS] = backward_count;
    out[FWD_PACKET_LENGTH_TOTAL] = forward_pkts.total();
    out[BWD_PACKET_LENGTH_TOTAL] = backward_pkts.total();

    out[FWD_PACKET_LENGTH_MAX] = forward_pkts.maximum();
    out[FWD_PACKET_LENGTH_MIN] = forward_pkts.minimum();
    out[FWD_PACKET_LENGTH_MEAN] = forward_pkts.mean();
    out[FWD_PACKET_LENGTH_STD] = forward_pkts.stddev();

    out[BWD_PACKET_LENGTH_MAX] = backward_pkts.maximum();
    out[BWD_PACKET_LENGTH_MIN] = backward_pkts.minimum();
    out[BWD_PACKET_LENGTH_MEAN] = backward_pkts.mean();
    out[BWD_PACKET_LENGTH_STD] = backward_pkts.stddev();

    out[FLOW_BYTES_PER_SEC] = per_second(static_cast<double>(forward_bytes + backward_bytes), duration);
    out[FLOW_PACKETS_PER_SEC] = per_second(static_cast<double>(packets), duration);

    out[FLOW_IAT_MEAN] = flow_iat.mean();
    out[FLOW_IAT_STD] = flow_iat.stddev();
    out[FLOW_IAT_MAX] = flow_iat.maximum();
    out[FLOW_IAT_MIN] = flow_iat.minimum();

    if (forward_count > 1)
    {
        out[FWD_IAT_TOTAL] = forward_iat.total();
        out[FWD_IAT_MEAN] = forward_iat.mean();
        out[FWD_IAT_STD] = forward_iat.stddev();
        out[FWD_IAT_MAX] = forward_iat.maximum();
        out[FWD_IAT_MIN] = forward_iat.minimum();
    }

    if (backward_count > 1)
    {
        out[BWD_IAT_TOTAL] = backward_iat.total();
        out[BWD_IAT_MEAN] = backward_iat.mean();
        out[BWD_IAT_STD] = backward_iat.stddev();
        out[BWD_IAT_MAX] = backward_iat.maximum();
        out[BWD_IAT_MIN] = backward_iat.minimum();
    }

    out[FWD_PSH_FLAGS] = forward_psh;
    out[BWD_PSH_FLAGS] = backward_psh;
    out[FWD_URG_FLAGS] = forward_urg;
    out[BWD_URG_FLAGS] = backward_urg;

    out[FWD_HEADER_LENGTH] = static_cast<double>(forward_header);
    out[BWD_HEADER_LENGTH] = static_cast<double>(backward_header);
    out[FWD_PACKETS_PER_SEC] = per_second(static_cast<double>(forward_count), duration);
    out[BWD_PACKETS_PER_SEC] = per_second(static_cast<double>(backward_count), duration);

    out[PACKET_LENGTH_MIN] = flow_length.minimum();
    out[PACKET_LENGTH_MAX] = flow_length.maximum();
    out[PACKET_LENGTH_MEAN] = flow_length.mean();
    out[PACKET_LENGTH_STD] = flow_length.stddev();
    out[PACKET_LENGTH_VARIANCE] = flow_length.variance();

    out[FIN_FLAG_COUNT] = flag_counts[FLAG_FIN];
    out[SYN_FLAG_COUNT] = flag_counts[FLAG_SYN];
    out[RST_FLAG_COUNT] = flag_counts[FLAG_RST];
    out[PSH_FLAG_COUNT] = flag_counts[FLAG_PSH];
    out[ACK_FLAG_COUNT] = flag_counts[FLAG_ACK];
    out[URG_FLAG_COUNT] = flag_counts[FLAG_URG];
    out[CWE_FLAG_COUNT] = flag_counts[FLAG_CWR];
    out[ECE_FLAG_COUNT] = flag_counts[FLAG_ECE];

    // Java performs the division in integer arithmetic, then widens it.
    if (forward_count > 0)
        out[DOWN_UP_RATIO] = static_cast<double>(backward_count / forward_count);

    if (packets > 0)
        out[AVERAGE_PACKET_SIZE] = flow_length.total() / static_cast<double>(packets);
    if (forward_count > 0)
        out[AVG_FWD_SEGMENT_SIZE] = forward_pkts.total() / static_cast<double>(forward_count);
    if (backward_count > 0)
        out[AVG_BWD_SEGMENT_SIZE] = backward_pkts.total() / static_cast<double>(backward_count);

    out[FWD_HEADER_LENGTH_DUP] = out[FWD_HEADER_LENGTH];

    out[FWD_AVG_BYTES_PER_BULK] = bulk_average(forward_bulk.total_size, forward_bulk.state_count);
    out[FWD_AVG_PACKETS_PER_BULK] = bulk_average(forward_bulk.packet_count, forward_bulk.state_count);
    out[FWD_AVG_BULK_RATE] = bulk_rate(forward_bulk.total_size, forward_bulk.duration);
    out[BWD_AVG_BYTES_PER_BULK] = bulk_average(backward_bulk.total_size, backward_bulk.state_count);
    out[BWD_AVG_PACKETS_PER_BULK] = bulk_average(backward_bulk.packet_count, backward_bulk.state_count);
    out[BWD_AVG_BULK_RATE] = bulk_rate(backward_bulk.total_size, backward_bulk.duration);

    if (sf_count > 0)
    {
        out[SUBFLOW_FWD_PACKETS] = static_cast<double>(forward_count / static_cast<uint32_t>(sf_count));
        out[SUBFLOW_FWD_BYTES] = static_cast<double>(forward_bytes / static_cast<uint64_t>(sf_count));
        out[SUBFLOW_BWD_PACKETS] = static_cast<double>(backward_count / static_cast<uint32_t>(sf_count));
        out[SUBFLOW_BWD_BYTES] = static_cast<double>(backward_bytes / static_cast<uint64_t>(sf_count));
    }

    out[INIT_WIN_BYTES_FORWARD] = init_win_forward;
    out[INIT_WIN_BYTES_BACKWARD] = init_win_backward;
    out[ACT_DATA_PKT_FORWARD] = act_data_forward;
    out[MIN_SEG_SIZE_FORWARD] = min_seg_forward;

    out[ACTIVE_MEAN] = flow_active.mean();
    out[ACTIVE_STD] = flow_active.stddev();
    out[ACTIVE_MAX] = flow_active.maximum();
    out[ACTIVE_MIN] = flow_active.minimum();

    out[IDLE_MEAN] = flow_idle.mean();
    out[IDLE_STD] = flow_idle.stddev();
    out[IDLE_MAX] = flow_idle.maximum();
    out[IDLE_MIN] = flow_idle.minimum();

    return out;
}

} // namespace mlc
