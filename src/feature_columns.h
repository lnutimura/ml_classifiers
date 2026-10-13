//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------
// MachineLearningCVE / CICIDS2017 feature columns. Column 56 repeats Fwd
// Header Length because that duplicate is present in the training CSV.
// This header is not named features.h: that name shadows glibc's features.h
// when the source directory is on the include path.

#ifndef ML_CLASSIFIERS_FEATURE_COLUMNS_H
#define ML_CLASSIFIERS_FEATURE_COLUMNS_H

namespace mlc
{

enum Feature : int
{
    DESTINATION_PORT = 0,
    FLOW_DURATION,
    TOTAL_FWD_PACKETS,
    TOTAL_BWD_PACKETS,
    FWD_PACKET_LENGTH_TOTAL,
    BWD_PACKET_LENGTH_TOTAL,
    FWD_PACKET_LENGTH_MAX,
    FWD_PACKET_LENGTH_MIN,
    FWD_PACKET_LENGTH_MEAN,
    FWD_PACKET_LENGTH_STD,
    BWD_PACKET_LENGTH_MAX,
    BWD_PACKET_LENGTH_MIN,
    BWD_PACKET_LENGTH_MEAN,
    BWD_PACKET_LENGTH_STD,
    FLOW_BYTES_PER_SEC,
    FLOW_PACKETS_PER_SEC,
    FLOW_IAT_MEAN,
    FLOW_IAT_STD,
    FLOW_IAT_MAX,
    FLOW_IAT_MIN,
    FWD_IAT_TOTAL,
    FWD_IAT_MEAN,
    FWD_IAT_STD,
    FWD_IAT_MAX,
    FWD_IAT_MIN,
    BWD_IAT_TOTAL,
    BWD_IAT_MEAN,
    BWD_IAT_STD,
    BWD_IAT_MAX,
    BWD_IAT_MIN,
    FWD_PSH_FLAGS,
    BWD_PSH_FLAGS,
    FWD_URG_FLAGS,
    BWD_URG_FLAGS,
    FWD_HEADER_LENGTH,
    BWD_HEADER_LENGTH,
    FWD_PACKETS_PER_SEC,
    BWD_PACKETS_PER_SEC,
    PACKET_LENGTH_MIN,
    PACKET_LENGTH_MAX,
    PACKET_LENGTH_MEAN,
    PACKET_LENGTH_STD,
    PACKET_LENGTH_VARIANCE,
    FIN_FLAG_COUNT,
    SYN_FLAG_COUNT,
    RST_FLAG_COUNT,
    PSH_FLAG_COUNT,
    ACK_FLAG_COUNT,
    URG_FLAG_COUNT,
    CWE_FLAG_COUNT,
    ECE_FLAG_COUNT,
    DOWN_UP_RATIO,
    AVERAGE_PACKET_SIZE,
    AVG_FWD_SEGMENT_SIZE,
    AVG_BWD_SEGMENT_SIZE,
    FWD_HEADER_LENGTH_DUP,
    FWD_AVG_BYTES_PER_BULK,
    FWD_AVG_PACKETS_PER_BULK,
    FWD_AVG_BULK_RATE,
    BWD_AVG_BYTES_PER_BULK,
    BWD_AVG_PACKETS_PER_BULK,
    BWD_AVG_BULK_RATE,
    SUBFLOW_FWD_PACKETS,
    SUBFLOW_FWD_BYTES,
    SUBFLOW_BWD_PACKETS,
    SUBFLOW_BWD_BYTES,
    INIT_WIN_BYTES_FORWARD,
    INIT_WIN_BYTES_BACKWARD,
    ACT_DATA_PKT_FORWARD,
    MIN_SEG_SIZE_FORWARD,
    ACTIVE_MEAN,
    ACTIVE_STD,
    ACTIVE_MAX,
    ACTIVE_MIN,
    IDLE_MEAN,
    IDLE_STD,
    IDLE_MAX,
    IDLE_MIN,
    FEATURE_COUNT
};

static_assert(BWD_URG_FLAGS == 33, "Bwd URG Flags is CSV column 34");
static_assert(FWD_HEADER_LENGTH_DUP == 55, "duplicate Fwd Header Length is CSV column 56");
static_assert(IDLE_MIN == 77, "last CICIDS2017 feature");
static_assert(FEATURE_COUNT == 78, "CICIDS2017 feature width");

} // namespace mlc

#endif
