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
#include <cstdlib>
#include <iostream>
#include <string>

namespace
{

int failures = 0;

void expect(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "FAIL " << message << '\n';
        ++failures;
    }
}

bool near(double actual, double expected)
{
    return std::fabs(actual - expected) <= 1e-6;
}

void test_directional_flags_and_double_count()
{
    mlc::FlowFeatures flow(80);
    const uint8_t first_flags = mlc::TCP_PSH | mlc::TCP_URG | mlc::TCP_CWR;
    const uint8_t later_flags = mlc::TCP_PSH | mlc::TCP_URG;

    flow.add(0, true, 10, 40, first_flags, 1000);
    flow.add(1000, true, 30, 20, later_flags, 1);

    const auto values = flow.vector();

    expect(values[mlc::DESTINATION_PORT] == 80, "destination port");
    expect(values[mlc::FLOW_DURATION] == 1000, "duration");
    expect(values[mlc::FWD_PSH_FLAGS] == 1, "forward PSH is counted on the first packet only");
    expect(values[mlc::FWD_URG_FLAGS] == 1, "forward URG is counted on the first packet only");
    expect(values[mlc::BWD_PSH_FLAGS] == 0, "backward PSH stays empty");
    expect(values[mlc::BWD_URG_FLAGS] == 0, "column 34 is backward URG, not backward PSH");
    expect(values[mlc::PSH_FLAG_COUNT] == 2, "PSH flag count includes every packet");
    expect(values[mlc::URG_FLAG_COUNT] == 2, "URG flag count includes every packet");
    expect(values[mlc::CWE_FLAG_COUNT] == 1, "CWE column counts the CWR bit");
    expect(values[mlc::ACT_DATA_PKT_FORWARD] == 1, "first forward payload is not act_data");
    expect(values[mlc::FWD_HEADER_LENGTH] == 60, "forward header bytes");
    expect(values[mlc::FWD_HEADER_LENGTH_DUP] == values[mlc::FWD_HEADER_LENGTH],
        "duplicate forward header length");
    expect(values[mlc::MIN_SEG_SIZE_FORWARD] == 20, "minimum forward header");
    expect(values[mlc::INIT_WIN_BYTES_FORWARD] == 1000, "forward initial window is the first packet");
    expect(near(values[mlc::AVERAGE_PACKET_SIZE], 25),
        "average packet size includes the duplicated first payload");
    expect(near(values[mlc::PACKET_LENGTH_MEAN], 50.0 / 3.0), "flow length mean");
    expect(values[mlc::PACKET_LENGTH_MIN] == 10, "flow length min");
    expect(values[mlc::PACKET_LENGTH_MAX] == 30, "flow length max");
    expect(near(values[mlc::FLOW_BYTES_PER_SEC], 40000), "flow bytes per second");
    expect(values[mlc::FWD_IAT_TOTAL] == 1000, "forward IAT total");
}

void test_backward_urgent_on_first_packet()
{
    mlc::FlowFeatures flow(443);
    flow.add(0, false, 0, 40, mlc::TCP_URG, 7);
    flow.add(10, false, 0, 40, mlc::TCP_PSH, 9);

    const auto values = flow.vector();
    expect(values[mlc::BWD_URG_FLAGS] == 1, "first backward packet sets Bwd URG Flags");
    expect(values[mlc::FWD_URG_FLAGS] == 0, "forward URG is untouched");
    expect(values[mlc::BWD_PSH_FLAGS] == 0, "later backward PSH does not set Bwd PSH Flags");
    expect(values[mlc::PSH_FLAG_COUNT] == 1, "later PSH still increments the flag count");
    expect(values[mlc::INIT_WIN_BYTES_BACKWARD] == 9, "backward window is taken from the latest packet");
}

void test_integer_down_up_ratio()
{
    mlc::FlowFeatures flow(80);
    flow.add(0, true, 1, 40, 0, 10);
    flow.add(1, true, 1, 40, 0, 10);
    for (int i = 0; i < 5; ++i)
        flow.add(10 + i, false, 1, 40, mlc::TCP_URG, 99);

    const auto values = flow.vector();
    expect(values[mlc::TOTAL_FWD_PACKETS] == 2, "forward packet count");
    expect(values[mlc::TOTAL_BWD_PACKETS] == 5, "backward packet count");
    expect(values[mlc::DOWN_UP_RATIO] == 2, "down/up ratio uses integer division");
    expect(values[mlc::BWD_URG_FLAGS] == 0, "URG after the first packet is not a directional flag");
    expect(values[mlc::INIT_WIN_BYTES_BACKWARD] == 99, "backward initial window tracks the last backward packet");
}

void test_active_idle_uses_packet_time()
{
    mlc::FlowFeatures flow(80);
    flow.add(0, true, 0, 0, 0, 0);
    flow.add(6000000, true, 0, 0, 0, 0);
    flow.add(13000000, true, 0, 0, 0, 0);

    const auto values = flow.vector();
    expect(near(values[mlc::IDLE_MEAN], 6500000), "idle mean");
    expect(near(values[mlc::IDLE_MIN], 6000000), "idle min");
    expect(near(values[mlc::IDLE_MAX], 7000000), "idle max");
}

} // namespace

int main()
{
    test_directional_flags_and_double_count();
    test_backward_urgent_on_first_packet();
    test_integer_down_up_ratio();
    test_active_idle_uses_packet_time();

    if (failures)
    {
        std::cerr << failures << " failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "flow feature tests passed\n";
    return EXIT_SUCCESS;
}
