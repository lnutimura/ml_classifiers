//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------
// Per-flow state. Snort owns the object through FlowData and deletes it
// when the flow is retired.

#ifndef ML_CLASSIFIERS_CONNECTION_H
#define ML_CLASSIFIERS_CONNECTION_H

#include <cstdint>
#include <memory>
#include <string>

#include "flow/flow_data.h"
#include "flow_features.h"

namespace snort
{
struct Packet;
}

namespace mlc
{
class Classifier;

class ConnectionData : public snort::FlowData
{
public:
    static void init();
    static unsigned data_id()
    { return inspector_id; }

    static int64_t timestamp_usec(const snort::Packet*);
    static void expire_idle(int64_t now_usec);
    static void classify_open();

    ConnectionData(const snort::Packet*, std::shared_ptr<Classifier>, uint32_t idle_seconds);
    ~ConnectionData() override;

    void add(const snort::Packet*);
    void classify();

    bool is_classified() const
    { return done; }

private:
    static unsigned inspector_id;

    FlowFeatures features;
    std::shared_ptr<Classifier> classifier;
    std::string flow_name;
    int64_t idle_usec = 0;
    bool done = false;
};

} // namespace mlc

#endif
