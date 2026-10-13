//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------

#include "connection.h"

#include <algorithm>
#include <exception>
#include <sstream>
#include <vector>

#include "classifier.h"
#include "counts.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "sfip/sf_ip.h"

using namespace snort;

namespace mlc
{
namespace
{

// Flows are processed by the packet thread that owns them, so this list
// does not need a process-wide mutex.
thread_local std::vector<ConnectionData*> open_connections;

void remember(ConnectionData* connection)
{
    open_connections.push_back(connection);
}

void forget(ConnectionData* connection)
{
    const auto found = std::find(open_connections.begin(), open_connections.end(), connection);
    if (found != open_connections.end())
        open_connections.erase(found);
}

std::string flow_tuple(const Packet* p)
{
    SfIpString client;
    SfIpString server;
    p->flow->client_ip.ntop(client);
    p->flow->server_ip.ntop(server);

    const char* proto = "IP";
    if (p->is_tcp())
        proto = "TCP";
    else if (p->is_udp())
        proto = "UDP";
    else if (p->is_icmp())
        proto = "ICMP";

    std::ostringstream out;
    out << proto << '-' << client << ':' << p->flow->client_port
        << '-' << server << ':' << p->flow->server_port;
    return out.str();
}

} // namespace

unsigned ConnectionData::inspector_id = 0;

void ConnectionData::init()
{
    if (inspector_id == 0)
        inspector_id = FlowData::create_flow_data_id();
}

int64_t ConnectionData::timestamp_usec(const Packet* p)
{
    return static_cast<int64_t>(p->pkth->ts.tv_sec) * 1000000LL
        + static_cast<int64_t>(p->pkth->ts.tv_usec);
}

void ConnectionData::expire_idle(int64_t now_usec)
{
    const std::vector<ConnectionData*> snapshot = open_connections;
    for (ConnectionData* connection : snapshot)
    {
        if (connection->done)
            continue;
        if ((now_usec - connection->features.last_seen()) > connection->idle_usec)
            connection->classify();
    }
}

void ConnectionData::classify_open()
{
    const std::vector<ConnectionData*> snapshot = open_connections;
    for (ConnectionData* connection : snapshot)
        connection->classify();
}

ConnectionData::ConnectionData(const Packet* p, std::shared_ptr<Classifier> model, uint32_t idle_seconds)
    : FlowData(inspector_id),
      features(p->flow->server_port),
      classifier(std::move(model)),
      flow_name(flow_tuple(p)),
      idle_usec(static_cast<int64_t>(idle_seconds) * 1000000LL)
{
    remember(this);
    count_flow();
}

ConnectionData::~ConnectionData()
{
    forget(this);
    if (!done)
        classify();
}

void ConnectionData::add(const Packet* p)
{
    if (done || !p->pkth)
        return;

    uint32_t header = 0;
    if (p->pktlen >= p->dsize)
        header = p->pktlen - p->dsize;

    uint8_t flags = 0;
    uint16_t window = 0;
    if (p->is_tcp() && p->ptrs.tcph)
    {
        flags = p->ptrs.tcph->th_flags;
        window = p->ptrs.tcph->win();
    }

    features.add(timestamp_usec(p), p->is_from_client(), p->dsize, header, flags, window);
}

void ConnectionData::classify()
{
    if (done)
        return;
    done = true;

    if (!classifier || features.packet_count() == 0)
        return;

    try
    {
        const auto values = features.vector();
        const double prediction = classifier->predict(values.data(), values.size());
        const bool attack = prediction != 0.0;

        LogMessage("ml_classifiers: %s %s (%g)\n",
            flow_name.c_str(), attack ? "attack" : "benign", prediction);

        count_classified();
        if (attack)
        {
            count_attack();
            if (DetectionEngine::get_current_packet())
                DetectionEngine::queue_event(GID, SID_ATTACK);
        }
        else
        {
            count_benign();
        }
    }
    catch (const std::exception& error)
    {
        LogMessage("ml_classifiers: %s classification failed: %s\n",
            flow_name.c_str(), error.what());
    }
}

} // namespace mlc
