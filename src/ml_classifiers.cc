//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------
// ml_classifiers.cc author Luan Utimura <luan.utimura@gmail.com>

#include <exception>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

#include "classifier.h"
#include "connection.h"
#include "counts.h"

#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_types.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

using namespace snort;

static const char* s_name = "ml_classifiers";
static const char* s_help = "classify bidirectional flows with a trained model";

static const Parameter s_params[] =
{
    { "classifier", Parameter::PT_SELECT, "ab | dt | rf | svc | bnb | gnb", "ab",
      "trained classifier" },
    { "model_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory containing scaler.joblib and the selected clf_*.joblib" },
    { "idle_timeout", Parameter::PT_INT, "1:max32", "120",
      "seconds of inactivity before a flow is classified" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap s_rules[] =
{
    { mlc::SID_ATTACK, "ML classifier detected an attack" },
    { 0, nullptr }
};

static const PegInfo s_pegs[] =
{
    { CountType::SUM, "packets", "packets inspected" },
    { CountType::SUM, "flows", "flows created" },
    { CountType::SUM, "classified", "flows classified" },
    { CountType::SUM, "benign", "flows classified as benign" },
    { CountType::SUM, "attacks", "flows classified as attacks" },
    { CountType::END, nullptr, nullptr }
};

struct MLCounts
{
    PegCount packets;
    PegCount flows;
    PegCount classified;
    PegCount benign;
    PegCount attacks;
};

static thread_local MLCounts s_counts;
static thread_local ProfileStats s_perf_stats;

namespace mlc
{
void count_packet() { ++s_counts.packets; }
void count_flow() { ++s_counts.flows; }
void count_classified() { ++s_counts.classified; }
void count_benign() { ++s_counts.benign; }
void count_attack() { ++s_counts.attacks; }
}

struct MLConfig
{
    std::string classifier = "ab";
    std::string model_dir;
    uint32_t idle_timeout = 120;
};

class MLClassifiersModule : public Module
{
public:
    MLClassifiersModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return s_pegs; }

    PegCount* get_counts() const override
    { return reinterpret_cast<PegCount*>(&s_counts); }

    ProfileStats* get_profile() const override
    { return &s_perf_stats; }

    unsigned get_gid() const override
    { return mlc::GID; }

    const RuleMap* get_rules() const override
    { return s_rules; }

    // Probes run after detection on every packet, whichever inspection
    // policy is selected. Current Snort requires that to be global.
    Usage get_usage() const override
    { return GLOBAL; }

    const MLConfig& get_config() const
    { return config; }

private:
    MLConfig config;
};

bool MLClassifiersModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("classifier"))
        config.classifier = v.get_string();
    else if (v.is("model_dir"))
        config.model_dir = v.get_string();
    else if (v.is("idle_timeout"))
        config.idle_timeout = v.get_uint32();
    else
        return false;

    return true;
}

class MLClassifiers : public Inspector
{
public:
    explicit MLClassifiers(MLConfig);

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void tterm() override;
    void eval(Packet*) override;

private:
    MLConfig config;
    std::shared_ptr<mlc::Classifier> classifier;
};

MLClassifiers::MLClassifiers(MLConfig c) : config(std::move(c))
{
    mlc::ConnectionData::init();
}

bool MLClassifiers::configure(SnortConfig*)
{
    const std::string filename = mlc::Classifier::model_filename(config.classifier);
    if (filename.empty())
    {
        ParseError("ml_classifiers: unknown classifier '%s'", config.classifier.c_str());
        return false;
    }

    if (config.model_dir.empty())
    {
        ParseError("ml_classifiers: model_dir is required");
        return false;
    }

    const std::filesystem::path directory(config.model_dir);
    const std::filesystem::path scaler = directory / "scaler.joblib";
    const std::filesystem::path model = directory / filename;
    std::error_code error;
    if (!std::filesystem::is_regular_file(scaler, error) || !std::filesystem::is_regular_file(model, error))
    {
        ParseError("ml_classifiers: model_dir '%s' must contain scaler.joblib and %s",
            config.model_dir.c_str(), filename.c_str());
        return false;
    }

    try
    {
        classifier = std::make_shared<mlc::Classifier>(config.model_dir, config.classifier);
    }
    catch (const std::exception& error)
    {
        ParseError("ml_classifiers: %s", error.what());
        return false;
    }

    return true;
}

void MLClassifiers::show(const SnortConfig*) const
{
    ConfigLogger::log_value("classifier", config.classifier.c_str());
    ConfigLogger::log_value("model_dir", config.model_dir.c_str());
    ConfigLogger::log_value("idle_timeout", config.idle_timeout);
}

void MLClassifiers::tterm()
{
    mlc::ConnectionData::classify_open();
}

void MLClassifiers::eval(Packet* p)
{
    if (!p->flow || !p->pkth)
        return;

    // Stream reassembly delivers a second copy of the same payload.
    if (p->packet_flags & PKT_REBUILT_STREAM)
        return;

    if (!(p->is_tcp() || p->is_udp() || p->is_icmp()))
        return;

    if (!classifier || mlc::ConnectionData::data_id() == 0)
        return;

    mlc::count_packet();
    mlc::ConnectionData::expire_idle(mlc::ConnectionData::timestamp_usec(p));

    auto* connection = static_cast<mlc::ConnectionData*>(
        p->flow->get_flow_data(mlc::ConnectionData::data_id()));

    if (connection && connection->is_classified())
    {
        p->flow->free_flow_data(mlc::ConnectionData::data_id());
        connection = nullptr;
    }

    if (!connection)
    {
        connection = new mlc::ConnectionData(p, classifier, config.idle_timeout);
        p->flow->set_flow_data(connection);
    }

    connection->add(p);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MLClassifiersModule; }

static void mod_dtor(Module* module)
{ delete module; }

static void plugin_pinit()
{ mlc::ConnectionData::init(); }

static void plugin_tterm()
{ mlc::ConnectionData::classify_open(); }

static Inspector* ml_ctor(Module* module)
{
    auto* mod = static_cast<MLClassifiersModule*>(module);
    return new MLClassifiers(mod->get_config());
}

static void ml_dtor(Inspector* inspector)
{ delete inspector; }

static const InspectApi ml_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__ICMP,
    nullptr,
    nullptr,
    plugin_pinit,
    nullptr,
    nullptr,
    plugin_tterm,
    ml_ctor,
    ml_dtor,
    nullptr,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ml_api.base,
    nullptr
};
