-- Plugin settings to merge into a Snort 3 Lua configuration.
-- The stream session timeouts match idle_timeout so Snort keeps the flow
-- until the classifier has seen the whole aggregation window.
--
-- snort --plugin-path <build-or-install-dir> -c snort.lua -r capture.pcap -A alert_fast

stream_tcp = { session_timeout = 120 }
stream_udp = { session_timeout = 120 }
stream_icmp = { session_timeout = 120 }

ml_classifiers =
{
    classifier = 'rf', -- ab | dt | rf | svc | bnb | gnb
    model_dir = '/path/to/ml_classifiers/joblibs',
    idle_timeout = 120,
}
