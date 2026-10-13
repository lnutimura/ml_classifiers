# ml_classifiers

**ml_classifiers** is a Snort 3 inspector that aggregates bidirectional flows and classifies them with the scikit-learn models trained for my master's thesis.

The models were trained on [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html). Each flow becomes the 78-column CICFlowMeter vector used in that dataset, including the duplicated forward-header-length column. A prediction of 0 is benign. Any other value raises Snort alert gid 45678, sid 1 (`ML classifier detected an attack`).

Trained classifiers:

* Gaussian Naive Bayes (`gnb`) and Bernoulli Naive Bayes (`bnb`)
* Linear support vector machine (`svc`)
* Decision tree (`dt`)
* Random forest (`rf`)
* AdaBoost (`ab`)

## Build

The inspector needs Snort 3 (pkg-config module `snort >= 3`), Python 3 development headers, and a C++17 compiler. At runtime the process also needs NumPy, scikit-learn, and joblib.

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Without Snort headers, CMake still builds and runs `test_flow_features`, which checks the feature vector. The shared inspector is built only when `snort.pc` is installed.

Install the module and its helper script with `cmake --install build`. They land in `<prefix>/lib/snort/inspectors/` and `<prefix>/lib/snort/inspectors/ml_py/`. Point Snort at the directory that contains `ml_classifiers.so`:

```bash
snort --plugin-path build -c snort.lua -r capture.pcap -A alert_fast
```

`ML_CLASSIFIERS_SCRIPT` or `ML_CLASSIFIERS_SCRIPT_DIR` overrides the location of `python/ml_classifiers.py` when it is not beside the plugin in `ml_py/`.

## Configuration

`model_dir` must contain `scaler.joblib` and the selected `clf_*.joblib`. This repository includes those files in `joblibs/`. They were saved with scikit-learn 0.20.3; the helper maps those pickles onto a current scikit-learn when it loads them. `idle_timeout` defaults to 120 seconds, which is the aggregation window from the thesis. Set the stream session timeouts to at least that value so Snort does not retire the flow early:

```lua
stream_tcp = { session_timeout = 120 }
stream_udp = { session_timeout = 120 }
stream_icmp = { session_timeout = 120 }

ml_classifiers =
{
    classifier = 'rf',
    model_dir = '/path/to/ml_classifiers/joblibs',
    idle_timeout = 120,
}
```

A copy of this fragment is in [lua/snort.lua](lua/snort.lua). The same helper can score a feature file outside Snort:

```bash
python3 python/ml_classifiers.py --model-dir joblibs --classifier rf --features-file rows.txt
```

Classification runs in-process. The Python GIL is held only while a model loads or a flow is scored. Flows are stored on Snort's `Flow` object. When a flow has been idle for `idle_timeout`, or when Snort retires it, the inspector logs the flow tuple and the verdict. Attacks are also queued on the packet being processed at that moment.

Peg counts `ml_classifiers.packets`, `flows`, `classified`, `benign`, and `attacks` are reported with Snort's inspector statistics.

## Thesis material

Training notebooks, dataset scripts, and the original timeout dumps are under `research/`. They are not part of the inspector build.

## License

Plugin sources are GPL version 2 only, which is the license required to link against Snort 3. The repository `LICENSE` file remains GPL version 3. Distributing the tree as one work mixes those two licenses.
