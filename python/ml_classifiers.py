#!/usr/bin/env python3
"""Score CICFlowMeter feature vectors with the dissertation joblib models."""

import argparse
import os
import sys

TECHNIQUES = {
    "svc": "clf_svc.joblib",
    "ab": "clf_ab.joblib",
    "dt": "clf_dt.joblib",
    "rf": "clf_rf.joblib",
    "bnb": "clf_bnb.joblib",
    "gnb": "clf_gnb.joblib",
}

FEATURE_COUNT = 78


def load_models(model_dir, technique):
    """Return (scaler, classifier) loaded from model_dir.

    The dissertation joblibs were written by scikit-learn 0.20.3. Current
    scikit-learn renamed those modules and extended the tree node layout, so
    loading goes through a small compatibility unpickler.
    """
    if technique not in TECHNIQUES:
        raise ValueError("unknown classifier '%s'" % technique)

    scaler_path = os.path.join(model_dir, "scaler.joblib")
    model_path = os.path.join(model_dir, TECHNIQUES[technique])
    return _load_joblib(scaler_path), _load_joblib(model_path)


# Old pickle paths, and the classes that replaced them.
_CLASS_ALIASES = {
    ("sklearn.preprocessing.data", "MinMaxScaler"): ("sklearn.preprocessing._data", "MinMaxScaler"),
    ("sklearn.svm.classes", "LinearSVC"): ("sklearn.svm._classes", "LinearSVC"),
    ("sklearn.ensemble.weight_boosting", "AdaBoostClassifier"): (
        "sklearn.ensemble._weight_boosting",
        "AdaBoostClassifier",
    ),
    ("sklearn.ensemble.forest", "RandomForestClassifier"): (
        "sklearn.ensemble._forest",
        "RandomForestClassifier",
    ),
    ("sklearn.tree.tree", "DecisionTreeClassifier"): ("sklearn.tree._classes", "DecisionTreeClassifier"),
}


def _tree_compat():
    """Tree subclass that adds the node field introduced after scikit-learn 0.20."""
    import numpy as np
    from sklearn.tree._tree import Tree

    node_dtype = Tree(1, np.array([1], dtype=np.intp), 1).__getstate__()["nodes"].dtype

    class TreeCompat(Tree):
        def __setstate__(self, state):
            nodes = state["nodes"]
            names = nodes.dtype.names or ()
            if "missing_go_to_left" not in names:
                upgraded = np.zeros(nodes.shape, dtype=node_dtype)
                for name in names:
                    upgraded[name] = nodes[name]
                state = dict(state)
                state["nodes"] = upgraded
            return Tree.__setstate__(self, state)

    return TreeCompat


def _repair_estimator(obj, seen):
    import numpy as np

    if obj is None or isinstance(obj, (str, bytes, int, float, np.ndarray, np.generic)):
        return
    ident = id(obj)
    if ident in seen:
        return
    seen.add(ident)

    if isinstance(obj, (list, tuple)):
        for item in obj:
            _repair_estimator(item, seen)
        return

    module = getattr(type(obj), "__module__", "") or ""
    if not module.startswith("sklearn"):
        return

    name = type(obj).__name__
    if name == "MinMaxScaler":
        if not hasattr(obj, "clip"):
            obj.clip = False
        if not hasattr(obj, "n_features_in_") and getattr(obj, "scale_", None) is not None:
            obj.n_features_in_ = int(np.shape(obj.scale_)[0])
    elif name == "DecisionTreeClassifier":
        if not hasattr(obj, "monotonic_cst"):
            obj.monotonic_cst = None
    elif name == "GaussianNB":
        if not hasattr(obj, "var_") and hasattr(obj, "sigma_"):
            obj.var_ = obj.sigma_
    elif name in ("RandomForestClassifier", "AdaBoostClassifier"):
        if not hasattr(obj, "estimator") and hasattr(obj, "base_estimator"):
            obj.estimator = obj.base_estimator
        if not hasattr(obj, "estimator_") and hasattr(obj, "base_estimator_"):
            obj.estimator_ = obj.base_estimator_

    data = getattr(obj, "__dict__", None)
    if isinstance(data, dict):
        for value in list(data.values()):
            _repair_estimator(value, seen)


def _load_joblib(path):
    from joblib.numpy_pickle import NumpyUnpickler

    tree_compat = _tree_compat()

    class CompatUnpickler(NumpyUnpickler):
        def find_class(self, module, name):
            if name == "Tree" and module.startswith("sklearn.tree"):
                return tree_compat
            module, name = _CLASS_ALIASES.get((module, name), (module, name))
            return super().find_class(module, name)

    with open(path, "rb") as handle:
        obj = CompatUnpickler(path, handle).load()
    _repair_estimator(obj, set())
    return obj


def predict_one(scaler, clf, features):
    """Scale one 78-column vector and return the model prediction as a float."""
    import numpy as np

    if len(features) != FEATURE_COUNT:
        raise ValueError("expected %d features, got %d" % (FEATURE_COUNT, len(features)))

    row = np.asarray(features, dtype=float).reshape(1, -1)
    adjusted = scaler.transform(row)
    return float(clf.predict(adjusted)[0])


def predict_file(scaler, clf, path):
    """Score each whitespace-separated feature row in path."""
    predictions = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            predictions.append(predict_one(scaler, clf, [float(value) for value in text.split()]))
    return predictions


def main(argv):
    parser = argparse.ArgumentParser(description="Classify CICFlowMeter feature rows.")
    parser.add_argument("--model-dir", required=True, help="directory containing scaler.joblib and clf_*.joblib")
    parser.add_argument("--classifier", required=True, choices=sorted(TECHNIQUES), help="trained model to load")
    parser.add_argument("--features-file", required=True, help="whitespace-separated feature rows, one flow per line")
    args = parser.parse_args(argv)

    scaler, clf = load_models(args.model_dir, args.classifier)
    for prediction in predict_file(scaler, clf, args.features_file):
        print(prediction)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
