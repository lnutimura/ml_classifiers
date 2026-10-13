//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "classifier.h"

#include <dlfcn.h>

#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <stdexcept>

namespace mlc
{
namespace
{

PyThreadState* saved_thread = nullptr;

class GilLock
{
public:
    GilLock() : state(PyGILState_Ensure()) { }
    ~GilLock() { PyGILState_Release(state); }

    GilLock(const GilLock&) = delete;
    GilLock& operator=(const GilLock&) = delete;

private:
    PyGILState_STATE state;
};

void python_ensure()
{
    static std::once_flag once;
    std::call_once(once, [] {
        Py_Initialize();
        saved_thread = PyEval_SaveThread();
        if (!saved_thread)
            throw std::runtime_error("failed to release the Python GIL");
    });
}

std::string python_exception(const char* where)
{
    if (!PyErr_Occurred())
        return std::string(where);

    PyObject* type = nullptr;
    PyObject* value = nullptr;
    PyObject* trace = nullptr;
    PyErr_Fetch(&type, &value, &trace);
    PyErr_NormalizeException(&type, &value, &trace);

    std::string message = where;
    if (value)
    {
        PyObject* text = PyObject_Str(value);
        if (text)
        {
            if (const char* utf8 = PyUnicode_AsUTF8(text))
                message = std::string(where) + ": " + utf8;
            Py_DECREF(text);
        }
    }

    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(trace);
    return message;
}

[[noreturn]] void raise_python(const char* where)
{
    throw std::runtime_error(python_exception(where));
}

std::filesystem::path helper_script()
{
    namespace fs = std::filesystem;

    if (const char* from_env = std::getenv("ML_CLASSIFIERS_SCRIPT"))
    {
        if (*from_env)
            return fs::path(from_env);
    }

    if (const char* dir = std::getenv("ML_CLASSIFIERS_SCRIPT_DIR"))
    {
        if (*dir)
        {
            fs::path candidate = fs::path(dir) / "ml_classifiers.py";
            if (fs::is_regular_file(candidate))
                return candidate;
        }
    }

    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(&helper_script), &info) && info.dli_fname)
    {
        fs::path bundled = fs::path(info.dli_fname).parent_path() / "ml_py" / "ml_classifiers.py";
        if (fs::is_regular_file(bundled))
            return bundled;
    }

#ifdef ML_CLASSIFIERS_SCRIPT_DIR
    return fs::path(ML_CLASSIFIERS_SCRIPT_DIR) / "ml_classifiers.py";
#else
    return "ml_classifiers.py";
#endif
}

PyObject* load_helper(const std::filesystem::path& script)
{
    if (!std::filesystem::is_regular_file(script))
        throw std::runtime_error("ml_classifiers helper not found: " + script.string());

    PyObject* importlib = PyImport_ImportModule("importlib.util");
    if (!importlib)
        raise_python("import importlib.util");

    PyObject* spec_fn = PyObject_GetAttrString(importlib, "spec_from_file_location");
    if (!spec_fn)
    {
        Py_DECREF(importlib);
        raise_python("importlib.util.spec_from_file_location");
    }

    PyObject* spec = PyObject_CallFunction(spec_fn, "ss", "ml_classifiers_helper", script.c_str());
    Py_DECREF(spec_fn);
    if (!spec)
    {
        Py_DECREF(importlib);
        raise_python("spec_from_file_location");
    }

    PyObject* from_spec = PyObject_GetAttrString(importlib, "module_from_spec");
    Py_DECREF(importlib);
    if (!from_spec)
    {
        Py_DECREF(spec);
        raise_python("importlib.util.module_from_spec");
    }

    PyObject* module = PyObject_CallFunctionObjArgs(from_spec, spec, nullptr);
    Py_DECREF(from_spec);
    if (!module)
    {
        Py_DECREF(spec);
        raise_python("load ml_classifiers.py");
    }

    PyObject* loader = PyObject_GetAttrString(spec, "loader");
    Py_DECREF(spec);
    if (!loader)
    {
        Py_DECREF(module);
        raise_python("module spec loader");
    }

    PyObject* exec_module = PyObject_GetAttrString(loader, "exec_module");
    Py_DECREF(loader);
    if (!exec_module)
    {
        Py_DECREF(module);
        raise_python("loader.exec_module");
    }

    PyObject* ran = PyObject_CallFunctionObjArgs(exec_module, module, nullptr);
    Py_DECREF(exec_module);
    if (!ran)
    {
        Py_DECREF(module);
        raise_python("exec ml_classifiers.py");
    }
    Py_DECREF(ran);
    return module;
}

} // namespace

struct Classifier::Impl
{
    PyObject* module = nullptr;
    PyObject* scaler = nullptr;
    PyObject* model = nullptr;

    ~Impl()
    {
        if (!Py_IsInitialized())
            return;
        GilLock gil;
        Py_XDECREF(model);
        Py_XDECREF(scaler);
        Py_XDECREF(module);
    }
};

std::string Classifier::model_filename(const std::string& technique)
{
    if (technique == "svc")
        return "clf_svc.joblib";
    if (technique == "ab")
        return "clf_ab.joblib";
    if (technique == "dt")
        return "clf_dt.joblib";
    if (technique == "rf")
        return "clf_rf.joblib";
    if (technique == "bnb")
        return "clf_bnb.joblib";
    if (technique == "gnb")
        return "clf_gnb.joblib";
    return {};
}

Classifier::Classifier(const std::string& model_dir, const std::string& technique)
    : impl(std::make_unique<Impl>())
{
    const std::string filename = model_filename(technique);
    if (filename.empty())
        throw std::runtime_error("unknown classifier '" + technique + "'");

    python_ensure();
    GilLock gil;

    impl->module = load_helper(helper_script());
    PyObject* loader = PyObject_GetAttrString(impl->module, "load_models");
    if (!loader)
        raise_python("ml_classifiers.load_models");

    PyObject* loaded = PyObject_CallFunction(loader, "ss", model_dir.c_str(), technique.c_str());
    Py_DECREF(loader);
    if (!loaded)
        raise_python("load joblib models");

    PyObject* scaler = PyTuple_GetItem(loaded, 0);
    PyObject* model = PyTuple_GetItem(loaded, 1);
    if (!scaler || !model)
    {
        Py_DECREF(loaded);
        raise_python("joblib load result");
    }

    Py_INCREF(scaler);
    Py_INCREF(model);
    impl->scaler = scaler;
    impl->model = model;
    Py_DECREF(loaded);
}

Classifier::~Classifier() = default;

double Classifier::predict(const double* features, std::size_t count) const
{
    python_ensure();
    GilLock gil;

    PyObject* function = PyObject_GetAttrString(impl->module, "predict_one");
    if (!function)
        raise_python("ml_classifiers.predict_one");

    PyObject* row = PyList_New(static_cast<Py_ssize_t>(count));
    if (!row)
    {
        Py_DECREF(function);
        raise_python("feature list");
    }

    for (std::size_t i = 0; i < count; ++i)
    {
        PyObject* number = PyFloat_FromDouble(features[i]);
        if (!number)
        {
            Py_DECREF(row);
            Py_DECREF(function);
            raise_python("feature value");
        }
        PyList_SET_ITEM(row, static_cast<Py_ssize_t>(i), number);
    }

    PyObject* result = PyObject_CallFunctionObjArgs(function, impl->scaler, impl->model, row, nullptr);
    Py_DECREF(row);
    Py_DECREF(function);
    if (!result)
        raise_python("predict");

    const double prediction = PyFloat_AsDouble(result);
    Py_DECREF(result);
    if (PyErr_Occurred())
        raise_python("prediction value");
    return prediction;
}

} // namespace mlc
