//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------
// In-process scikit-learn inference. The GIL is held only while a model
// is loaded or a vector is predicted.

#ifndef ML_CLASSIFIERS_CLASSIFIER_H
#define ML_CLASSIFIERS_CLASSIFIER_H

#include <cstddef>
#include <memory>
#include <string>

namespace mlc
{

class Classifier
{
public:
    // Empty when the technique is not one of ab, dt, rf, svc, bnb, gnb.
    static std::string model_filename(const std::string& technique);

    Classifier(const std::string& model_dir, const std::string& technique);
    ~Classifier();

    Classifier(const Classifier&) = delete;
    Classifier& operator=(const Classifier&) = delete;

    // Returns the model's prediction. 0 is benign. Throws std::runtime_error
    // when the embedded interpreter cannot score the vector.
    double predict(const double* features, std::size_t count) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace mlc

#endif
