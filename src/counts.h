//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Luan Utimura <luan.utimura@gmail.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation. You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------

#ifndef ML_CLASSIFIERS_COUNTS_H
#define ML_CLASSIFIERS_COUNTS_H

namespace mlc
{

// Outside the GID range Snort reserves for builtin inspectors.
constexpr unsigned GID = 45678;
constexpr unsigned SID_ATTACK = 1;

void count_packet();
void count_flow();
void count_classified();
void count_benign();
void count_attack();

} // namespace mlc

#endif
