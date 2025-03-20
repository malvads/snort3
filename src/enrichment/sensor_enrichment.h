//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// sensor_enrichment.h author Miguel Álvarez <malvarez@redborder.com>

#ifdef HAVE_ENRICHMENT
#ifndef SENSOR_ENRICHMENT_H
#define SENSOR_ENRICHMENT_H

#include "log/text_log.h"
#include "enrichment/enrichment.h"

class SensorEnrichment {
public:
    static void EnrichJsonLog(BinaryWriter* writer, const Enrichment& enrichment);
};

#endif // SENSOR_ENRICHMENT_H
#endif