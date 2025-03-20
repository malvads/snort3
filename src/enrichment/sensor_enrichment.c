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
// sensor_enrichment.cc author Miguel Álvarez <malvarez@redborder.com>

#ifdef HAVE_ENRICHMENT
#include "enrichment/sensor_enrichment.h"
#include <utility>

void SensorEnrichment::EnrichJsonLog(BinaryWriter* writer, const Enrichment& enrichment) {
    const std::pair<const char*, const char*> params[] = {
        {"sensor_uuid", enrichment.sensor_uuid},
        {"sensor_name", enrichment.sensor_name},
        {"sensor_type", enrichment.sensor_type},
        {"sensor_ip", enrichment.sensor_ip},
        {"group_name", enrichment.group_name}
    };
    
    for (const auto& param : params) {
        if (param.second && param.second[0] != '\0') {
            TextLog_WriteString(writer, ", ");
            TextLog_Putc(writer, '"');
            TextLog_WriteString(writer, param.first);
            TextLog_Putc(writer, '"');
            TextLog_WriteString(writer, ": \"");
            TextLog_WriteString(writer, param.second);
            TextLog_Putc(writer, '"');
        }
    }

    TextLog_WriteString(writer, ", ");
    TextLog_Putc(writer, '"');
    TextLog_WriteString(writer, "sensor_id_snort");
    TextLog_Putc(writer, '"');
    TextLog_WriteString(writer, ": ");
    TextLog_WriteString(writer, enrichment.sensor_id_snort);

}
#endif