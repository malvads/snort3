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
// enrichment.h author Miguel Álvarez <malvarez@redborder.com>

#ifdef HAVE_ENRICHMENT
#ifndef ENRICHMENT_H
#define ENRICHMENT_H

struct Enrichment {
    const char* sensor_uuid;
    const char* sensor_type;
    const char* sensor_ip;
    const char* sensor_id_snort;
    const char* sensor_name;
    const char* group_name;
};

#endif // ENRICHMENT_H
#endif