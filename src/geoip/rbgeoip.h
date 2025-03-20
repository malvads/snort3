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
// rbgeoip.h author Miguel Álvarez <malvarez@redborder.com>
// Simple SINGLETON to load/unload geoip database for libgeoip++

#ifdef HAVE_GEOIP
#ifndef GEO_IP_LOADER_H
#define GEO_IP_LOADER_H

#include <string>
#include <stdexcept>
#include <GeoLite2PP.hpp>

namespace GeoIpLoader {

    class Manager {
    private:
        GeoLite2PP::DB* db;  
        static Manager* instance;  
        bool isLoaded;  

        Manager();
        ~Manager();

        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;

    public:
        static Manager* getInstance(const std::string& dbPath = "");
        void loadDB(const std::string& dbPath);
        void unloadDB();
        std::string getCountryByIP(const std::string& ip_string);
    };

}  // namespace GeoIpLoader

#endif // GEO_IP_LOADER_H
#endif