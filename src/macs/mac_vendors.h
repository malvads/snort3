//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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

// mac_vendors.h author Miguel Álvarez <malvarez@redborder.com>

// Easy algorithm to insert and search mac vendor without librd

#ifdef HAVE_MACVENDORDB
#ifndef RB_MAC_VENDORS_H
#define RB_MAC_VENDORS_H

#include <string>
#include <cstdint>
#include <iostream>
#include <memory>

struct MacVendorNode {
    uint64_t mac_prefix;
    std::string name;
    MacVendorNode *left;
    MacVendorNode *right;
    int height;

    MacVendorNode(uint64_t prefix, const std::string& vendor_name)
        : mac_prefix(prefix), name(vendor_name), left(nullptr), right(nullptr), height(1) {}
};

class MacVendorDatabase {
    MacVendorNode *root;

public:
    MacVendorDatabase() : root(nullptr) {}
    ~MacVendorDatabase() { destroy_tree(root); }

    void insert(uint64_t mac_prefix, const std::string& vendor_name);
    void insert_mac_vendors_from_file(const std::string& filename);
    const char* find_mac_vendor(uint64_t mac);
    
private:
    MacVendorNode* insert(MacVendorNode* node, uint64_t mac_prefix, const std::string& vendor_name);
    MacVendorNode* find_mac_vendor(MacVendorNode* node, uint64_t mac_prefix);
    void destroy_tree(MacVendorNode* node);
    int height(MacVendorNode* node);
    int balance_factor(MacVendorNode* node);
    MacVendorNode* rotate_right(MacVendorNode* node);
    MacVendorNode* rotate_left(MacVendorNode* node);
    MacVendorNode* balance(MacVendorNode* node);
};

#endif // RB_MAC_VENDORS_H
#endif