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

// mac_vendors.cc author Miguel Álvarez <malvarez@redborder.com>

// AVL Tree-based MAC Vendor Lookup Algorithm
// This implementation provides an efficient mechanism for inserting and searching MAC vendors 
// without relying on external libraries like librd. It uses an AVL tree data structure, 
// a self-balancing binary search tree, to store and query MAC prefixes (the first 24 bits of a MAC address).

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <cstdint>
#include <algorithm>

#ifdef HAVE_MACVENDORDB
struct MacVendorNode {
    uint64_t mac_prefix;
    std::string name;
    MacVendorNode* left;
    MacVendorNode* right;
    int height;

    MacVendorNode(uint64_t prefix, const std::string& vendor_name)
        : mac_prefix(prefix), name(vendor_name), left(nullptr), right(nullptr), height(1) {}
};

class MacVendorDatabase {
    MacVendorNode* root;

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

int MacVendorDatabase::height(MacVendorNode* node) {
    return node ? node->height : 0;
}

int MacVendorDatabase::balance_factor(MacVendorNode* node) {
    return height(node->left) - height(node->right);
}

MacVendorNode* MacVendorDatabase::rotate_right(MacVendorNode* node) {
    MacVendorNode* new_root = node->left;
    node->left = new_root->right;
    new_root->right = node;

    node->height = std::max(height(node->left), height(node->right)) + 1;
    new_root->height = std::max(height(new_root->left), height(new_root->right)) + 1;

    return new_root;
}

MacVendorNode* MacVendorDatabase::rotate_left(MacVendorNode* node) {
    MacVendorNode* new_root = node->right;
    node->right = new_root->left;
    new_root->left = node;

    node->height = std::max(height(node->left), height(node->right)) + 1;
    new_root->height = std::max(height(new_root->left), height(new_root->right)) + 1;

    return new_root;
}

MacVendorNode* MacVendorDatabase::balance(MacVendorNode* node) {
    if (balance_factor(node) > 1) {
        if (balance_factor(node->left) < 0) {
            node->left = rotate_left(node->left);
        }
        return rotate_right(node);
    }

    if (balance_factor(node) < -1) {
        if (balance_factor(node->right) > 0) {
            node->right = rotate_right(node->right);
        }
        return rotate_left(node);
    }

    return node;
}

void MacVendorDatabase::insert(uint64_t mac_prefix, const std::string& vendor_name) {
    mac_prefix &= 0xFFFFFF000000ULL;
    root = insert(root, mac_prefix, vendor_name);
}

MacVendorNode* MacVendorDatabase::insert(MacVendorNode* node, uint64_t mac_prefix, const std::string& vendor_name) {
    if (!node) return new MacVendorNode(mac_prefix, vendor_name);

    if (mac_prefix < node->mac_prefix) {
        node->left = insert(node->left, mac_prefix, vendor_name);
    } else if (mac_prefix > node->mac_prefix) {
        node->right = insert(node->right, mac_prefix, vendor_name);
    } else {
        node->name = vendor_name;
    }

    node->height = std::max(height(node->left), height(node->right)) + 1;

    return balance(node);
}

void MacVendorDatabase::insert_mac_vendors_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        std::string mac_str, vendor_name;

        if (std::getline(ss, mac_str, '|') && std::getline(ss, vendor_name)) {
            uint64_t mac_prefix = std::stoull(mac_str, nullptr, 16) << 24;

            insert(mac_prefix, vendor_name);
        }
    }

    file.close();
}

const char* MacVendorDatabase::find_mac_vendor(uint64_t mac) {
    uint64_t mac_prefix = mac & 0xFFFFFF000000ULL;
    MacVendorNode* node = find_mac_vendor(root, mac_prefix);
    return node ? node->name.c_str() : nullptr;
}

MacVendorNode* MacVendorDatabase::find_mac_vendor(MacVendorNode* node, uint64_t mac_prefix) {
    if (!node) return nullptr;

    if (mac_prefix < node->mac_prefix) {
        return find_mac_vendor(node->left, mac_prefix);
    } else if (mac_prefix > node->mac_prefix) {
        return find_mac_vendor(node->right, mac_prefix);
    } else {
        return node;
    }
}

void MacVendorDatabase::destroy_tree(MacVendorNode* node) {
    if (node) {
        destroy_tree(node->left);
        destroy_tree(node->right);
        delete node;
    }
}
#endif