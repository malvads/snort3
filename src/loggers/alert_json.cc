//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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

// alert_json.cc author Russ Combs <rucombs@cisco.com>
//

// Extended for sending to kafka (librdkafka) and http (libcpr) with extra-fields
// by Miguel Álvarez <malvarez@redborder.com>

// preliminary version based on hacking up alert_csv.cc.  should probably
// share a common implementation class.

// if a more sophisticated solution is needed, for example to escape \ or
// whatever, look at this from Joel: https://github.com/jncornett/alert_json,
// which is also more OO implemented.  should pull in that at some point.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "events/event.h"
#include "flow/flow_key.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/base64_encoder.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/cisco_meta_data.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
using namespace snort;
using namespace std;

#define LOG_BUFFER (4*K_BYTES)

#ifdef HAVE_RDKAFKA
    #include <librdkafka/rdkafka.h>
    #define EXPORT_TYPE_KAFKA "kafka"
#endif

#ifdef HAVE_CPR
    #include <cpr/cpr.h>
    #define EXPORT_TYPE_HTTP "http"
    #define DEF_VERIFY_SSL "true"
#endif

#ifdef HAVE_GEOIP
    #include "geoip/rbgeoip.h"
#endif

#ifdef HAVE_ENRICHMENT
    #include "enrichment/sensor_enrichment.h"
#endif

#define EXPORT_TYPE_STDOUT "stdout"

static THREAD_LOCAL TextLog* json_log;

#define S_NAME "alert_json"
#define F_NAME S_NAME ".txt"
#ifdef HAVE_RDKAFKA
    #define D_TOPIC "rb_event"
    #define D_KAFKA_HOST "kafka.service:9092"
#endif
#ifdef HAVE_MACVENDORDB
    #include "macs/mac_vendors.h"
    MacVendorDatabase MacVendorDB;
#endif
#ifndef RB_ENABLE_OVERRIDES
    #define RB_ENABLE_OVERRIDES true
#endif

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

namespace
{
struct Args
{
    Packet* pkt;
    const char* msg;
    const Event& event;
    bool comma;
};
}

static void print_label(const Args& a, const char* label)
{
    if ( a.comma )
        TextLog_Print(json_log, ",");

    TextLog_Print(json_log, " \"%s\" : ", label);
}

static bool ff_action(const Args& a)
{
    print_label(a, "action");
    if(RB_ENABLE_OVERRIDES){
        string action = "log";
        if(a.pkt->active->packet_was_dropped()) action = "drop";
        if(a.pkt->active->packet_would_be_dropped()) action = "should_drop";
        #ifdef RB_EXTRADATA
            if(a.pkt->active->packet_cant_be_dropped()) action = "cant_drop";
            if(a.pkt->active->packet_would_be_allowed()) action = "alert";
        #endif
        TextLog_Quote(json_log, action.c_str());
    } else {
        TextLog_Quote(json_log, a.pkt->active->get_action_string());
    }
    return true;
}

static bool ff_class(const Args& a)
{
    if(RB_ENABLE_OVERRIDES){
        const char *cls = "none";

        if (a.event.get_class_type() && a.event.get_class_type()[0] != '\0')
            cls = a.event.get_class_type();

        print_label(a, "class");
        TextLog_Quote(json_log, cls);
        return true;
    } else {
        const char* cls = a.event.get_class_type();
        if ( !cls ) cls = "none";

        print_label(a, "class");
        TextLog_Quote(json_log, cls);
        return true;
    }
}

static bool ff_b64_data(const Args& a)
{
    if ( !a.pkt->dsize )
        return false;

    const unsigned block_size = 2048;
    char out[2*block_size];
    const uint8_t* in = a.pkt->data;

    unsigned nin = 0;
    Base64Encoder b64;

    print_label(a, "b64_data");
    TextLog_Putc(json_log, '"');

    while ( nin < a.pkt->dsize )
    {
        unsigned kin = min(a.pkt->dsize-nin, block_size);
        unsigned kout = b64.encode(in+nin, kin, out);
        TextLog_Write(json_log, out, kout);
        nin += kin;
    }

    if ( unsigned kout = b64.finish(out) )
        TextLog_Write(json_log, out, kout);

    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_client_bytes(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_bytes");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_bytes);
        return true;
    }
    return false;
}

static bool ff_client_pkts(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_pkts");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_pkts);
        return true;
    }
    return false;
}

static bool ff_dir(const Args& a)
{
    const char* dir;

    if ( a.pkt->is_from_application_client() )
        dir = "C2S";
    else if ( a.pkt->is_from_application_server() )
        dir = "S2C";
    else
        dir = "UNK";

    print_label(a, "dir");
    TextLog_Quote(json_log, dir);
    return true;
}

#ifdef RB_EXTRADATA
    static bool ff_src(const Args &a)
    {
        if (a.pkt->has_ip() or a.pkt->is_data())
        {
            SfIpString ip_str;
            print_label(a, "src");
            TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
            return true;
        }
        return false;
    }

    static bool ff_dst(const Args &a)
    {
        if (a.pkt->has_ip() or a.pkt->is_data())
        {
            SfIpString ip_str;
            print_label(a, "dst");
            TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
            return true;
        }
        return false;
    }

    static bool ff_udplen(const Args &a)
    {
        if (a.pkt->ptrs.udph)
        {
            print_label(a, "udplen");
            TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
            return true;
        }
        return false;
    }

#endif

#if defined(RB_EXTRADATA) && defined(HAVE_GEOIP)
    static bool ff_src_country_code(const Args &a)
    {
        if (a.pkt->has_ip() || a.pkt->is_data())
        {
            print_label(a, "src_country_code");
            SfIpString ip_str;
            a.pkt->ptrs.ip_api.get_src()->ntop(ip_str);
            string ip_string = ip_str;
            string country = GeoIpLoader::Manager::getInstance()->getCountryByIP(ip_string);
            TextLog_Print(json_log, "\"%s\"", country.c_str());
            return true;
        }
        return false;
    }
    static bool ff_dst_country_code(const Args &a)
    {
        if (a.pkt->has_ip() || a.pkt->is_data())
        {
            print_label(a, "dst_country_code");
            SfIpString ip_str;
            a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str);
            string ip_string = ip_str;
            string country = GeoIpLoader::Manager::getInstance()->getCountryByIP(ip_string);
            BinaryWriter_Print(json_log, "\"%s\"", country.c_str());
            return true;
        }
        return false;
    }
#endif

#ifdef RB_EXTRADATA
    static bool ff_dst_country(const Args &a)
    {
        print_label(a, "dst_country");
        TextLog_Print(json_log, "\"Unknown\"");
        return true;
    }
    static bool ff_src_country(const Args &a)
    {
        print_label(a, "src_country");
        TextLog_Print(json_log, "\"Unknown\"");
        return true;
    }
    static bool ff_ethlength_range(const Args &a)
    {
        if (a.pkt)
        {
            int len = 0;

            if (a.pkt->has_ip())
                len = a.pkt->ptrs.ip_api.dgram_len();
            else
                len = a.pkt->dsize;

            print_label(a, "ethlength_range");

            if (len == 0)
            {
                TextLog_Print(json_log, "\"0\"");
            }
            else if (len <= 64)
            {
                TextLog_Print(json_log, "\"(0-64]\"");
            }
            else if (len <= 128)
            {
                TextLog_Print(json_log, "\"(64-128]\"");
            }
            else if (len <= 256)
            {
                TextLog_Print(json_log, "\"(128-256]\"");
            }
            else if (len <= 512)
            {
                TextLog_Print(json_log, "\"(256-512]\"");
            }
            else if (len <= 768)
            {
                TextLog_Print(json_log, "\"(512-768]\"");
            }
            else if (len <= 1024)
            {
                TextLog_Print(json_log, "\"(768-1024]\"");
            }
            else if (len <= 1280)
            {
                TextLog_Print(json_log, "\"(1024-1280]\"");
            }
            else if (len <= 1514)
            {
                TextLog_Print(json_log, "\"(1280-1514]\"");
            }
            else if (len <= 2048)
            {
                TextLog_Print(json_log, "\"(1514-2048]\"");
            }
            else if (len <= 4096)
            {
                TextLog_Print(json_log, "\"(2048-4096]\"");
            }
            else if (len <= 8192)
            {
                TextLog_Print(json_log, "\"(4096-8192]\"");
            }
            else if (len <= 16384)
            {
                TextLog_Print(json_log, "\"(8192-16384]\"");
            }
            else if (len <= 32768)
            {
                TextLog_Print(json_log, "\"(16384-32768]\"");
            }
            else
            {
                TextLog_Print(json_log, "\">32768\"");
            }

            return true;
        }
        return false;
    }
    static bool ff_sig_generator(const Args &a)
    {
        print_label(a, "sig_generator");
        TextLog_Print(json_log, "\"%u\"", a.event.get_rev());

        return true;
    }
    static bool ff_sig_id(const Args &a)
    {
        print_label(a, "sig_id");
        TextLog_Print(json_log, "\"%u\"", a.event.get_rev());
        return true;
    }

    #ifdef HAVE_MACVENDORDB
        static bool ff_eth_src_mac(const Args &a)
        {
            if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
                return false;

            print_label(a, "ethsrcmac");

            const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

            uint64_t mac_prefix = 0;
            for (int i = 0; i < 6; ++i)
            {
                mac_prefix <<= 8;
                mac_prefix |= static_cast<uint64_t>(eh->ether_src[i]);
            }

            const char *vendor = MacVendorDB.find_mac_vendor(mac_prefix);

            if (vendor)
            {
                TextLog_Print(json_log, "\"%s\"", vendor);
            }
            else
            {
                TextLog_Print(json_log, "\"%s\"", "Unknown");
            }

            return true;
        }

        static bool ff_eth_dst_mac(const Args &a)
        {
            if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
                return false;

            print_label(a, "ethdstmac");

            const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

            uint64_t mac_prefix = 0;
            for (int i = 0; i < 6; ++i)
            {
                mac_prefix <<= 8;
                mac_prefix |= static_cast<uint64_t>(eh->ether_dst[i]);
            }

            const char *vendor = MacVendorDB.find_mac_vendor(mac_prefix);

            if (vendor)
            {
                TextLog_Print(json_log, "\"%s\"", vendor);
            }
            else
            {
                TextLog_Print(json_log, "\"%s\"", "Unknown");
            }

            return true;
        }
    #endif
#endif

static bool ff_dst_addr(const Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "dst_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_dst_ap(const Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.dp;

    print_label(a, "dst_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_dst_port(const Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "dst_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.dp);
        return true;
    }
    return false;
}

static bool ff_eth_dst(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_dst");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    return true;
}

static bool ff_eth_len(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_len");
    TextLog_Print(json_log, "%u", a.pkt->pkth->pktlen);
    return true;
}

static bool ff_eth_src(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_src");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);
    return true;
}

static bool ff_eth_type(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    print_label(a, "eth_type");
    TextLog_Print(json_log, "\"0x%X\"", ntohs(eh->ether_type));
    return true;
}

static bool ff_flowstart_time(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "flowstart_time");
        TextLog_Print(json_log, "%ld", a.pkt->flow->flowstats.start_time.tv_sec);
        return true;
    }
    return false;
}

static bool ff_geneve_vni(const Args& a)
{
    if (a.pkt->proto_bits & PROTO_BIT__GENEVE)
    {
        print_label(a, "geneve_vni");
        TextLog_Print(json_log, "%u", a.pkt->get_flow_geneve_vni());
    }
    return true;
}

static bool ff_gid(const Args& a)
{
    print_label(a, "gid");
    TextLog_Print(json_log, "%u",  a.event.get_gid());
    return true;
}

static bool ff_icmp_code(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_code");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->code);
        return true;
    }
    return false;
}

static bool ff_icmp_id(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_id");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_id));
        return true;
    }
    return false;
}

static bool ff_icmp_seq(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_seq");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_seq));
        return true;
    }
    return false;
}

static bool ff_icmp_type(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_type");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->type);
        return true;
    }
    return false;
}

static bool ff_iface(const Args& a)
{
    print_label(a, "iface");
    TextLog_Quote(json_log, SFDAQ::get_input_spec());
    return true;
}

static bool ff_ip_id(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_id");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.id());
        return true;
    }
    return false;
}

#ifndef RB_ENABLE_OVERRIDES
     bool ff_ip_len(const Args& a)
#else
    static bool ff_iplen(const Args& a)
#endif
{
    if (a.pkt->has_ip())
    {
        #ifndef RB_ENABLE_OVERRIDES
            print_label(a, "ff_ip_len");
        #else
            print_label(a, "ff_iplen");
        #endif
        
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.pay_len());
        return true;
    }
    return false;
}

static bool ff_msg(const Args& a)
{
    print_label(a, "msg");
    TextLog_Puts(json_log, a.msg);
    return true;
}

static bool ff_mpls(const Args& a)
{
    uint32_t mpls;

    if (a.pkt->flow)
        mpls = a.pkt->flow->key->mplsLabel;

    else if ( a.pkt->proto_bits & PROTO_BIT__MPLS )
        mpls = a.pkt->ptrs.mplsHdr.label;

    else
        return false;

    print_label(a, "mpls");
    TextLog_Print(json_log, "%u", mpls);
    return true;
}

static bool ff_pkt_gen(const Args& a)
{
    print_label(a, "pkt_gen");
    TextLog_Quote(json_log, a.pkt->get_pseudo_type());
    return true;
}

static bool ff_pkt_len(const Args& a)
{
    print_label(a, "pkt_len");

    if (a.pkt->has_ip())
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.dgram_len());
    else
        TextLog_Print(json_log, "%u", a.pkt->dsize);

    return true;
}

static bool ff_pkt_num(const Args& a)
{
    print_label(a, "pkt_num");
    TextLog_Print(json_log, STDu64, a.pkt->context->packet_number);
    return true;
}

static bool ff_priority(const Args& a)
{
    if(RB_ENABLE_OVERRIDES){
        static const char *priority_name[] = {NULL, "high", "medium", "low", "very low"};
        const int priority_id = a.event.get_priority();
        const char *prio_name = NULL;
        if(priority_id < sizeof(priority_name)/sizeof(priority_name[0]))
            prio_name = priority_name[priority_id];
        print_label(a, "priority");
        TextLog_Print(json_log, "\"%s\"", prio_name);
        return true;
    } else {
        print_label(a, "priority");
        TextLog_Print(json_log, "%u", a.event.get_priority());
    }
    return true;
}

static bool ff_proto(const Args& a)
{
    print_label(a, "proto");
    TextLog_Quote(json_log, a.pkt->get_type());
    return true;
}

static bool ff_rev(const Args& a)
{
    print_label(a, "rev");
    TextLog_Print(json_log, "%u",  a.event.get_rev());
    return true;
}

static bool ff_rule(const Args& a)
{
    print_label(a, "rule");

    uint32_t gid, sid, rev;
    a.event.get_sig_ids(gid, sid, rev);

    TextLog_Print(json_log, "\"%u:%u:%u\"", gid, sid, rev);
    return true;
}

static bool ff_seconds(const Args& a)
{
    print_label(a, "seconds");
    TextLog_Print(json_log, "%ld",  a.pkt->pkth->ts.tv_sec);
    return true;
}

static bool ff_server_bytes(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_bytes");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_bytes);
        return true;
    }
    return false;
}

static bool ff_server_pkts(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_pkts");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_pkts);
        return true;
    }
    return false;
}

static bool ff_service(const Args& a)
{
    const char* svc = "unknown";

    if ( a.pkt->flow and a.pkt->flow->service )
        svc = a.pkt->flow->service;

    print_label(a, "service");
    TextLog_Quote(json_log, svc);
    return true;
}

static bool ff_sgt(const Args& a)
{
    if (a.pkt->proto_bits & PROTO_BIT__CISCO_META_DATA)
    {
        const cisco_meta_data::CiscoMetaDataHdr* cmdh = layer::get_cisco_meta_data_layer(a.pkt);
        print_label(a, "sgt");
        TextLog_Print(json_log, "%hu", cmdh->sgt_val());
        return true;
    }
    return false;
}

static bool ff_sid(const Args& a)
{
    print_label(a, "sid");
    TextLog_Print(json_log, "%u",  a.event.get_sid());
    return true;
}

static bool ff_src_addr(const Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "src_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_src_ap(const Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.sp;

    print_label(a, "src_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_src_port(const Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "src_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.sp);
        return true;
    }
    return false;
}

static bool ff_target(const Args& a)
{
    SfIpString addr = "";
    bool src;

    if ( !a.event.get_target(src) )
        return false;

    if ( src )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    print_label(a, "target");
    TextLog_Quote(json_log, addr);
    return true;
}

static bool ff_tcp_ack(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_ack");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_ack));
        return true;
    }
    return false;
}

static bool ff_tcp_flags(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        char tcpFlags[9];
        a.pkt->ptrs.tcph->stringify_flags(tcpFlags);

        print_label(a, "tcp_flags");
        TextLog_Quote(json_log, tcpFlags);
        return true;
    }
    return false;
}

static bool ff_tcp_len(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_len");
        TextLog_Print(json_log, "%u", (a.pkt->ptrs.tcph->off()));
        return true;
    }
    return false;
}

static bool ff_tcp_seq(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_seq");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_seq));
        return true;
    }
    return false;
}

static bool ff_tcp_win(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_win");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.tcph->th_win));
        return true;
    }
    return false;
}

static bool ff_timestamp(const Args& a)
{
    if(RB_ENABLE_OVERRIDES){
        time_t current_time = time(nullptr);
        if (a.comma)
        {
            TextLog_Putc(json_log, ',');
        }
        TextLog_Print(json_log, "\"timestamp\": ");
        TextLog_Print(json_log, to_string(current_time).c_str());
        return true;
    } else {
        print_label(a, "timestamp");
        TextLog_Putc(json_log, '"');
        LogTimeStamp(json_log, a.pkt);
        TextLog_Putc(json_log, '"');
        return true;
    }
    return false;
}

static bool ff_tos(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "tos");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.tos());
        return true;
    }
    return false;
}

static bool ff_ttl(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ttl");
        TextLog_Print(json_log, "%u",a.pkt->ptrs.ip_api.ttl());
        return true;
    }
    return false;
}

static bool ff_udp_len(const Args& a)
{
    if (a.pkt->ptrs.udph )
    {
        print_label(a, "udp_len");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
        return true;
    }
    return false;
}

static bool ff_vlan(const Args& a)
{
    print_label(a, "vlan");
    TextLog_Print(json_log, "%hu", a.pkt->get_flow_vlan_id());
    return true;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

typedef bool (*JsonFunc)(const Args&);

static const JsonFunc json_func[] =
{
    ff_action, ff_class, ff_b64_data, ff_client_bytes, ff_client_pkts, ff_dir,
    ff_dst_addr, ff_dst_ap, ff_dst_port, ff_eth_dst, ff_eth_len, ff_eth_src,
    ff_eth_type, ff_flowstart_time, ff_geneve_vni, ff_gid, ff_icmp_code, ff_icmp_id, ff_icmp_seq,
    ff_icmp_type, ff_iface, ff_ip_id, ff_msg, ff_mpls, ff_pkt_gen, ff_pkt_len,
    ff_pkt_num, ff_priority, ff_proto, ff_rev, ff_rule, ff_seconds, ff_server_bytes,
    ff_server_pkts, ff_service, ff_sgt, ff_sid, ff_src_addr, ff_src_ap, ff_src_port,
    ff_target, ff_tcp_ack, ff_tcp_flags, ff_tcp_len, ff_tcp_seq, ff_tcp_win, ff_timestamp,
    ff_tos, ff_ttl, ff_udp_len, ff_vlan,
#ifndef RB_ENABLE_OVERRIDES
    ff_ip_len,
#else
    ff_iplen,
#endif
    #ifdef RB_EXTRADATA
        ff_src, ff_dst, ff_src_country, ff_dst_country,
        ff_ethlength_range, ff_udplen, ff_sig_id, ff_sig_generator,
        
    #ifdef HAVE_MACVENDORDB
        ff_eth_src_mac, ff_eth_dst_mac,
    #endif

    #ifdef HAVE_GEOIP
        ff_src_country_code, ff_dst_country_code,
    #endif
#endif
};

#define JSON_RANGE_BASE \
    "action | class | b64_data | client_bytes | client_pkts | dir | " \
    "dst_addr | dst_ap | dst_port | eth_dst | eth_len | eth_src | " \
    "eth_type | flowstart_time | geneve_vni | gid | icmp_code | icmp_id | icmp_seq | " \
    "icmp_type | iface | ip_id | msg | mpls | pkt_gen | pkt_len | " \
    "pkt_num | priority | proto | rev | rule | seconds | server_bytes | " \
    "server_pkts | service | sgt | sid | src_addr | src_ap | src_port | " \
    "target | tcp_ack | tcp_flags | tcp_len | tcp_seq | tcp_win | timestamp | " \
    "tos | ttl | udp_len | vlan"

#ifdef RB_ENABLE_OVERRIDES
    #define JSON_IP_FIELD " | iplen"
#else
    #define JSON_IP_FIELD " | ip_len"
#endif

#ifdef RB_EXTRADATA
    #ifdef HAVE_MACVENDORDB
        #ifdef HAVE_GEOIP
            #define json_range JSON_RANGE_BASE JSON_IP_FIELD " | src | dst | src_country | dst_country | ethlength_range | udplen | sig_id | sig_generator" \
                              " | eth_src_mac | eth_dst_mac" \
                              " | src_country_code | dst_country_code"
        #else
            #define json_range JSON_RANGE_BASE JSON_IP_FIELD " | src | dst | src_country | dst_country | ethlength_range | udplen | sig_id | sig_generator" \
                              " | eth_src_mac | eth_dst_mac"
        #endif
    #else
        #ifdef HAVE_GEOIP
            #define json_range JSON_RANGE_BASE JSON_IP_FIELD " | src | dst | src_country | dst_country | ethlength_range | udplen | sig_id | sig_generator" \
                              " | src_country_code | dst_country_code"
        #else
            #define json_range JSON_RANGE_BASE JSON_IP_FIELD " | src | dst | src_country | dst_country | ethlength_range | udplen | sig_id | sig_generator"
        #endif
    #endif
#else
    #define json_range JSON_RANGE_BASE JSON_IP_FIELD
#endif

#define json_deflt \
    "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action"


static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },
#if defined(HAVE_CPR) || defined(HAVE_RDKAFKA)
    { "type", Parameter::PT_STRING, nullptr, EXPORT_TYPE_STDOUT,
      "Default export type" },
#endif

#ifdef HAVE_CPR
    { "http_endpoint", Parameter::PT_STRING, nullptr, nullptr,
      "HTTP endpoint for send data to the manager" },

    { "verify_ssl", Parameter::PT_BOOL, nullptr, DEF_VERIFY_SSL,
      "Verify SSL Cert when sending requests" },
#endif

#ifdef HAVE_RDKAFKA
    {"kafka_topic", Parameter::PT_STRING, nullptr, D_TOPIC,
        "send data to topic " D_TOPIC},

    {"kafka_broker", Parameter::PT_STRING, nullptr, D_KAFKA_HOST, 
    
    "Kafka broker host"},
#endif
    { "fields", Parameter::PT_MULTI, json_range, json_deflt,
      "selected fields will be output in given order left to right" },

    { "limit", Parameter::PT_INT, "0:maxSZ", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "separator", Parameter::PT_STRING, nullptr, ", ",
      "separate fields with this character sequence" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event in json format"

class JsonModule : public Module
{
public:
    JsonModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

public:
    bool file = false;
#ifdef HAVE_RDKAFKA
    string kafka_broker;
    string kafka_topic;
#endif
#if defined(HAVE_CPR) || defined(HAVE_RDKAFKA)
    string type;
#endif
#ifdef HAVE_CPR
    string http_endpoint;
    bool verify_ssl;
#endif
    size_t limit = 0;
    string sep;
    vector<JsonFunc> fields;
};

bool JsonModule::set(const char*, Value& v, SnortConfig*)
{
#if defined(HAVE_CPR) || defined(HAVE_RDKAFKA)
    if ( v.is("type") )
        type = v.get_string();
#endif

#ifdef HAVE_CPR
    if ( v.is("http_endpoint") )
        http_endpoint = v.get_string();
#endif

#ifdef HAVE_RDKAFKA
    if (v.is("kafka_broker"))
        kafka_broker = v.get_string();

    if (v.is("kafka_topic"))
        kafka_topic = v.get_string();
#endif

    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("fields") )
    {
        string tok;
        v.set_first_token();
        fields.clear();

        while ( v.get_next_token(tok) )
        {
            int i = Parameter::index(json_range, tok.c_str());
            if ( i >= 0 )
                fields.emplace_back(json_func[i]);
        }
    }

    else if ( v.is("limit") )
        limit = v.get_size() * 1024 * 1024;

    else if ( v.is("separator") )
        sep = v.get_string();

    return true;
}

bool JsonModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    sep = ", ";

    if ( fields.empty() )
    {
        Value v(json_deflt);
        string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
        {
            int i = Parameter::index(json_range, tok.c_str());
            if ( i >= 0 )
                fields.emplace_back(json_func[i]);
        }
    }
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class LogExporterBaseStrategy {
public:
    virtual ~LogExporterBaseStrategy() = default;
    virtual void open() = 0;
    virtual void close() = 0;
    virtual void alert(Packet *p, const char *msg, const Event &event) = 0;
};

#ifdef HAVE_RDKAFKA
struct KafkaContext {
    rd_kafka_t *rk;
    rd_kafka_conf_t *conf;
    rd_kafka_topic_t *rkt;
};

class KafkaExporterStrategy : public LogExporterBaseStrategy {
public:
    KafkaExporterStrategy(const string& broker, const string& topic, vector<JsonFunc> fields)
        : kafka_broker(broker.empty() ? D_KAFKA_HOST : broker),
          kafka_topic(topic.empty() ? D_TOPIC : topic),
          fields(fields)
    {}

    void open() override {
        json_log = TextLog_Init(F_NAME, LOG_BUFFER, 0);
        ctx.conf = rd_kafka_conf_new();
        rd_kafka_conf_set(ctx.conf, "bootstrap.servers", kafka_broker.c_str(), errstr, sizeof(errstr));
        ctx.rk = rd_kafka_new(RD_KAFKA_PRODUCER, ctx.conf, errstr, sizeof(errstr));
        ctx.rkt = rd_kafka_topic_new(ctx.rk, kafka_topic.c_str(), nullptr);
    }

    void close() override {
        if (json_log)
            TextLog_Term(json_log);
        if (ctx.rkt)
            rd_kafka_topic_destroy(ctx.rkt);
        if (ctx.rk) {
            rd_kafka_flush(ctx.rk, 10000);
            rd_kafka_destroy(ctx.rk);
        }
    }

    void alert(Packet *p, const char *msg, const Event &event) override {
        Args a = {p, msg, event, false};
        TextLog_Putc(json_log, '{');
        for (JsonFunc f : fields) {
            f(a);
            a.comma = true;
        }
        TextLog_Print(json_log, " }\n");
        char* json_event = TextLog_GetBuffer(json_log);
        if (json_event) {
            size_t json_event_size = strlen(json_event);
            rd_kafka_produce(
                    ctx.rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                    json_event, json_event_size,
                    NULL, 0, NULL);
        }
        TextLog_Flush(json_log);
        rd_kafka_poll(ctx.rk, 0);
    }

private:
    string kafka_broker;
    string kafka_topic;
    vector<JsonFunc> fields;
    char errstr[512];
    thread_local static KafkaContext ctx;
};

thread_local KafkaContext KafkaExporterStrategy::ctx = {nullptr, nullptr, nullptr};

#endif

#ifdef HAVE_CPR

//---------------------------------
// HTTP ASYNC SENDING
//---------------------------------

class HttpExporterStrategy : public LogExporterBaseStrategy {
public:
    HttpExporterStrategy(const std::string& http_endpoint, const bool verify_ssl, std::vector<JsonFunc> fields)
        : http_endpoint(http_endpoint), verify_ssl(verify_ssl), fields(fields)
    {}

    void open() override {
        json_log = TextLog_Init(F_NAME, LOG_BUFFER, 0);
    }

    void close() override {
        if (json_log)
            TextLog_Term(json_log);
    }

    void alert(Packet *p, const char *msg, const Event &event) override {
        Args a = { p, msg, event, false };
        TextLog_Putc(json_log, '{');

        for (JsonFunc f : fields) {
            f(a);
            a.comma = true;
        }

        TextLog_Print(json_log, " }\n");
        char* json_event = TextLog_GetBuffer(json_log);
        if (json_event) {
            std::string body(json_event);
            auto future_response = cpr::PostAsync(
                cpr::Url{http_endpoint},
                cpr::VerifySsl{verify_ssl},
                cpr::Body{body},
                cpr::Header{{"Content-Type", "application/json"}});
        }
        TextLog_Flush(json_log);
    }

private:
    std::string http_endpoint;
    bool verify_ssl;
    std::vector<JsonFunc> fields;
};
#endif

class StdoutExporterStrategy : public  LogExporterBaseStrategy {
public:
    StdoutExporterStrategy(const bool filename, unsigned long limit, vector<JsonFunc> fields)
        : file(filename), logLimit(limit), fields(fields)
    {}

    void open() override {
        filename = file ? F_NAME : "stdout";
        json_log = TextLog_Init(filename.c_str(), LOG_BUFFER, logLimit);
    }

    void close() override {
        if ( json_log )
            TextLog_Term(json_log);
    }

    void alert(Packet *p, const char *msg, const Event &event) override {
        Args a = { p, msg, event, false };
        TextLog_Putc(json_log, '{');

        for ( JsonFunc f : fields )
        {
            f(a);
            a.comma = true;
        }

        TextLog_Print(json_log, " }\n");
        TextLog_Flush(json_log);
    }

private:
    bool file;
    string filename;
    vector<JsonFunc> fields;
    unsigned long logLimit;
};

class LogExporterFactory {
public:
    static unique_ptr<LogExporterBaseStrategy> create(JsonModule* m) {
#ifdef HAVE_RDKAFKA
        if(m->type == EXPORT_TYPE_KAFKA) {
            return make_unique<KafkaExporterStrategy>(m->kafka_broker, m->kafka_topic, m->fields);
        }
#endif

#ifdef HAVE_CPR
        if(m->type == EXPORT_TYPE_HTTP) {
            return make_unique<HttpExporterStrategy>(m->http_endpoint, m->verify_ssl, m->fields);
        }
#endif
        return make_unique<StdoutExporterStrategy>(m->file, m->limit, m->fields);
    }
};

class JsonLogger : public Logger {
public:
    JsonLogger(JsonModule* m) : Logger() {
        exporter = LogExporterFactory::create(m);
    }

    void open() override {
#ifdef HAVE_MACVENDORDB
        // TODO (LOAD mac_vendors)
        MacVendorDB.insert_mac_vendors_from_file(mac_vendors.c_str());
#endif
        exporter->open();
    }

    void close() override {
        exporter->close();
    }

    void alert(Packet *p, const char *msg, const Event &event) override {
        exporter->alert(p, msg, event);
    }

private:
    std::unique_ptr<LogExporterBaseStrategy> exporter;
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new JsonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* json_ctor(Module* mod)
{ return new JsonLogger((JsonModule*)mod); }

static void json_dtor(Logger* p)
{ delete p; }

static LogApi json_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    json_ctor,
    json_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_json[] =
#endif
{
    &json_api.base,
    nullptr
};

