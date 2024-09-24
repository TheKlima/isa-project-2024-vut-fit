#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include "dns_monitor_exception.h"
#include <new>                     // For std::nothrow
#include <cstdlib>                 // For u_char
#include <arpa/inet.h>             // For inet_ntop
#include <netinet/ether.h>         // For Ethernet header (struct ether_header)
#include <iostream>

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) = 0;
    
protected:
    void printTimestamp(struct pcap_pkthdr* packet_header) const;
    void printIpAddress(const char* ip_address) const;
    void processIpHeader(struct pcap_pkthdr* packet_header, const u_char* packet_data);
    
    bool m_is_ipv4{};
    char m_src_ip[INET6_ADDRSTRLEN]{};
    char m_dst_ip[INET6_ADDRSTRLEN]{};

private:
    void getSrcDstIpAddresses(const void* src_ip, const void* dst_ip);
};

#endif // PACKET_WRITER_H