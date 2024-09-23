#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include "dns_monitor_exception.h"
#include <new>                     // For std::nothrow
#include <cstdlib>                 // For u_char
#include <iostream>

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) = 0;
    
protected:
    void printTimestamp(struct pcap_pkthdr* packet_header) const;
    void printIpAddress(const char* ip_address) const;
};

#endif // PACKET_WRITER_H