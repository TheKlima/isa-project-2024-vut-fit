#ifndef SIMPLE_PACKET_WRITER_H
#define SIMPLE_PACKET_WRITER_H

#include "packet_writer.h"

class Simple_packet_writer : public Packet_writer {
public:
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;
};

#endif // SIMPLE_PACKET_WRITER_H