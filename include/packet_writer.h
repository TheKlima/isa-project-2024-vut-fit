#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include <new>     // For std::nothrow
#include <cstdlib> // For u_char

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;
    
private:
    bool printTimestamp(struct pcap_pkthdr* packet_header) const;
};

#endif // PACKET_WRITER_H