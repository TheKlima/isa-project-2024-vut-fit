#ifndef VERBOSE_PACKET_WRITER_H
#define VERBOSE_PACKET_WRITER_H

#include "packet_writer.h"

class Verbose_packet_writer : public Packet_writer {
public:
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;

protected:
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const override;
    virtual void printTimestamp(std::string_view timestamp) const override;
    
private:
    void advancePtrToUdpHeader(const u_char** packet_data) const;
    void processUdpHeader(const u_char* packet_data) const;

};

#endif // VERBOSE_PACKET_WRITER_H