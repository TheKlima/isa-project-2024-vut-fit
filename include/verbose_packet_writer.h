#ifndef VERBOSE_PACKET_WRITER_H
#define VERBOSE_PACKET_WRITER_H

#include "packet_writer.h"
#include <iomanip>  // for std::setw and std::setfill

class Verbose_packet_writer : public Packet_writer {
public:
    Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;

protected:
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const override;
    virtual void printTimestamp(std::string_view timestamp) const override;
    virtual void printSrcDstIpAddresses() const override;
    virtual void printDnsHeader() const override;
    
private:
    void advancePtrToUdpHeader(const u_char** packet_data) const;
    void printSrcDstUdpPorts(const struct udphdr* udp_header) const;

};

#endif // VERBOSE_PACKET_WRITER_H