#ifndef VERBOSE_PACKET_WRITER_H
#define VERBOSE_PACKET_WRITER_H

#include "packet_writer.h"
#include <iomanip>  // for std::setw and std::setfill

class Verbose_packet_writer : public Packet_writer {
public:
    Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
                             bool is_translations_file) override;

protected:
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const override;
    virtual void printTimestamp(std::string_view timestamp) const override;
    virtual void printSrcDstIpAddresses() const override;
    virtual void printDnsHeader() const override;
    virtual void processDnsQuestion(const u_char** packet_data, bool is_domains_file) override;
    
private:
    enum class Dns_record_type {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        MX = 15,
        AAAA = 28,
        SRV = 33
    };


    void advancePtrToUdpHeader(const u_char** packet_data) const;
    void printSrcDstUdpPorts(const struct udphdr* udp_header) const;
    void printDnsRecordType(Dns_record_type dns_record_type) const;
    void printDnsSectionsDelimiter() const;
    bool isSupportedDnsRecordType(uint16_t dns_record_type) const;
    bool isSupportedDnsClass(uint16_t dns_class) const;
};

#endif // VERBOSE_PACKET_WRITER_H