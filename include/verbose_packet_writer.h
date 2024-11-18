#ifndef VERBOSE_PACKET_WRITER_H
#define VERBOSE_PACKET_WRITER_H

#include "packet_writer.h"
#include <iomanip>  // for std::setw and std::setfill

class Verbose_packet_writer : public Packet_writer {
public:
    Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name);
    void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;

protected:
    void advancePtrToDnsHeader(const u_char** packet_data) const override;
    void printTimestamp(std::string_view timestamp) const override;
    void printSrcDstIpAddresses() const override;
    void printDnsHeader() const override;
    void processDnsQuestions(const u_char** packet_data, uint16_t questions_count) override;
    void processDnsRecords(const u_char** packet_data, uint16_t records_count, std::string_view section_name) override;
    
private:
    
    void advancePtrToUdpHeader(const u_char** packet_data) const;
    static void printSrcDstUdpPorts(const struct udphdr* udp_header);
//    void printDnsSectionsDelimiter() const;
    static std::string getDnsRecordType(Dns_record_type dns_record_type);
    
    const char* m_sections_delimiter{};
};

#endif // VERBOSE_PACKET_WRITER_H
