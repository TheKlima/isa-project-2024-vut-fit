#ifndef SIMPLE_PACKET_WRITER_H
#define SIMPLE_PACKET_WRITER_H

#include "packet_writer.h"

class Simple_packet_writer : public Packet_writer {
public:
    Simple_packet_writer(const char* domains_file_name, const char* translations_file_name);
    void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) override;
    
protected:
    void advancePtrToDnsHeader(const u_char** packet_data) const override;
    void printTimestamp(std::string_view timestamp) const override;
    void printSrcDstIpAddresses() const override;
    void printDnsHeader() const override;
    void processDnsQuestions(const u_char** packet_data, uint16_t questions_count) override;
    void processDnsRecords(const u_char** packet_data, uint16_t records_count, std::string_view section_name) override;

private:
    void skipDnsQuestion(const u_char** packet_data) const;
};

#endif // SIMPLE_PACKET_WRITER_H
