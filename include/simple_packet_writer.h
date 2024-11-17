#ifndef SIMPLE_PACKET_WRITER_H
#define SIMPLE_PACKET_WRITER_H

#include "packet_writer.h"

class Simple_packet_writer : public Packet_writer {
public:
    Simple_packet_writer(const char* domains_file_name, const char* translations_file_name);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
                             bool is_translations_file) override;
    
protected:
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const override;
    virtual void printTimestamp(std::string_view timestamp) const override;
    virtual void printSrcDstIpAddresses() const override;
    virtual void printDnsHeader() const override;
    virtual void processDnsQuestions(const u_char** packet_data, uint16_t questions_count, bool is_domains_file) override;
    virtual void processDnsRecords(const u_char** packet_data, uint16_t records_count, bool is_domains_file,
                                   bool is_translations_file, std::string_view section_name) override;

private:
    void skipDnsQuestion(const u_char** packet_data) const;
};

#endif // SIMPLE_PACKET_WRITER_H
