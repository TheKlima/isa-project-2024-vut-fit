#include "simple_packet_writer.h"

Simple_packet_writer::Simple_packet_writer(const char* domains_file_name, const char* translations_file_name)
    :
    Packet_writer(domains_file_name, translations_file_name)
{
    
}

void Simple_packet_writer::skipDnsQuestion(const u_char** packet_data) const
{
    while(**packet_data != '\0')
    {
        uint8_t label_length{**packet_data};
        (*packet_data) += 1 + label_length;
    }
    
    (*packet_data) += 5;
}

void Simple_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
                                       bool is_translations_file)
{
    printTimestamp(getTimestamp(packet_header));
    std::cout << ' ' << std::flush;              // TODO make a function from it
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    std::cout << ' ' << std::flush;
    advancePtrToDnsHeader(&packet_data);
    m_dns_header.fill(packet_data);
    printDnsHeader();

    if(is_domains_file)
    {
        processDnsQuestion(&packet_data);
    }
    else
    {
        skipDnsQuestion(&packet_data);
    }
}

void Simple_packet_writer::processDnsQuestion(const u_char** packet_data)
{
    std::string domain_name{getQuestionDomainName(packet_data)};
    processDomainName(domain_name);
    (*packet_data) += 4;
}

void Simple_packet_writer::printTimestamp(std::string_view timestamp) const
{
    std::cout << timestamp << std::flush;
}

void Simple_packet_writer::printSrcDstIpAddresses() const
{
    std::cout << m_src_ip << " -> " << m_dst_ip << std::flush;
}

void Simple_packet_writer::printDnsHeader() const
{
    std::cout << "(" << (m_dns_header.getQr() ? 'R' : 'Q') << ' ' << m_dns_header.getQdcount() << '/'
    << m_dns_header.getAncount() << '/' << m_dns_header.getNscount() << '/' << m_dns_header.getArcount() << ')' << std::endl;
}
