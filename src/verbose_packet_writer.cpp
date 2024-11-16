#include "verbose_packet_writer.h"
#include <netinet/udp.h>

Verbose_packet_writer::Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name)
        :
        Packet_writer(domains_file_name, translations_file_name)
{

}

void Verbose_packet_writer::printDnsRecordType(Dns_record_type dns_record_type) const
{
    switch (dns_record_type)
    {
        case Dns_record_type::A:
            std::cout << "A";
        case Dns_record_type::NS:
            std::cout << "NS";
        case Dns_record_type::CNAME:
            std::cout << "CNAME";
        case Dns_record_type::SOA:
            std::cout << "SOA";
        case Dns_record_type::MX:
            std::cout << "MX";
        case Dns_record_type::AAAA:
            std::cout << "AAAA";

        default: // SRV
        std::cout << "SRV";
    }
}

bool Verbose_packet_writer::isSupportedDnsRecordType(uint16_t dns_record_type) const
{
    switch (dns_record_type)
    {
        case static_cast<uint16_t> (Dns_record_type::A):
        case static_cast<uint16_t> (Dns_record_type::NS):
        case static_cast<uint16_t> (Dns_record_type::CNAME):
        case static_cast<uint16_t> (Dns_record_type::SOA):
        case static_cast<uint16_t> (Dns_record_type::MX):
        case static_cast<uint16_t> (Dns_record_type::AAAA):
        case static_cast<uint16_t> (Dns_record_type::SRV):
            return true;
            
        default:
            return false;
    }
}

void Verbose_packet_writer::processDnsQuestion(const u_char **packet_data)
{
    std::string domain_name{getQuestionDomainName(packet_data)};
    processDomainName(domain_name);

    uint16_t qtype = ntohs(*(reinterpret_cast<const uint16_t*>(*packet_data)));
    (*packet_data) += 2;

    uint16_t qclass = ntohs(*(reinterpret_cast<const uint16_t*>(*packet_data)));
    (*packet_data) += 2;
    
    if(!isSupportedDnsRecordType(qtype))
    {
        return;
    }
    
    // TODO check IN
    
    std::cout << domain_name << ' ';
    // TODO print IN
    printDnsRecordType(static_cast<Dns_record_type> (qtype));

//    std::cout << "[Question Section]" << std::endl;

}

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
                                        bool is_translations_file)
{
    printTimestamp(getTimestamp(packet_header));
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    advancePtrToUdpHeader(&packet_data);
    printSrcDstUdpPorts(reinterpret_cast<const struct udphdr*> (packet_data));
    advancePtrToDnsHeader(&packet_data);
    m_dns_header.fill(packet_data);
    printDnsHeader();
    processDnsQuestion(&packet_data);
}

void Verbose_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    (*packet_data) += UDP_HEADER_SIZE;
}

void Verbose_packet_writer::advancePtrToUdpHeader(const u_char** packet_data) const
{
    *packet_data += ETHER_HDR_LEN + getIpHeaderSize(*packet_data);
}

void Verbose_packet_writer::printTimestamp(std::string_view timestamp) const
{
    std::cout << "Timestamp: " << timestamp << std::endl;
}

void Verbose_packet_writer::printSrcDstIpAddresses() const
{
    std::cout << "SrcIP: " << m_src_ip << "\nDstIP: " << m_dst_ip << std::endl;
}

void Verbose_packet_writer::printSrcDstUdpPorts(const struct udphdr* udp_header) const
{
    std::cout << "SrcPort: UDP/" << ntohs(udp_header->source) << "\nDstPort: UDP/" << ntohs(udp_header->dest) << std::endl;
}

void Verbose_packet_writer::printDnsHeader() const
{
    std::cout << "Identifier: 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << m_dns_header.getId()
    << std::dec << "\nFlags: QR=" << m_dns_header.getQr() << ", OPCODE=" << m_dns_header.getOpcode() << ", AA=" <<
    m_dns_header.getAa() << ", TC=" << m_dns_header.getTc() << ", RD=" << m_dns_header.getRd() << ", RA=" << m_dns_header.getRa()
    << ", AD=" << m_dns_header.getAd() << ", CD=" << m_dns_header.getCd() << ", RCODE=" << m_dns_header.getRcode()
    << '\n' << std::endl;
}