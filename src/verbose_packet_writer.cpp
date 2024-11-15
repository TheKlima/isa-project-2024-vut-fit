#include "verbose_packet_writer.h"
#include <netinet/udp.h>

Verbose_packet_writer::Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name)
        :
        Packet_writer(domains_file_name, translations_file_name)
{

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