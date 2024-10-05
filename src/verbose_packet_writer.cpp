#include "verbose_packet_writer.h"
#include <netinet/udp.h>

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    advancePtrToUdpHeader(&packet_data);
    printSrcDstUdpPorts(reinterpret_cast<const struct udphdr*> (packet_data));
    advancePtrToDnsHeader(&packet_data);
    dns_header.create(packet_data);
    printDnsHeader();
}

void Verbose_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    ++(*packet_data);
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
    std::cout << "Flags:  QR=" << dns_header.getQr() << ", OPCODE=" << dns_header.getOpcode() << ", AA=" <<
    dns_header.getAa() << ", TC=" << dns_header.getTc() << ", RD=" << dns_header.getRd() << "RA=" << dns_header.getRa()
    << ", AD=" << dns_header.getAd() << ", CD=" << dns_header.getCd() << ", RCODE=" << dns_header.getRcode()
    << '\n' << std::endl;
}