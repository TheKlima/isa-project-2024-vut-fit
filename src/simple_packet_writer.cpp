#include "simple_packet_writer.h"

void Simple_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    std::cout << ' ' << std::flush;              // TODO make a function from it
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    std::cout << ' ' << std::flush;
    advancePtrToDnsHeader(&packet_data);
    dns_header.fill(packet_data);
    printDnsHeader();
}

void Simple_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    (*packet_data) += ETHER_HDR_LEN + getIpHeaderSize(*packet_data) + UDP_HEADER_SIZE;
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
    std::cout << "(" << (dns_header.getQr() ? 'R' : 'Q') << ' ' << dns_header.getQdcount() << '/'
    << dns_header.getAncount() << '/' << dns_header.getNscount() << '/' << dns_header.getArcount() << ')' << std::endl;
}