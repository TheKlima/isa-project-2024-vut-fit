#include "verbose_packet_writer.h"
#include <netinet/udp.h>

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    processIpHeader(packet_data);
    std::cout << "\nSrcIP: " << std::flush;
    printSrcIp();
    std::cout << "\nDstIP: " << std::flush;
    printDstIp();
    advancePtrToUdpHeader(&packet_data);
    processUdpHeader(packet_data);
    advancePtrToDnsHeader(&packet_data);
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

void Verbose_packet_writer::processUdpHeader(const u_char* packet_data) const
{
    const struct udphdr* udp_header{reinterpret_cast<const struct udphdr*> (packet_data)};
    std::cout << "\nSrcPort: UDP/" << ntohs(udp_header->source) << "\nDstPort: UDP/" <<  std::flush;
//    printPortNumber(ntohs(udp_header->source));
//    std::cout << "\nDstPort: UDP/" << std::flush;
//    printPortNumber(ntohs(udp_header->dest));
}