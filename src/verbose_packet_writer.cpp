#include "verbose_packet_writer.h"

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    std::cout << "Timestamp: " << std::flush;
    printTimestamp(packet_header);
    processIpHeader(packet_data);
    std::cout << "\nSrcIP: " << std::flush;
    printSrcIp();
    std::cout << "\nDstIP: " << std::flush;
    printDstIp();
    std::cout << "\nSrcPort: UDP/" << std::flush;
    std::cout << "\n\n";
}

void Verbose_packet_writer::advancePtrToDnsHeader(const u_char** packet_data)
{
    ++(*packet_data);
}

void Verbose_packet_writer::advancePtrToUdpHeader(const u_char** packet_data)
{
    *packet_data += ETHER_HDR_LEN + getIpHeaderSize(*packet_data);
}