#include "simple_packet_writer.h"

void Simple_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    std::cout << ' ' << std::flush;              // TODO make a function from it
    processIpHeader(packet_data);
    printSrcIp();
    std::cout << " -> " << std::flush;
    printDstIp();
    std::cout << " (" << std::flush;
    std::cout << ')' << std::endl;
}

void Simple_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    *packet_data += ETHER_HDR_LEN + getIpHeaderSize(*packet_data) + 1;
}

void Simple_packet_writer::printTimestamp(std::string_view timestamp) const
{
    std::cout << timestamp << std::flush;
}