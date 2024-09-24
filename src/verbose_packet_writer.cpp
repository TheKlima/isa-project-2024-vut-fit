#include "verbose_packet_writer.h"

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    std::cout << "Timestamp: " << std::flush;
    printTimestamp(packet_header);
    std::cout << "\nSrcIP: " << std::flush;
    printSrcIp();
    std::cout << "\nDstIP: " << std::flush;
    printDstIp();
    std::cout << "\nSrcPort: UDP/" << std::flush;
    std::cout << "\n\n";
}