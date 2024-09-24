#include "simple_packet_writer.h"

void Simple_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(packet_header);
    std::cout << ' ';
}