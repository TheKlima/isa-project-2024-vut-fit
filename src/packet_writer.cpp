#include "packet_writer.h"
#include "verbose_packet_writer.h"
#include "simple_packet_writer.h"
#include <ctime>                    // For localtime() and strftime()
#include <iostream>

Packet_writer* Packet_writer::create(bool is_verbose)
{
    if(is_verbose)
    {
        return new(std::nothrow) Verbose_packet_writer;
    }

    return new(std::nothrow) Simple_packet_writer;
}

bool Packet_writer::printTimestamp(struct pcap_pkthdr* packet_header) const
{
    struct tm* local_time{localtime(&(packet_header->ts.tv_sec))};

    if(local_time == NULL)
    {
        return false;
    }

    char timestamp_buffer[20]{0, };
    strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d %H:%M:%S", local_time);
    
    std::cout << timestamp_buffer;
    return true;
}