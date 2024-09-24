#include "packet_writer.h"
#include "verbose_packet_writer.h"
#include "simple_packet_writer.h"
#include <ctime>                    // For localtime() and strftime()

Packet_writer* Packet_writer::create(bool is_verbose)
{
    if(is_verbose)
    {
        return new(std::nothrow) Verbose_packet_writer;
    }

    return new(std::nothrow) Simple_packet_writer;
}

void Packet_writer::printTimestamp(struct pcap_pkthdr* packet_header) const
{
    struct tm* local_time{localtime(&(packet_header->ts.tv_sec))};

    if(!local_time)
    {
        throw Dns_monitor_exception{"Error! local_time() has failed."};
    }

    char timestamp_buffer[20]{0, };
    strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d %H:%M:%S", local_time);
    
    std::cout << timestamp_buffer << std::flush;
}

void Packet_writer::printIpAddress(const char* ip_address) const
{
    if(!ip_address)
    {
        throw Dns_monitor_exception{"Error! inet_ntop() has failed."};
    }
    
    std::cout << ip_address << std::flush;
}

void Packet_writer::getSrcDstIpAddresses(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    const struct ether_header* ethernet_header{reinterpret_cast<const struct ether_header*> (packet_data)};

    uint16_t ethernet_type = ntohs(ethernet_header->ether_type);

    switch(ethernet_type)
    {
        case ETHERTYPE_IP:
            m_is_ipv4 = true;
            getSrcDstIpv4Addresses(reinterpret_cast<struct ip*> (packet_data + ETHER_HDR_LEN));
            return;
        case ETHERTYPE_IPV6:
            m_is_ipv4 = false;
            getSrcDstIpv6Addresses(reinterpret_cast<struct ip6_hdr*> (packet_data + ETHER_HDR_LEN));
            return;
        default:
            throw Dns_monitor_exception{"Error! Unsupported link layer protocol: expecting only IPv4 or IPv6."};
    }
}