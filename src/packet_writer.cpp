#include "packet_writer.h"
#include "verbose_packet_writer.h"
#include "simple_packet_writer.h"
#include <ctime>                    // For localtime() and strftime()
#include <pcap/pcap.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

void Packet_writer::processDomainName(std::string& domain_name)
{
    for(const auto& i : m_known_domains)
    {
        if(domain_name.find(i) != std::string::npos)
        {
            return;
        }
    }
    
    m_domains_file << domain_name << std::endl;
    m_known_domains.push_back(domain_name);
}

void Packet_writer::advancePtrToDnsQuestion(const u_char** packet_data) const
{
    (*packet_data) += 12;
}

std::string Packet_writer::getQuestionDomainName(const u_char** packet_data) const
{
    std::string domain_name{};

    while(true)
    {
        uint8_t label_length{**packet_data};
        ++(*packet_data);
        
        domain_name.append(reinterpret_cast<const char*>(*packet_data), label_length);
        (*packet_data) += label_length;
        
        if(**packet_data == '\0')
        {
            ++(*packet_data);
            return domain_name;
        }

        domain_name.push_back('.');
    }
}

bool Packet_writer::getIsConstructorErr() const
{
    return m_is_constructor_err;
}

Packet_writer::Packet_writer(const char* domains_file_name, const char* translations_file_name)
    :
    m_is_constructor_err{false}
{
    createOutputFile(m_domains_file, domains_file_name);
    createOutputFile(m_translations_file, translations_file_name);
    
    if(!m_domains_file || !m_translations_file)
    {
        m_is_constructor_err = true;
    }
}

void Packet_writer::closeOutputFile(std::ofstream& output_file)
{
    if(output_file.is_open())
    {
        output_file.close();
    }
}

Packet_writer::~Packet_writer()
{
    closeOutputFile(m_domains_file);
    closeOutputFile(m_translations_file);
}

void Packet_writer::createOutputFile(std::ofstream& output_file, const char* file_name)
{
    if(file_name)
    {
        output_file.open(file_name);
    }
}

Packet_writer* Packet_writer::create(bool is_verbose, const char* domains_file_name, const char* translations_file_name)
{
    if(is_verbose)
    {
        return new Verbose_packet_writer{domains_file_name, translations_file_name};
    }

    return new Simple_packet_writer{domains_file_name, translations_file_name};
}

std::string Packet_writer::getTimestamp(struct pcap_pkthdr* packet_header) const
{
    struct tm* local_time{localtime(&(packet_header->ts.tv_sec))};

    if(!local_time)
    {
        throw Dns_monitor_exception{"Error! local_time() has failed."};
    }

    char timestamp_buffer[20]{0, };
    strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d %H:%M:%S", local_time);
    
    return std::string{timestamp_buffer};
}

void Packet_writer::printIpAddress(const char* ip_address) const
{
    if(!ip_address)
    {
        throw Dns_monitor_exception{"Error! inet_ntop() has failed."};
    }
    
    std::cout << ip_address << std::flush;
}

void Packet_writer::processIpHeader(const u_char* packet_data)
{
    const struct ether_header* ethernet_header{reinterpret_cast<const struct ether_header*> (packet_data)};

    uint16_t ethernet_type = ntohs(ethernet_header->ether_type);

    const struct ip* ipv4_header{nullptr};
    const struct ip6_hdr* ipv6_header{nullptr};

    switch(ethernet_type)
    {
        case ETHERTYPE_IP:
            m_is_ipv4 = true;
            ipv4_header = reinterpret_cast<const struct ip*> (packet_data + ETHER_HDR_LEN);
            getSrcDstIpAddresses(&(ipv4_header->ip_src), &(ipv4_header->ip_dst));
            return;
            
        case ETHERTYPE_IPV6:
            m_is_ipv4 = false;
            ipv6_header = reinterpret_cast<const struct ip6_hdr*> (packet_data + ETHER_HDR_LEN);
            getSrcDstIpAddresses(&(ipv6_header->ip6_src), &(ipv6_header->ip6_dst));
            return;
            
        default:
            throw Dns_monitor_exception{"Error! Unsupported link layer protocol: expecting only IPv4 or IPv6."};
    }
}

void Packet_writer::getSrcDstIpAddresses(const void* src_ip, const void* dst_ip)
{
    int address_family{m_is_ipv4 ? AF_INET : AF_INET6};

    if(!inet_ntop(address_family, src_ip, m_src_ip, INET6_ADDRSTRLEN) ||
       !inet_ntop(address_family, dst_ip, m_dst_ip, INET6_ADDRSTRLEN))
    {
        throw Dns_monitor_exception{"Error! inet_ntop() has failed."};
    }
}

void Packet_writer::printSrcIp() const
{
    std::cout << m_src_ip << std::flush;
}
void Packet_writer::printDstIp() const
{
    std::cout << m_dst_ip << std::flush;
}

int Packet_writer::getIpHeaderSize(const u_char* packet_data) const
{
    if(m_is_ipv4)
    {
        return ((reinterpret_cast<const struct ip*> (packet_data + ETHER_HDR_LEN))->ip_hl * 4);
    }
    
    return sizeof(struct ip6_hdr);
}