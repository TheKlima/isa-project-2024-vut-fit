#include "packet-writer.h"
#include "verbose-packet-writer.h"
#include "simple-packet-writer.h"
#include <ctime>                    // For localtime() and strftime()
#include <pcap/pcap.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

void Packet_writer::processDomainName(std::string& domain_name)
{
    if((isDomainsFile() || isTranslationsFile()) && !m_known_domains_translations.contains(domain_name))
    {
        if(isDomainsFile())
        {
            m_domains_file << domain_name << std::endl;
        }
        
        m_known_domains_translations[domain_name] = std::set<std::string>{};
    }
}

bool Packet_writer::isDomainsFile() const
{
    return m_domains_file.is_open();
}

bool Packet_writer::isTranslationsFile() const
{
    return m_translations_file.is_open();
}

bool Packet_writer::isSupportedDnsClass(uint16_t dns_class)
{
    return dns_class == 1; // IN
}

bool Packet_writer::isSupportedDnsRecordType(uint16_t dns_record_type)
{
    switch (dns_record_type)
    {
        case static_cast<uint16_t> (Dns_record_type::A):
        case static_cast<uint16_t> (Dns_record_type::NS):
        case static_cast<uint16_t> (Dns_record_type::CNAME):
        case static_cast<uint16_t> (Dns_record_type::SOA):
        case static_cast<uint16_t> (Dns_record_type::MX):
        case static_cast<uint16_t> (Dns_record_type::AAAA):
        case static_cast<uint16_t> (Dns_record_type::SRV):
            return true;

        default:
            return false;
    }
}

void Packet_writer::skipRecordIp(const u_char** packet_data, bool is_ipv4)
{
    (*packet_data) += is_ipv4 ? 4 : 16;
}

const char* Packet_writer::getRecordIp() const
{
    return m_record_ip;
}

void Packet_writer::processRecordA(const u_char** packet_data, std::string& domain_name, bool is_ipv4)
{
    fillRecordIp(*packet_data, is_ipv4);
    
    if(isDomainsFile() || isTranslationsFile())
    {
        if(!m_known_domains_translations.contains(domain_name))
        {
            m_known_domains_translations[domain_name] = std::set<std::string>{m_record_ip};

            if(isDomainsFile())
            {
                m_domains_file << domain_name << std::endl;
            }
            
            if(isTranslationsFile())
            {
                m_translations_file << domain_name << ' ' << m_record_ip << std::endl;
            }
        }
        else
        {
            if(!m_known_domains_translations[domain_name].contains(m_record_ip))
            {
                m_known_domains_translations[domain_name].insert(m_record_ip);
                
                if(isTranslationsFile())
                {
                    m_translations_file << domain_name << ' ' << m_record_ip << std::endl;
                }
            }
        }
    }
}

void Packet_writer::fillRecordIp(const u_char* packet_data, bool is_ipv4)
{
    int address_family{is_ipv4 ? AF_INET : AF_INET6};

    if(!inet_ntop(address_family, packet_data, m_record_ip, INET6_ADDRSTRLEN))
    {
        throw Dns_monitor_exception{"Error! inet_ntop() has failed."};
    }
}

void Packet_writer::advancePtrToDnsQuestion(const u_char** packet_data)
{
    (*packet_data) += 12;
}

std::string Packet_writer::getDomainName(const u_char** packet_data) const
{
    std::string domain_name{};
    const u_char* original_data{*packet_data};
    bool is_compressed{false};

    while(true)
    {
        uint8_t label_length{**packet_data};

        // Check for pointer (two leading bits set to 1)
        if((label_length & 0xC0) == 0xC0)
        {
            if(!is_compressed)
            {
                // First time encountering a pointer; mark original position to restore later
                original_data = *packet_data + 2;
                is_compressed = true;
            }

            // Read the 14-bit offset
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t*>(*packet_data)) & 0x3FFF;
            *packet_data = m_dns_header.getPtr() + offset;
            label_length = **packet_data;
        }
        
        // Append label to domain name
        ++(*packet_data);  // Move past the length byte
        domain_name.append(reinterpret_cast<const char*>(*packet_data), label_length);
        (*packet_data) += label_length;

        if(**packet_data == 0)
        {
            if(is_compressed)
            {
                *packet_data = original_data;
            }
            else
            {
                ++(*packet_data);
            }

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

std::string Packet_writer::getTimestamp(struct pcap_pkthdr* packet_header)
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

int Packet_writer::getIpHeaderSize(const u_char* packet_data) const
{
    if(m_is_ipv4)
    {
        return ((reinterpret_cast<const struct ip*> (packet_data + ETHER_HDR_LEN))->ip_hl * 4);
    }
    
    return sizeof(struct ip6_hdr);
}
