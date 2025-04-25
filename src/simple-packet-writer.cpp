/**
 * DNS monitor
 * 
 * @brief Implementation of the Simple_packet_writer class
 * @file packet-writer.cpp
 * @author Andrii Klymenko <xklyme00>
 */

#include "simple-packet-writer.h"

Simple_packet_writer::Simple_packet_writer(const char* domains_file_name, const char* translations_file_name)
        :
        Packet_writer(domains_file_name, translations_file_name)
{

}

void Simple_packet_writer::processNsCnameRecord(const u_char** packet_data, std::string& domain_name)
{
    domain_name = getDomainName(packet_data);
    processDomainName(domain_name);
}

void Simple_packet_writer::processSoaRecord(const u_char** packet_data, std::string& domain_name)
{
    domain_name = getDomainName(packet_data);
    processDomainName(domain_name);
    getDomainName(packet_data);
    (*packet_data) += 20;
}

void Simple_packet_writer::processMxRecord(const u_char** packet_data)
{
    (*packet_data) += 2;
    getDomainName(packet_data);
}

void Simple_packet_writer::processSrvRecord(const u_char** packet_data, std::string& domain_name)
{
    (*packet_data) += 6;

    domain_name = getDomainName(packet_data);

    processDomainName(domain_name);
}

void Simple_packet_writer::processDnsRecords(const u_char** packet_data, uint16_t records_count, std::string_view section_name)
{
    (void) section_name;
    
    for(int i{records_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};

        auto qtype {getUint<uint16_t>(packet_data)};
        auto qclass {getUint<uint16_t>(packet_data)};
        
        (*packet_data) += 4;
        auto rdlength{getUint<uint16_t>(packet_data)};

        if(!isSupportedDnsRecordType(qtype) || !isSupportedDnsClass(qclass))
        {
            (*packet_data) += rdlength;
            continue;
        }

        processDomainName(domain_name);

        bool is_record_A{false};
        
        switch(qtype)
        {
            case static_cast<uint16_t> (Dns_record_type::A):
            case static_cast<uint16_t> (Dns_record_type::AAAA):
                is_record_A = (qtype == static_cast<uint16_t> (Dns_record_type::A));
                processRecordA(packet_data, domain_name, is_record_A);
                skipRecordIp(packet_data, is_record_A);
                break;
                
            case static_cast<uint16_t> (Dns_record_type::NS):
            case static_cast<uint16_t> (Dns_record_type::CNAME):
                processNsCnameRecord(packet_data, domain_name);
                break;
                
            case static_cast<uint16_t> (Dns_record_type::SOA):
                processSoaRecord(packet_data, domain_name);
                break;
                
            case static_cast<uint16_t> (Dns_record_type::MX):
                processMxRecord(packet_data);
                break;

            default: // SRV
                processSrvRecord(packet_data, domain_name);
                break;
        }
    }
}

void Simple_packet_writer::skipDnsQuestion(const u_char** packet_data)
{
    while(**packet_data != '\0')
    {
        uint8_t label_length{**packet_data};
        (*packet_data) += 1 + label_length;
    }

    (*packet_data) += 5;
}

void Simple_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    std::cout << ' ';
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    std::cout << ' ';
    advancePtrToDnsHeader(&packet_data);
    m_dns_header.fill(packet_data);
    printDnsHeader();
    advancePtrToDnsQuestion(&packet_data);

    if(isDomainsFile())
    {
        processDnsQuestions(&packet_data, m_dns_header.getQdcount());
    }
    else
    {
        skipDnsQuestion(&packet_data);
    }

    processDnsRecords(&packet_data, m_dns_header.getAncount(), "Answer");
    processDnsRecords(&packet_data, m_dns_header.getNscount(), "Authority");
    processDnsRecords(&packet_data, m_dns_header.getArcount(), "Additional");
}

void Simple_packet_writer::processDnsQuestions(const u_char** packet_data, uint16_t questions_count)
{
    for(int i{questions_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};
        
        auto qtype {getUint<uint16_t>(packet_data)};
        auto qclass {getUint<uint16_t>(packet_data)};

        if(isSupportedDnsRecordType(qtype) && isSupportedDnsClass(qclass))
        {
            processDomainName(domain_name);
        }
    }
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
    std::cout << "(" << (m_dns_header.getQr() ? 'R' : 'Q') << ' ' << m_dns_header.getQdcount() << '/'
              << m_dns_header.getAncount() << '/' << m_dns_header.getNscount() << '/' << m_dns_header.getArcount() << ')' << std::endl;
}

void Simple_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    (*packet_data) += ETHER_HDR_LEN + getIpHeaderSize(*packet_data) + UDP_HEADER_SIZE;
}
