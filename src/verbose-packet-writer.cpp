#include "verbose-packet-writer.h"
#include <netinet/udp.h>

Verbose_packet_writer::Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name)
    :
    Packet_writer(domains_file_name, translations_file_name),
    m_sections_delimiter{"===================="}
{

}

void Verbose_packet_writer::processDnsRecords(const u_char** packet_data, uint16_t records_count, std::string_view section_name)
{
    for(int i{records_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};

        auto qtype {getUint<uint16_t>(packet_data)};
        auto qclass {getUint<uint16_t>(packet_data)};

        if(i == records_count)
        {
            std::cout << '[' << section_name << " Section]" << std::endl;
        }

        if(!isSupportedDnsRecordType(qtype) || !isSupportedDnsClass(qclass))
        {
            continue;
        }
        
        if(isDomainsFile())
        {
            processDomainName(domain_name);
        }

        auto ttl {getUint<uint32_t>(packet_data)};
        
        (*packet_data) += 2;
        
        std::cout << domain_name <<  ". " << ttl << " IN " << getDnsRecordType(static_cast<Dns_record_type> (qtype)) << ' ';
        
        bool is_record_A{false};

        switch(qtype)
        {
            case static_cast<uint16_t> (Dns_record_type::A):
            case static_cast<uint16_t> (Dns_record_type::AAAA):
                is_record_A = (qtype == static_cast<uint16_t> (Dns_record_type::A));
                processRecordA(packet_data, domain_name, is_record_A);
                std::cout << getRecordIp() << std::endl;
                skipRecordIp(packet_data, is_record_A);
                break;
            case static_cast<uint16_t> (Dns_record_type::NS):
            case static_cast<uint16_t> (Dns_record_type::CNAME):
                domain_name = getDomainName(packet_data);

                if(isDomainsFile())
                {
                    processDomainName(domain_name);
                }

                std::cout << domain_name << '.' << std::endl;
                break;
            case static_cast<uint16_t> (Dns_record_type::SOA):
                domain_name = getDomainName(packet_data);

                if(isDomainsFile())
                {
                    processDomainName(domain_name);
                }

                std::cout << domain_name << ". " << getDomainName(packet_data) << ". " << getUint<uint32_t>(packet_data)
                        << ' ' << getUint<uint32_t>(packet_data) << ' ' << getUint<uint32_t>(packet_data) << ' ' <<
                        getUint<uint32_t>(packet_data) << ' ' << getUint<uint32_t>(packet_data) << ' ' << std::endl;
                
                break;
            case static_cast<uint16_t> (Dns_record_type::MX):
                std::cout << getUint<uint16_t>(packet_data) << ' ' << getDomainName(packet_data) << '.' << std::endl;
                break;
            default: // SRV
                
                break;
        }
    }

    if(records_count != 0)
    {
        std::cout << m_sections_delimiter << '\n' << std::endl;
    }
}

std::string Verbose_packet_writer::getDnsRecordType(Dns_record_type dns_record_type)
{
    switch (dns_record_type)
    {
        case Dns_record_type::A:
            return "A";
        case Dns_record_type::NS:
            return "NS";
        case Dns_record_type::CNAME:
            return "CNAME";
        case Dns_record_type::SOA:
            return "SOA";
        case Dns_record_type::MX:
            return "MX";
        case Dns_record_type::AAAA:
            return "AAAA";

        default: // SRV
            return "SRV";
    }
}

void Verbose_packet_writer::processDnsQuestions(const u_char **packet_data, uint16_t questions_count)
{
    for(int i{questions_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};

        if(isDomainsFile())
        {
            processDomainName(domain_name);
        }

        auto qtype {getUint<uint16_t>(packet_data)};
        auto qclass {getUint<uint16_t>(packet_data)};
        
        if(i == questions_count)
        {
            std::cout << "[Question Section]" << std::endl;
        }

        if(!isSupportedDnsRecordType(qtype) || !isSupportedDnsClass(qclass))
        {
            continue;
        }
        
        std::cout << domain_name << ". IN " << getDnsRecordType(static_cast<Dns_record_type> (qtype)) << std::endl;
    }

    std::cout << m_sections_delimiter << '\n' << std::endl;
}

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    printTimestamp(getTimestamp(packet_header));
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    advancePtrToUdpHeader(&packet_data);
    printSrcDstUdpPorts(reinterpret_cast<const struct udphdr*> (packet_data));
    advancePtrToDnsHeader(&packet_data);
    m_dns_header.fill(packet_data);
    printDnsHeader();
    advancePtrToDnsQuestion(&packet_data);
    processDnsQuestions(&packet_data, m_dns_header.getQdcount());
    processDnsRecords(&packet_data, m_dns_header.getAncount(), "Answer");
    processDnsRecords(&packet_data, m_dns_header.getNscount(), "Authority");
    processDnsRecords(&packet_data, m_dns_header.getArcount(), "Additional");
}

void Verbose_packet_writer::advancePtrToDnsHeader(const u_char** packet_data) const
{
    (*packet_data) += UDP_HEADER_SIZE;
}

void Verbose_packet_writer::advancePtrToUdpHeader(const u_char** packet_data) const
{
    *packet_data += ETHER_HDR_LEN + getIpHeaderSize(*packet_data);
}

void Verbose_packet_writer::printTimestamp(std::string_view timestamp) const
{
    std::cout << "Timestamp: " << timestamp << std::endl;
}

void Verbose_packet_writer::printSrcDstIpAddresses() const
{
    std::cout << "SrcIP: " << m_src_ip << "\nDstIP: " << m_dst_ip << std::endl;
}

//void Verbose_packet_writer::printSrcDstUdpPorts(const struct udphdr* udp_header)
//{
//    std::cout << "SrcPort: UDP/" << ntohs(udp_header->source) << "\nDstPort: UDP/" << ntohs(udp_header->dest) << std::endl;
//}

void Verbose_packet_writer::printSrcDstUdpPorts(const struct udphdr* udp_header)
{
    std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << "\nDstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
}


void Verbose_packet_writer::printDnsHeader() const
{
    std::cout << "Identifier: 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << m_dns_header.getId()
    << std::dec << "\nFlags: QR=" << m_dns_header.getQr() << ", OPCODE=" << m_dns_header.getOpcode() << ", AA=" <<
    m_dns_header.getAa() << ", TC=" << m_dns_header.getTc() << ", RD=" << m_dns_header.getRd() << ", RA=" << m_dns_header.getRa()
    << ", AD=" << m_dns_header.getAd() << ", CD=" << m_dns_header.getCd() << ", RCODE=" << m_dns_header.getRcode()
    << '\n' << std::endl;
}
