#include "verbose_packet_writer.h"
#include <netinet/udp.h>

Verbose_packet_writer::Verbose_packet_writer(const char* domains_file_name, const char* translations_file_name)
    :
    Packet_writer(domains_file_name, translations_file_name),
    m_sections_delimiter{"===================="}
{

}

void Verbose_packet_writer::processDnsRecords(const u_char** packet_data, uint16_t records_count, bool is_domains_file,
                               bool is_translations_file, std::string_view section_name)
{
    (void) is_domains_file;
    for(int i{records_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};

        uint16_t qtype = get16BitUint(packet_data);
        uint16_t qclass = get16BitUint(packet_data);

        if(i == records_count)
        {
            std::cout << '[' << section_name << " Section]" << std::endl;
        }

        if(!isSupportedDnsRecordType(qtype) || !isSupportedDnsClass(qclass))
        {
            continue;
        }
        
        if(is_domains_file && qtype)
        {
            processDomainName(domain_name);
        }

        uint32_t ttl = ntohs(*(reinterpret_cast<const uint32_t*>(*packet_data)));
        (*packet_data) += 4;

        uint16_t rdlength = get16BitUint(packet_data);
        (void) rdlength;
        
        std::cout << domain_name <<  ". " << ttl << " IN " << getDnsRecordType(static_cast<Dns_record_type> (qtype)) << ' ';
        
        bool is_record_A{false};

        switch(qtype)
        {
            case static_cast<uint16_t> (Dns_record_type::A):
            case static_cast<uint16_t> (Dns_record_type::AAAA):
                is_record_A = (qtype == static_cast<uint16_t> (Dns_record_type::A));
                processRecordA(packet_data, domain_name, is_record_A, is_domains_file, is_translations_file);
                std::cout << getRecordIp() << std::endl;
                skipRecordIp(packet_data, is_record_A);
                break;
            case static_cast<uint16_t> (Dns_record_type::NS):
            case static_cast<uint16_t> (Dns_record_type::CNAME):
                domain_name = getDomainName(packet_data);

                if(is_domains_file)
                {
                    processDomainName(domain_name);
                }

                std::cout << domain_name << std::endl;
                break;
            case static_cast<uint16_t> (Dns_record_type::SOA):
                break;
            case static_cast<uint16_t> (Dns_record_type::MX):
                std::cout << get16BitUint(packet_data) << ' ';
                domain_name = getDomainName(packet_data);
                std::cout << domain_name << std::endl;
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

std::string Verbose_packet_writer::getDnsRecordType(Dns_record_type dns_record_type) const
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

void Verbose_packet_writer::processDnsQuestions(const u_char **packet_data, uint16_t questions_count, bool is_domains_file)
{
    for(int i{questions_count}; i != 0; --i)
    {
        std::string domain_name{getDomainName(packet_data)};

        if(is_domains_file)
        {
            processDomainName(domain_name);
        }

        uint16_t qtype = get16BitUint(packet_data);
        uint16_t qclass = get16BitUint(packet_data);
        
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

void Verbose_packet_writer::printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
                                        bool is_translations_file)
{
    (void) is_domains_file; // TODO remove it
    (void) is_translations_file; // TODO remove it
    printTimestamp(getTimestamp(packet_header));
    processIpHeader(packet_data);
    printSrcDstIpAddresses();
    advancePtrToUdpHeader(&packet_data);
    printSrcDstUdpPorts(reinterpret_cast<const struct udphdr*> (packet_data));
    advancePtrToDnsHeader(&packet_data);
    m_dns_header.fill(packet_data);
    printDnsHeader();
    advancePtrToDnsQuestion(&packet_data);
    processDnsQuestions(&packet_data, m_dns_header.getQdcount(), is_domains_file);
    processDnsRecords(&packet_data, m_dns_header.getAncount(), is_domains_file, is_translations_file, "Answer");
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

void Verbose_packet_writer::printSrcDstUdpPorts(const struct udphdr* udp_header) const
{
    std::cout << "SrcPort: UDP/" << ntohs(udp_header->source) << "\nDstPort: UDP/" << ntohs(udp_header->dest) << std::endl;
}

void Verbose_packet_writer::printDnsHeader() const
{
    std::cout << "Identifier: 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << m_dns_header.getId()
    << std::dec << "\nFlags: QR=" << m_dns_header.getQr() << ", OPCODE=" << m_dns_header.getOpcode() << ", AA=" <<
    m_dns_header.getAa() << ", TC=" << m_dns_header.getTc() << ", RD=" << m_dns_header.getRd() << ", RA=" << m_dns_header.getRa()
    << ", AD=" << m_dns_header.getAd() << ", CD=" << m_dns_header.getCd() << ", RCODE=" << m_dns_header.getRcode()
    << '\n' << std::endl;
}
