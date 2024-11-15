#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include "dns_monitor_exception.h"
#include "dns-header.h"
#include <new>                     // For std::nothrow
#include <cstdlib>                 // For u_char
#include <arpa/inet.h>             // For inet_ntop
#include <netinet/ether.h>         // For Ethernet header (struct ether_header)
#include <iostream>
#include <fstream>
#include <vector>

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose, const char* domains_file_name, const char* translations_file_name);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data, bool is_domains_file,
            bool is_translations_file) = 0;
    virtual ~Packet_writer();
    bool getIsConstructorErr() const;
    
    static constexpr int UDP_HEADER_SIZE{8};
    
protected:
    Packet_writer(const char* domains_file_name, const char* translations_file_name);
    std::string getTimestamp(struct pcap_pkthdr* packet_header) const;
    std::string getQuestionDomainName(const u_char** packet_data) const;
    int getIpHeaderSize(const u_char* packet_data) const;
    void printIpAddress(const char* ip_address) const;
    void processIpHeader(const u_char* packet_data);
    void processDomainName(std::string& domain_name, std::vector<std::string> known_domains);
    void printSrcIp() const;
    void printDstIp() const;
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const = 0;
    virtual void printTimestamp(std::string_view timestamp) const = 0;
    virtual void printSrcDstIpAddresses() const = 0;
    virtual void printDnsHeader() const = 0;
    virtual void processDnsQuestion() const = 0;

    bool m_is_ipv4{};
    char m_src_ip[INET6_ADDRSTRLEN]{};
    char m_dst_ip[INET6_ADDRSTRLEN]{};
    Dns_header m_dns_header;
    
    std::ofstream m_domains_file{};
    std::ofstream m_translations_file{};

    bool m_is_constructor_err{};

private:
    void getSrcDstIpAddresses(const void* src_ip, const void* dst_ip);
    void createOutputFile(std::ofstream& output_file, const char* const file_name);
    void closeOutputFile(std::ofstream& output_file);
};

#endif // PACKET_WRITER_H

//void Dns_packet::processQuestion(const u_char** packet_data) {
//    std::string domain_name = "";
//
//    while (**packet_data != 0) {
//        uint8_t label_length = **packet_data;
//        (*packet_data)++;
//
//        if (!domain_name.empty()) {
//            domain_name += ".";
//        }
//
//        domain_name.append(reinterpret_cast<const char*>(*packet_data), label_length);
//        (*packet_data) += label_length;
//    }
//
//    // Move past the null byte (end of domain name)
//    (*packet_data)++;
//
//    // Now read the type (2 bytes)
//    uint16_t qtype = ntohs(*(reinterpret_cast<const uint16_t*>(*packet_data)));
//    (*packet_data) += 2;
//
//    // Now read the class (2 bytes)
//    uint16_t qclass = ntohs(*(reinterpret_cast<const uint16_t*>(*packet_data)));
//    (*packet_data) += 2;
//
//    // Print the domain name, type, and class
//    std::cout << "Domain: " << domain_name << std::endl;
//    std::cout << "Type: " << std::hex << "0x" << qtype << std::dec << std::endl;
//    std::cout << "Class: " << std::hex << "0x" << qclass << std::dec << std::endl;
//}