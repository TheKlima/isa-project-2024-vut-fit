/**
 * DNS monitor
 * 
 * @brief Definition of the abstract class representing DNS packets writer
 * @file packet-writer.h
 * @author Andrii Klymenko <xklyme00>
 */

#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include "dns-monitor-exception.h"
#include "dns-header.h"
#include <new>                     // For std::nothrow
#include <cstdlib>                 // For u_char
#include <arpa/inet.h>             // For inet_ntop
#include <sys/socket.h>            // For sockaddr
#include <netinet/if_ether.h>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose, const char* domains_file_name, const char* translations_file_name);
    virtual void printPacket(struct pcap_pkthdr* packet_header, const u_char* packet_data) = 0;
    virtual ~Packet_writer();
    bool getIsConstructorErr() const;
    
    static constexpr int UDP_HEADER_SIZE{8};
    
protected:
    Packet_writer(const char* domains_file_name, const char* translations_file_name);
    std::string getDomainName(const u_char** packet_data) const;
    const char* getRecordIp() const;
    int getIpHeaderSize(const u_char* packet_data) const;
    bool isDomainsFile() const;
    bool isTranslationsFile() const;
    static std::string getTimestamp(struct pcap_pkthdr* packet_header);
//    static uint16_t get16BitUint(const u_char** packet_data);
//    static uint32_t get32BitUint(const u_char** packet_data);
    static bool isSupportedDnsRecordType(uint16_t dns_record_type);
    static bool isSupportedDnsClass(uint16_t dns_class);
    static void skipRecordIp(const u_char** packet_data, bool is_ipv4);
    static void advancePtrToDnsQuestion(const u_char** packet_data);
    //    void printIpAddress(const char* ip_address) const;
    void processIpHeader(const u_char* packet_data);
    void processDomainName(std::string& domain_name);
//    void printSrcIp() const;
//    void printDstIp() const;
    void processRecordA(const u_char** packet_data, std::string& domain_name, bool is_ipv4);
    virtual void advancePtrToDnsHeader(const u_char** packet_data) const = 0;
    virtual void printTimestamp(std::string_view timestamp) const = 0;
    virtual void printSrcDstIpAddresses() const = 0;
    virtual void printDnsHeader() const = 0;
    virtual void processDnsQuestions(const u_char** packet_data, uint16_t questions_count) = 0;
    virtual void processDnsRecords(const u_char** packet_data, uint16_t records_count, std::string_view section_name) = 0;
    virtual void processNsCnameRecord(const u_char** packet_data, std::string& domain_name) = 0;
    virtual void processSoaRecord(const u_char** packet_data, std::string& domain_name) = 0;
    virtual void processMxRecord(const u_char** packet_data) = 0;
    virtual void processSrvRecord(const u_char** packet_data, std::string& domain_name) = 0;

    template <typename T>
    T getUint(const u_char** packet_data)
    {
        T value = (sizeof(T) == 2) ? ntohs(*(reinterpret_cast<const T*>(*packet_data)))
                                   : ntohl(*(reinterpret_cast<const T*>(*packet_data)));
        (*packet_data) += sizeof(T);
        return value;
    }


    char m_src_ip[INET6_ADDRSTRLEN]{};
    char m_dst_ip[INET6_ADDRSTRLEN]{};
    char m_record_ip[INET6_ADDRSTRLEN]{};
    Dns_header m_dns_header;
    
    std::ofstream m_domains_file{};
    std::ofstream m_translations_file{};

    bool m_is_constructor_err{};
    std::unordered_map<std::string, std::set<std::string>> m_known_domains_translations{};
    
    enum class Dns_record_type {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        MX = 15,
        AAAA = 28,
        SRV = 33
    };

private:
    void getSrcDstIpAddresses(const void* src_ip, const void* dst_ip);
    static void createOutputFile(std::ofstream& output_file, const char* const file_name);
    static void closeOutputFile(std::ofstream& output_file);
    void fillRecordIp(const u_char* packet_data, bool is_ipv4);

    bool m_is_ipv4{};
};

#endif // PACKET_WRITER_H
