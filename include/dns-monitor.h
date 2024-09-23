#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include "args.h"
#include "packet_writer.h"
#include <pcap/pcap.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip6.h>

class Dns_monitor {
public:
    Dns_monitor(int argc, char** argv);
    ~Dns_monitor();
    void printErrBuff() const;
    bool getIsConstructorErr() const;
    bool run();
    
private:
    Args m_args;
    Packet_writer* m_packet_writer;
    bool m_is_constructor_err{};
    char m_err_buff[PCAP_ERRBUF_SIZE]{};
    pcap_t* m_pcap_handle{};
    const char* const m_dns_filter{};
    
    void createPcapHandle();
};

#endif // DNS_MONITOR_H