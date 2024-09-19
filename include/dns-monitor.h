#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include "args.h"
#include <pcap/pcap.h>
#include <cstring>

class Dns_monitor {
public:
    Dns_monitor(int argc, char** argv);
    
    bool getIsConstructorErr() const;
    
private:
    Args m_args;
    bool m_is_constructor_err{};
    char m_err_buff[PCAP_ERRBUF_SIZE]{};
    pcap_t* m_pcap_handle{};
    const char* const m_dns_filter{};



    bool createPcapHandle();
};

#endif // DNS_MONITOR_H