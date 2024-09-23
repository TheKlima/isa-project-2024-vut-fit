#include "dns-monitor.h"

Dns_monitor::Dns_monitor(int argc, char **argv)
    :
    m_args{argc, argv},
    m_packet_writer{Packet_writer::create(m_args.getIsVerbose())},
    m_is_constructor_err{false},
    m_err_buff{0, },
    m_pcap_handle{nullptr},
    m_dns_filter{"udp port 53"}
{
    if(!m_packet_writer || !createPcapHandle())
    {
        if(!m_packet_writer)
        {
            strcpy(m_err_buff, "Error! operator 'new' has failed: couldn't allocate memory on heap for Packet_writer object.\n");
        }
        
        m_is_constructor_err = true;
    }
}

Dns_monitor::~Dns_monitor()
{
    if(m_packet_writer)
    {
        delete m_packet_writer;
    }
    
    if(m_pcap_handle)
    {
        pcap_close(m_pcap_handle);
    }
}

// preparation before processing DNS packets
// inspired by: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#process-packets
bool Dns_monitor::createPcapHandle()
{
    bpf_u_int32 net_mask{0};
    bpf_u_int32 src_ip{0};

    if(m_args.getSniffingFromInterface())
    {
        // get network device source IP address and netmask
        if(pcap_lookupnet(m_args.getPacketsSource(), &src_ip, &net_mask, m_err_buff) == PCAP_ERROR)
        {
            return false;
        }

        // open the device for live capture
        m_pcap_handle = pcap_open_live(m_args.getPacketsSource(), BUFSIZ, 1, 100, m_err_buff);
    }
    else
    {
        m_pcap_handle = pcap_open_offline(m_args.getPacketsSource(), m_err_buff);
    }
    
    if(!m_pcap_handle)
    {
        return false;
    }

    struct bpf_program bpf{};
    
    // convert the packet filter expression into a packet filter binary
    if(pcap_compile(m_pcap_handle, &bpf, m_dns_filter, 0, net_mask) == PCAP_ERROR)
    {
        strcpy(m_err_buff, pcap_geterr(m_pcap_handle));
        return false;
    }

    // bind the packet filter to the libpcap handle
    if(pcap_setfilter(m_pcap_handle, &bpf) == PCAP_ERROR)
    {
        strcpy(m_err_buff, pcap_geterr(m_pcap_handle));
        pcap_freecode(&bpf);
        return false;
    }

    pcap_freecode(&bpf);
    return true;
}

bool Dns_monitor::getIsConstructorErr() const
{
    return m_is_constructor_err;
}

void Dns_monitor::printErrBuff() const
{
    std::cerr << m_err_buff << std::endl;
}

bool Dns_monitor::run()
{
    struct pcap_pkthdr* packet_header{nullptr};
    const u_char *packet_data{nullptr};
    
    while(true)
    {
        int result{pcap_next_ex(m_pcap_handle, &packet_header, &packet_data)};
        
        if(result == 0)
        {
            continue;
        }
        else if(result == PCAP_ERROR_BREAK)
        {
            break;
        }
        else if(result != 1)
        {
            strcpy(m_err_buff, "pcap_next_ex() error has occurred\n");
            return false;
        }
        
        m_packet_writer->printPacket(packet_header, packet_data);
    }
    
    return true;
}