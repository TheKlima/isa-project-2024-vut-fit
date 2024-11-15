#include "dns-monitor.h"

Dns_monitor::Dns_monitor(int argc, char **argv)
    :
    m_args{argc, argv},
    m_packet_writer{Packet_writer::create(m_args.getIsVerbose(), m_args.getDomainsFileName(), m_args.getTranslationsFileName())},
    m_is_constructor_err{false},
    m_err_buff{0, },
    m_pcap_handle{nullptr},
    m_dns_filter{"udp port 53"}
{
    if(!m_packet_writer)
    {
        strcpy(m_err_buff, "Error! Couldn't allocate memory for packet writer.\n");
        m_is_constructor_err = true;
        return;
    }
    
    if(m_packet_writer->getIsConstructorErr())
    {
        strcpy(m_err_buff, "Error! Couldn't create/open output file.\n");
        m_is_constructor_err = true;
        return;
    }
    
    createPcapHandle();
}

Dns_monitor::~Dns_monitor()
{
    delete m_packet_writer;
    
    if(m_pcap_handle)
    {
        pcap_close(m_pcap_handle);
    }
}

// preparation before processing DNS packets
// inspired by: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#process-packets
void Dns_monitor::createPcapHandle()
{
    bpf_u_int32 net_mask{0};
    bpf_u_int32 src_ip{0};

    if(m_args.getSniffingFromInterface())
    {
        // get network device source IP address and netmask
        if(pcap_lookupnet(m_args.getPacketsSource(), &src_ip, &net_mask, m_err_buff) == PCAP_ERROR)
        {
            m_is_constructor_err = true;
            return;
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
        m_is_constructor_err = true;
        return;
    }

    struct bpf_program bpf{};
    
    // convert the packet filter expression into a packet filter binary
    if(pcap_compile(m_pcap_handle, &bpf, m_dns_filter, 0, net_mask) == PCAP_ERROR)
    {
        m_is_constructor_err = true;
        strcpy(m_err_buff, pcap_geterr(m_pcap_handle));
        return;
    }

    // bind the packet filter to the libpcap handle
    if(pcap_setfilter(m_pcap_handle, &bpf) == PCAP_ERROR)
    {
        pcap_freecode(&bpf);
        m_is_constructor_err = true;
        strcpy(m_err_buff, pcap_geterr(m_pcap_handle));
        return;
    }

    pcap_freecode(&bpf);
}

bool Dns_monitor::getIsConstructorErr() const
{
    return m_is_constructor_err;
}

void Dns_monitor::printErrBuff() const
{
    std::cerr << m_err_buff << std::endl;
}

void Dns_monitor::run()
{
    struct pcap_pkthdr* packet_header{nullptr};
    const u_char* packet_data{nullptr};

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGQUIT, signalHandler);
    
    while(true)
    {
        int result{pcap_next_ex(m_pcap_handle, &packet_header, &packet_data)};
        
        if(result == 0)
        {
            continue;
        }
        else if(result == PCAP_ERROR_BREAK)
        {
            return;
        }
        else if(result != 1)
        {
            throw Dns_monitor_exception{"Error! pcap_next_ex() has failed."};
        }

        m_packet_writer->printPacket(packet_header, packet_data);
    }
}

void Dns_monitor::signalHandler(int sig)
{
    (void)sig;
    throw Dns_monitor_exception{""};
}

//void Dns_monitor::createOutputFile(std::ofstream output_file, const char* const file_name)
//{
//    if(file_name)
//    {
//        output_file.open(file_name);
//
//        if(!output_file)
//        {
//            strcpy(m_err_buff, "Error! Couldn't create an output file.\n");
//            m_is_constructor_err = true;
//        }
//    }
//}
