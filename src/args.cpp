/**
 * DNS monitor
 * 
 * @brief Implementation of the Args class
 * @file args.cpp
 * @author Andrii Klymenko <xklyme00>
 */

#include "args.h"
#include "getopt.h"
#include "dns-monitor-exception.h"

Args::Args(int argc, char** argv)
    :
    m_packets_source{nullptr},
    m_domains_file_name{nullptr},
    m_translations_file_name{nullptr},
    m_is_verbose{false}
{
    int opt{};

    while((opt = getopt(argc, argv, "i:p:d:t:v")) != -1)
    {
        switch(opt)
        {
            case 'i':
            case 'p':
                if(m_packets_source != nullptr) // if both an interface name and a pcap file name were specified
                {
                    throw Dns_monitor_exception{"You must specify either an interface name or PCAP file name but not both."};
                }
                
                m_sniffing_from_interface = (opt == 'i');
                m_packets_source = optarg;
                break;
                
            case 'd':
                m_domains_file_name = optarg;
                break;
                
            case 't':
                m_translations_file_name = optarg;
                break;
                
            case 'v':
                m_is_verbose = true;
                break;
                
            default:
                break;
        }
    }
}

// "Getters"

const char* Args::getPacketsSource() const
{
    return m_packets_source;
}

const char* Args::getDomainsFileName() const
{
    return m_domains_file_name;
}

const char* Args::getTranslationsFileName() const
{
    return m_translations_file_name;
}

bool Args::getIsVerbose() const
{
    return m_is_verbose;
}

bool Args::getSniffingFromInterface() const
{
    return m_sniffing_from_interface;
}

// End of the "Getters"
