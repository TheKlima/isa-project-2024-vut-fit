#include "args.h"
#include "getopt.h"

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