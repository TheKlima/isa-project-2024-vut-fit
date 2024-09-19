#include "args.h"
#include "getopt.h"

Args::Args(int argc, char** argv)
    :
    m_packets_source{nullptr},
    m_is_verbose{false}
{
    int opt{};

    while((opt = getopt(argc, argv, "i:r:v")) != -1)
    {
        switch(opt)
        {
            case 'i':
                m_sniffing_from_interface = true;
                m_packets_source = optarg;
                break;
                
            case 'r':
                m_sniffing_from_interface = false;
                m_packets_source = optarg;
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

bool Args::getIsVerbose() const
{
    return m_is_verbose;
}

bool Args::getSniffingFromInterface() const
{
    return m_sniffing_from_interface;
}