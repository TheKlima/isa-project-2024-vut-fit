#include "args.h"

const char* Args::getPacketsSource() const
{
    return m_packets_source;
}

bool Args::getIsVerbose() const
{
    return m_is_verbose;
}