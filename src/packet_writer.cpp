#include "packet_writer.h"
#include "verbose_packet_writer.h"
#include "simple_packet_writer.h"

Packet_writer* Packet_writer::create(bool is_verbose)
{
    if(is_verbose)
    {
        return new(std::nothrow) Verbose_packet_writer;
    }
    
    return new(std::nothrow) Simple_packet_writer;
}