#ifndef PACKET_WRITER_H
#define PACKET_WRITER_H

#include <new>  // For std::nothrow

class Packet_writer {
public:
    static Packet_writer* create(bool is_verbose);
};

#endif // PACKET_WRITER_H