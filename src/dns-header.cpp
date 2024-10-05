#include "dns-header.h"

void Dns_header::create(const u_char* dns_header)
{
    std::memcpy(this, dns_header, sizeof(Dns_header));
}