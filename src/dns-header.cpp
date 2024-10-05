#include "dns-header.h"

void Dns_header::create(const u_char* dns_header)
{
    std::memcpy(this, dns_header, sizeof(Dns_header));
}

uint16_t Dns_header::getId() const
{
    return m_id;
}

uint16_t Dns_header::getQr() const
{
    return m_qr;
}

uint16_t Dns_header::getOpcode() const
{
    return m_opcode;
}

uint16_t Dns_header::getAa() const
{
    return m_aa;
}

uint16_t Dns_header::getTc() const
{
    return m_tc;
}

uint16_t Dns_header::getRd() const
{
    return m_rd;
}

uint16_t Dns_header::getRa() const
{
    return m_ra;
}

uint16_t Dns_header::getZ() const
{
    return m_z;
}

uint16_t Dns_header::getAd() const
{
    return m_ad;
}

uint16_t Dns_header::getCd() const
{
    return m_cd;
}

uint16_t Dns_header::getRcode() const
{
    return m_rcode;
}

uint16_t Dns_header::getQdcount() const
{
    return m_qdcount;
}

uint16_t Dns_header::getAncount() const
{
    return m_ancount;
}

uint16_t Dns_header::getNscount() const
{
    return m_nscount;
}

uint16_t Dns_header::getArcount() const
{
    return m_arcount;
}
