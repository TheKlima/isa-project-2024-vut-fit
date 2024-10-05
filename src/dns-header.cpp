#include "dns-header.h"

void Dns_header::fill(const u_char* dns_header)
{
    setId(ntohs(*(reinterpret_cast<const uint16_t*>(dns_header))));

    uint16_t flags{ntohs(*(reinterpret_cast<const uint16_t*>(dns_header + 2)))};

    setQr((flags >> 15) & 1);
    setOpcode((flags >> 11) & 0b1111);
    setAa((flags >> 10) & 1);
    setTc((flags >> 9) & 1);
    setRd((flags >> 8) & 1);
    setRa((flags >> 7) & 1);
    setAd((flags >> 5) & 1);
    setCd((flags >> 4) & 1);
    setRcode((flags >> 3) & 0b1111);
    
    setQdcount(ntohs(*(reinterpret_cast<const uint16_t*>(dns_header + 4))));
    setAncount(ntohs(*(reinterpret_cast<const uint16_t*>(dns_header + 6))));
    setNscount(ntohs(*(reinterpret_cast<const uint16_t*>(dns_header + 8))));
    setArcount(ntohs(*(reinterpret_cast<const uint16_t*>(dns_header + 10))));
}

// 'Getters'

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

// End of 'Getters'

// Private 'Setters'

void Dns_header::setId(uint16_t id)
{
    m_id = id;
}

void Dns_header::setQr(uint8_t qr)
{
    m_qr = qr;
}

void Dns_header::setOpcode(uint8_t opcode)
{
    m_opcode = opcode;
}

void Dns_header::setAa(uint8_t aa)
{
    m_aa = aa;
}

void Dns_header::setTc(uint8_t tc)
{
    m_tc = tc;
}

void Dns_header::setRd(uint8_t rd)
{
    m_rd = rd;
}

void Dns_header::setRa(uint8_t ra)
{
    m_ra = ra;
}

void Dns_header::setAd(uint8_t ad)
{
    m_ad = ad;
}

void Dns_header::setCd(uint8_t cd)
{
    m_cd = cd;
}

void Dns_header::setRcode(uint8_t rcode)
{
    m_rcode = rcode;
}

void Dns_header::setQdcount(uint16_t qdcount)
{
    m_qdcount = qdcount;
}

void Dns_header::setAncount(uint16_t ancount)
{
    m_ancount = ancount;
}

void Dns_header::setNscount(uint16_t nscount)
{
    m_nscount = nscount;
}

void Dns_header::setArcount(uint16_t arcount)
{
    m_arcount = arcount;
}


// End of private 'Setters'