#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <cstdint>
#include <cstring>

class __attribute__((packed)) Dns_header {
private:
    uint16_t m_id{};
    uint16_t m_qr : 1 {};
    uint16_t m_opcode : 4 {};
    uint16_t m_aa : 1 {};
    uint16_t m_tc : 1 {};
    uint16_t m_rd : 1 {};
    uint16_t m_ra : 1 {};
    uint16_t m_z : 1 {};
    uint16_t m_ad : 1 {};
    uint16_t m_cd : 1 {};
    uint16_t m_rcode : 4 {};
    uint16_t m_qdcount{};
    uint16_t m_ancount{};
    uint16_t m_nscount{};
    uint16_t m_arcount{};
    
public:
    void create(const u_char* dns_header);

    uint16_t getId() const;
    uint16_t getQr() const;
    uint16_t getOpcode() const;
    uint16_t getAa() const;
    uint16_t getTc() const;
    uint16_t getRd() const;
    uint16_t getRa() const;
    uint16_t getZ() const;
    uint16_t getAd() const;
    uint16_t getCd() const;
    uint16_t getRcode() const;
    uint16_t getQdcount() const;
    uint16_t getAncount() const;
    uint16_t getNscount() const;
    uint16_t getArcount() const;
};

#endif // DNS_HEADER_H