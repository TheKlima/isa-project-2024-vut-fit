#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>

class Dns_header {
private:
    uint16_t m_id{};
    uint8_t m_qr{};
    uint8_t m_opcode{};
    uint8_t m_aa{};
    uint8_t m_tc{};
    uint8_t m_rd{};
    uint8_t m_ra{};
    uint8_t m_ad{};
    uint8_t m_cd{};
    uint8_t m_rcode{};
    uint16_t m_qdcount{};
    uint16_t m_ancount{};
    uint16_t m_nscount{};
    uint16_t m_arcount{};

    void setId(uint16_t id);
    void setQr(uint8_t qr);
    void setOpcode(uint8_t opcode);
    void setAa(uint8_t aa);
    void setTc(uint8_t tc);
    void setRd(uint8_t rd);
    void setRa(uint8_t ra);
    void setAd(uint8_t ad);
    void setCd(uint8_t cd);
    void setRcode(uint8_t rcode);
    void setQdcount(uint16_t qdcount);
    void setAncount(uint16_t ancount);
    void setNscount(uint16_t nscount);
    void setArcount(uint16_t arcount);
    
public:
    void fill(const u_char* dns_header);

    uint16_t getId() const;
    uint16_t getQr() const;
    uint16_t getOpcode() const;
    uint16_t getAa() const;
    uint16_t getTc() const;
    uint16_t getRd() const;
    uint16_t getRa() const;
    uint16_t getAd() const;
    uint16_t getCd() const;
    uint16_t getRcode() const;
    uint16_t getQdcount() const;
    uint16_t getAncount() const;
    uint16_t getNscount() const;
    uint16_t getArcount() const;
};

#endif // DNS_HEADER_H