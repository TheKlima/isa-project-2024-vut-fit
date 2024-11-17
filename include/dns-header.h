/**
 * DNS monitor
 * 
 * @brief Definition of the class representing DNS packet's header
 * @file dns-header.h
 * @author Andrii Klymenko <xklyme00>
 */
 
#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>

/**
 * @brief Class representing DNS packet's header
 */
class Dns_header {
private:
    const u_char* m_ptr{};  // pointer to the DNS header
    
    uint16_t m_id{};      // message identifier
    uint8_t m_qr{};       // specifies whether this message is a query (0), or a response (1)
    uint8_t m_opcode{};   // specifies kind of query in the message
    uint8_t m_aa{};       // specifies if the answer is authoritative 
    uint8_t m_tc{};       /* specifies that the message was truncated due to length greater than that permitted on the
                             transmission channel */
    
    uint8_t m_rd{};       // specifies if the recursion is desired
    uint8_t m_ra{};       // specifies if the recursion is available
    uint8_t m_ad{};       // indicates in a response that the data included has been verified by the server providing it
    uint8_t m_cd{};       // indicates in a query that non-verified data is acceptable to the resolver sending the query
    uint8_t m_rcode{};    // response code
    uint16_t m_qdcount{}; // number of the entries in the question section
    uint16_t m_ancount{}; // number of resource records in the answer section
    uint16_t m_nscount{}; // number of the name server resource records in the authority records section
    uint16_t m_arcount{}; // number of the resource records in the additional records section

    // Private "Setters"

    /**
     * @brief Sets object's private member m_id
     *
     * @param id id
     */
    void setId(uint16_t id);
    
    /**
     * @brief Sets object's private member m_qr
     *
     * @param qr qr
     */
    void setQr(uint8_t qr);
    
    /**
     * @brief Sets object's private member m_opcode
     *
     * @param opcode opcode
     */
    void setOpcode(uint8_t opcode);
    
    /**
     * @brief Sets object's private member m_aa
     *
     * @param aa aa
     */
    void setAa(uint8_t aa);
    
    /**
     * @brief Sets object's private member m_tc
     *
     * @param tc tc
     */
    void setTc(uint8_t tc);
    
    /**
     * @brief Sets object's private member m_rd
     *
     * @param rd rd
     */
    void setRd(uint8_t rd);
    
    /**
     * @brief Sets object's private member m_ra
     *
     * @param ra ra
     */
    void setRa(uint8_t ra);
    
    /**
     * @brief Sets object's private member m_ad
     *
     * @param ad ad
     */
    void setAd(uint8_t ad);
    
    /**
     * @brief Sets object's private member m_cd
     *
     * @param cd cd
     */
    void setCd(uint8_t cd);
    
    /**
     * @brief Sets object's private member m_rcode
     *
     * @param rcode rcode
     */
    void setRcode(uint8_t rcode);
    
    /**
     * @brief Sets object's private member m_qdcount
     *
     * @param qdcount qdcount
     */
    void setQdcount(uint16_t qdcount);
    
    /**
     * @brief Sets object's private member m_ancount
     *
     * @param ancount ancount
     */
    void setAncount(uint16_t ancount);
    
    /**
     * @brief Sets object's private member m_nscount
     *
     * @param nscount nscount
     */
    void setNscount(uint16_t nscount);
    
    /**
     * @brief Sets object's private member m_arcount
     *
     * @param arcount arcount
     */
    void setArcount(uint16_t arcount);
    
    // End of the private "Setters"
    
public:
    /**
     * @brief "Fills" an object (assigns some values to its private members) based on the DNS packet's header
     *
     * @param dns_header pointer to the first byte of the DNS packet's header
     */
    void fill(const u_char* dns_header);

    // "Getters"

    /**
     * @brief Object's private member m_id "getter"
     *
     * @return Value of the object's private member m_id
     */
    uint16_t getId() const;
    
    /**
     * @brief Object's private member m_qr "getter"
     *
     * @return Value of the object's private member m_qr
     */
    uint16_t getQr() const;
    
    /**
     * @brief Object's private member m_opcode "getter"
     *
     * @return Value of the object's private member m_opcode
     */
    uint16_t getOpcode() const;
    
    /**
     * @brief Object's private member m_aa "getter"
     *
     * @return Value of the object's private member m_aa
     */
    uint16_t getAa() const;
    
    /**
     * @brief Object's private member m_tc "getter"
     *
     * @return Value of the object's private member m_tc
     */
    uint16_t getTc() const;
    
    /**
     * @brief Object's private member m_rd "getter"
     *
     * @return Value of the object's private member m_rd
     */
    uint16_t getRd() const;
    
    /**
     * @brief Object's private member m_ra "getter"
     *
     * @return Value of the object's private member m_ra
     */
    uint16_t getRa() const;
    
    /**
     * @brief Object's private member m_ad "getter"
     *
     * @return Value of the object's private member m_ad
     */
    uint16_t getAd() const;
    
    /**
     * @brief Object's private member m_cd "getter"
     *
     * @return Value of the object's private member m_cd
     */
    uint16_t getCd() const;
    
    /**
     * @brief Object's private member m_rcode "getter"
     *
     * @return Value of the object's private member m_rcode
     */
    uint16_t getRcode() const;
    
    /**
     * @brief Object's private member m_qdcount "getter"
     *
     * @return Value of the object's private member m_qdcount
     */
    uint16_t getQdcount() const;
    
    /**
     * @brief Object's private member m_ancount "getter"
     *
     * @return Value of the object's private member m_ancount
     */
    uint16_t getAncount() const;
    
    /**
     * @brief Object's private member m_nscount "getter"
     *
     * @return Value of the object's private member m_nscount
     */
    uint16_t getNscount() const;
    
    /**
     * @brief Object's private member "getter" m_arcount
     *
     * @return Value of the object's private member m_arcount
     */
    uint16_t getArcount() const;

    /**
     * @brief Object's private member "getter" m_ptr
     *
     * @return Value of the object's private member m_ptr
     */
    const u_char* getPtr() const;
    
    // End of the "Getters"
};

#endif // DNS_HEADER_H
