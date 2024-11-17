/**
 * DNS monitor
 * 
 * @brief Definition of the object representing program arguments
 * @file args.h
 * @author Andrii Klymenko <xklyme00>
 */

#ifndef ARGS_H
#define ARGS_H

/**
 * @brief Object representing program arguments
 */
class Args {
public:
    /**
     * @brief Constructs an object (assigns some values to its private members) based on the program arguments
     *
     * @param argc number of the program arguments + 1 (program's executable)
     */
    Args(int argc, char** argv);
    
    // "Getters"
    
    /**
     * @brief object's m_packets_source private member "getter"
     *
     * @return value of the object's m_packets_source private member
     */
    const char* getPacketsSource() const;
    
    /**
     * @brief object's m_domains_file_name private member "getter"
     *
     * @return value of the object's m_domains_file_name private member
     */
    const char* getDomainsFileName() const;
    
    /**
     * @brief object's m_translations_file_name private member "getter"
     *
     * @return value of the object's m_translations_file_name private member
     */
    const char* getTranslationsFileName() const;
    
    /**
     * @brief object's m_is_verbose private member "getter"
     *
     * @return value of the object's m_is_verbose private member
     */
    bool getIsVerbose() const;
    
    /**
     * @brief object's m_sniffing_from_interface private member "getter"
     *
     * @return value of the object's m_sniffing_from_interface private member
     */
    bool getSniffingFromInterface() const;
    
    // End of "Getters"
    
private:
    const char* m_packets_source{};         // either an interface name or pcap file name
    const char* m_domains_file_name{};
    const char* m_translations_file_name{};

    // specifies if the DNS monitor must work in the verbose mode (-v flag was provided while running the program)
    bool m_is_verbose{};
    bool m_sniffing_from_interface{}; // true if sniffing from some interface, false if sniffing from pcap file
};

#endif // ARGS_H
