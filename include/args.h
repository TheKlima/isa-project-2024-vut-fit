/**
 * DNS monitor
 * 
 * @brief Definition of the class representing program arguments
 * @file args.h
 * @author Andrii Klymenko <xklyme00>
 */

#ifndef ARGS_H
#define ARGS_H

/**
 * @brief Class representing program arguments
 */
class Args {
public:
    /**
     * @brief Constructs an object (assigns some values to its private members) based on the program arguments
     *
     * @param argc number of the program arguments + 1 (program's executable)
     * @param argv pointer to the array of the program arguments
     */
    Args(int argc, char** argv);
    
    // "Getters"
    
    /**
     * @brief Object's private member m_packets_source "getter"
     *
     * @return Value of the object's private member m_packets_source
     */
    const char* getPacketsSource() const;
    
    /**
     * @brief Object's private member m_domains_file_name "getter"
     *
     * @return Value of the object's private member m_domains_file_name
     */
    const char* getDomainsFileName() const;
    
    /**
     * @brief Object's private member m_translations_file_name "getter"
     *
     * @return Value of the object's private member m_translations_file_name
     */
    const char* getTranslationsFileName() const;
    
    /**
     * @brief Object's private member m_is_verbose "getter"
     *
     * @return Value of the object's private member m_is_verbose
     */
    bool getIsVerbose() const;
    
    /**
     * @brief Object's private member "getter" m_sniffing_from_interface
     *
     * @return Value of the object's private member m_sniffing_from_interface
     */
    bool getSniffingFromInterface() const;
    
    // End of the "Getters"
    
private:
    const char* m_packets_source{};         // either an interface name or pcap file name
    const char* m_domains_file_name{};
    const char* m_translations_file_name{};

    // specifies if the DNS monitor must work in the verbose mode (-v flag was provided while running the program)
    bool m_is_verbose{};
    bool m_sniffing_from_interface{}; // true if sniffing from some interface, false if sniffing from pcap file
};

#endif // ARGS_H
